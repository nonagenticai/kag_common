"""KAG ecosystem Prometheus counters — centralised so every consuming
service shares one Counter registry per process.

Counter names + labels match the prometheus rules in
``gitops-production/clusters/strato/services/alerting/rules/prometheusrule-kag-loudness.yaml``
— do not rename or relabel without updating that file in the same change.

Usage:

    from kag_common.metrics import (
        make_metrics_app,
        record_tenant_id_required,
        record_dual_write,
        record_stage_degraded,
    )

    app.mount("/metrics", make_metrics_app())
    record_tenant_id_required("kag_graph_service")
    record_dual_write("hirag_service", tenant_id, "succeeded")
    record_stage_degraded("kag_orchestrator", tenant_id, stage_name)

The ``service`` parameter is passed at the call site rather than read from
a module-level constant so that the helpers work uniformly across all
consumer services without per-service subclassing.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from typing import Any

from prometheus_client import Counter, make_asgi_app

logger = logging.getLogger(__name__)

tenant_id_required_total = Counter(
    "kag_tenant_id_required_total",
    "Requests refused for missing X-Tenant-Id on the trusted-network branch",
    ["service"],
)

dual_write_total = Counter(
    "kag_dual_write_total",
    "KAG dual-write outcomes (succeeded | failed | skipped)",
    ["service", "tenant", "outcome"],
)

stage_degraded_total = Counter(
    "kag_stage_degraded_total",
    "Downstream stage reported degraded/partial on a successful completion",
    ["service", "tenant", "stage"],
)

phi_access_audit_failures_total = Counter(
    "kag_phi_access_audit_failures_total",
    "PHI-access audit writes that failed and were swallowed (HIPAA §164.312(b) "
    "audit-control gap — a PHI read served without its audit row)",
    ["service", "action"],
)

# ⚠️ METERING LOSS, and this is the only instrument that can see it. The cost-bus
# XADD in ``kag_common.metering.emit_cost_event`` is fire-and-forget and contracted
# never to raise, so a failed emit leaves the request succeeding and the spend
# simply absent from the billing ledger. That module is the SHARED emitter for the
# whole kag lineage, so one cost-bus blip drops every consuming service's spend at
# once — which is exactly the shape of loss a log line cannot alert on.
#
# ``error_type`` is the exception CLASS name: bounded cardinality, and it separates
# a cost-bus outage (ConnectionError / TimeoutError, after the emitter's bounded
# retry gave up) from a marshalling bug in the emitter itself.
#
# ⭐ It carries ONE value that is not an exception that was actually raised:
# ``NoRunningLoopError`` (``kag_common.metering.NO_LOOP_ERROR_TYPE``), recorded
# when ``schedule_cost_event`` is called from a frame with no running event loop,
# so the emit was never even entered. It lives on THIS series rather than a new
# metric on purpose: both values mean the same thing to an operator — a billable
# request whose ledger row does not exist — and splitting them across two metrics
# guarantees that every future dashboard and alert has to remember to sum both,
# with the rarer one being the one that gets forgotten.
#
# ⛔ What this counter still cannot answer, and did not before this value existed
# either: a RATIO. There is no ``kag_cost_events_total{outcome="ok"}`` anywhere in
# this module, so "what FRACTION of this service's cost events is being lost?"
# has no denominator in kag metrics. The w2v_common port of the same emitter does
# have one (``w2v_cost_events_total{outcome=...}``). Closing that gap is a
# separate change.
cost_event_emit_failed_total = Counter(
    "kag_cost_event_emit_failed_total",
    "Cost events that never reached the ledger — the XADD failed, or "
    "schedule_cost_event found no running event loop — while the request itself "
    "succeeded",
    ["service", "error_type"],
)


#: Cost events whose ``project_id`` was neither passed explicitly nor bound on the
#: request context, by what the emitter did instead (owner ruling 2026-10-07:
#: the cost project is the calling app's own, forwarded by shared services).
#:
#: ``tenant_level``: the tenant-level project
#: (:func:`kag_common.attribution.tenant_level_project_id`) was emitted.
#: ``no_project``: not even that could be derived (non-UUID legacy tenant), so
#: the key was omitted. A steady rate on a service means its callers are not
#: sending ``X-Project-Id`` / ``X-W2V-Project-Id`` — or it is not binding them.
#:
#: Pre-initialised: a labelled Counter exports no series until a child exists,
#: and an absent series reads as "not instrumented", not "never fell back".
COST_PROJECT_FALLBACK_REASONS: tuple[str, ...] = ("tenant_level", "no_project")
cost_project_fallback_total = Counter(
    "kag_cost_project_fallback_total",
    "Cost events emitted without an explicit or request-bound project, by fallback reason",
    ["reason"],
)
for _fallback_reason in COST_PROJECT_FALLBACK_REASONS:
    cost_project_fallback_total.labels(reason=_fallback_reason)


def record_cost_project_fallback(reason: str) -> None:
    """Best-effort fallback observation — must never break an emit."""
    try:
        cost_project_fallback_total.labels(reason=reason).inc()
    except Exception:  # noqa: BLE001 — telemetry must never fail a billable request
        logger.debug("cost_project_fallback_metric_failed reason=%s", reason)


#: Cost events emitted with NO ``actor_id`` (owner ruling 2026-10-07: every cost
#: event names who acted — the human's Keycloak sub, else the calling service's
#: own service-account sub). Incremented by ``emit_cost_event`` when neither a
#: value, and by the outbound hop when it sends no ``X-Actor-Id``. ``service`` is
#: the emitting ``service_key`` (emit) or this process (outbound). ``reason``:
#:
#: ``inbound_without_actor``: an inbound request arrived with no valid
#: ``X-Actor-Id``. The service's own id is deliberately NOT substituted — that
#: would hide the CALLER's gap from billing coverage and router enforcement.
#: ``no_service_actor``: service-originated work (no inbound request) and the
#: deployment lacks a valid ``SERVICE_ACTOR_ID``.
ACTOR_MISSING_REASONS: tuple[str, ...] = ("inbound_without_actor", "no_service_actor")
actor_missing_total = Counter(
    "kag_common_actor_missing_total",
    "Cost events / outbound calls without an actor_id, by reason",
    ["service", "reason"],
)

#: Inbound ``X-Actor-Id`` headers that were present but not a canonical non-nil
#: UUID. The value is DROPPED (treated as absent), never coerced; this counts
#: the caller bug so it can be chased. ``service`` is this process
#: (:func:`resolve_service_label`).
actor_header_malformed_total = Counter(
    "kag_common_actor_header_malformed_total",
    "Inbound X-Actor-Id headers dropped because they were not a canonical non-nil UUID",
    ["service"],
)


def record_actor_missing(service: str, reason: str) -> None:
    """Best-effort observation — must never break an emit or a request."""
    try:
        actor_missing_total.labels(service=service or "unknown", reason=reason).inc()
    except Exception:  # noqa: BLE001 — telemetry must never fail a billable request
        logger.debug("actor_missing_metric_failed service=%s reason=%s", service, reason)


def record_actor_header_malformed() -> None:
    """Best-effort observation — must never break a request."""
    try:
        actor_header_malformed_total.labels(service=resolve_service_label()).inc()
    except Exception:  # noqa: BLE001 — telemetry must never fail a request
        logger.debug("actor_header_malformed_metric_failed")


def make_metrics_app():
    """Return an ASGI app suitable for mounting at ``/metrics``."""
    return make_asgi_app()


def record_tenant_id_required(service: str) -> None:
    tenant_id_required_total.labels(service=service).inc()


def record_dual_write(service: str, tenant: str, outcome: str) -> None:
    dual_write_total.labels(service=service, tenant=tenant or "unknown", outcome=outcome).inc()


def record_stage_degraded(service: str, tenant: str, stage: str) -> None:
    stage_degraded_total.labels(service=service, tenant=tenant or "unknown", stage=stage).inc()


def record_phi_audit_failure(service: str, action: str) -> None:
    phi_access_audit_failures_total.labels(
        service=service or "unknown", action=action or "unknown"
    ).inc()


def record_cost_event_emit_failed(service: str, error_type: str) -> None:
    cost_event_emit_failed_total.labels(
        service=service or "unknown", error_type=error_type or "unknown"
    ).inc()


# --------------------------------------------------------------------------- #
# ⭐ THE SILENT FAIL-OPEN. Added 0.30.0.
#
# ``kag_common.auth.is_trusted_network()`` answers "did this request come from a
# CIDR in TRUSTED_CIDRS", and ``DEFAULT_TRUSTED_CIDRS`` ships ``10.0.0.0/8`` — a
# superset of the k3s pod CIDR ``10.42.0.0/16``. Seven consumers (kag_orchestrator,
# hirag_service, kag_graph_service, nlp_service, ingestion_service, karma_service,
# graph_adapter_service) branch on that predicate ALONE and then take the tenant
# straight off a bare ``X-Tenant-Id``, so any pod in the cluster can assert any
# tenant with no credential. hirag_service goes further and falls back to
# ``DEFAULT_TENANT_ID`` when the header is absent entirely.
#
# Until now that branch emitted NOTHING — no counter, no log, no alert — so the
# size of the affected population was unknown and enforcement could not be armed
# against an unmeasured population.
#
# ⛔ NEITHER SERIES ENFORCES ANYTHING. No request changes outcome. These count.
#
# ⚠️ READ THE TWO NAMES AS DIFFERENT MEASUREMENTS — they are not interchangeable:
#
#   * ``kag_trusted_network_bypass_total`` is what actually FIRES today, because
#     it hangs off ``is_trusted_network()``, which every one of the seven already
#     calls. It counts PREDICATE EVALUATIONS, not requests. Three consumers
#     (nlp_service, ingestion_service, kag_graph_service) call the predicate twice
#     per request — once in middleware, once in a tenant dependency — so this is
#     an UPPER BOUND on requests, not a request count. Take a per-``service``
#     ratio against that service's own request total rather than reading the raw
#     number as "requests bypassed".
#
#   * ``kag_tokenless_tenant_assertion_total`` is the semantically exact one: one
#     increment per resolution decision, with the header-present / header-absent
#     split that actually distinguishes the two failure modes. It hangs off
#     ``resolve_tokenless_tenant()``, which is the library's supported seam and
#     which ZERO consumers call today. It is therefore INERT until a consumer
#     migrates. That is stated here rather than discovered later from a flat
#     graph: a series at 0 because nothing calls it is indistinguishable, on a
#     dashboard, from a series at 0 because the exposure is not being exercised.
#
# CARDINALITY — every label is bounded, deliberately:
#   * ``service``    — one value per process, from ``OTEL_SERVICE_NAME`` (set on
#     every kag deployment in gitops) falling back to ``SERVICE_NAME``.
#   * ``peer_class`` — a fixed 9-value bucketing of the peer address (below), NOT
#     the raw IP. A raw pod IP would mint a new series per pod restart.
#   * ``trusted`` / ``has_header`` — "true" | "false".
#   * ``outcome``    — 4 fixed strings from ``resolve_tokenless_tenant``.
#
# ⚠️ WHAT THESE LABELS CANNOT DO: name the calling workload. ``peer_class`` is a
# NETWORK bucket, not an identity. It separates the known-distinct vectors (an
# external caller arriving via the SSR proxy presents ``lan_192``; the hostNetwork
# API gateway SNATs to ``10.42.0.0`` and so presents ``k8s_pod``), but it cannot
# tell you WHICH pod. Attributing a specific caller still needs ztunnel/Istio
# access logs joined on time. This is the same gap that
# ``worker_management_unauthenticated_tenant_assertion_total`` hit; a per-pod-IP
# label would close it and is rejected on cardinality, not on principle.
# --------------------------------------------------------------------------- #
trusted_network_bypass_total = Counter(
    "kag_trusted_network_bypass_total",
    "Evaluations of the TRUSTED_CIDRS credential-less bypass predicate "
    "(is_trusted_network). NOT a request count — see the module comment.",
    ["service", "peer_class", "trusted"],
)

tokenless_tenant_assertion_total = Counter(
    "kag_tokenless_tenant_assertion_total",
    "Decisions taken by resolve_tokenless_tenant(): a tenant asserted with NO "
    "credential, split by whether the caller sent an X-Tenant-Id header at all",
    ["service", "has_header", "outcome"],
)

#: Outcomes of :func:`kag_common.auth.resolve_tokenless_tenant`. Fixed set.
TOKENLESS_ADMITTED = "admitted"
TOKENLESS_REFUSED_PEER = "refused_peer_or_opt_out"
TOKENLESS_REFUSED_NO_HEADER = "refused_no_header"
TOKENLESS_REFUSED_BEARER = "refused_bearer_in_header"


def resolve_service_label() -> str:
    """The ``service`` label value for this process.

    ``OTEL_SERVICE_NAME`` is set on every kag Deployment in gitops; ``SERVICE_NAME``
    is the older spelling still present on nlp-service. Read at CALL time, not
    import time, matching this package's env convention (``kag_common.env``) so a
    test can set it with ``monkeypatch.setenv`` and so import order cannot pin it.

    ``BaseServiceSettings.service_name`` is deliberately NOT used: it is a required
    field with no default, so reading it here would mean instantiating a consumer's
    settings object from inside a hot auth predicate.
    """
    raw = os.getenv("OTEL_SERVICE_NAME") or os.getenv("SERVICE_NAME") or ""
    return raw.strip() or "unknown"


_PRIVATE_10 = ipaddress.ip_network("10.0.0.0/8")
_PEER_CLASSES: tuple[tuple[Any, str], ...] = (
    (ipaddress.ip_network("10.42.0.0/16"), "k8s_pod"),
    (ipaddress.ip_network("10.43.0.0/16"), "k8s_svc"),
    (ipaddress.ip_network("192.168.0.0/16"), "lan_192"),
    (ipaddress.ip_network("172.16.0.0/12"), "docker_172"),
    (ipaddress.ip_network("100.64.0.0/10"), "tailnet"),
)


def classify_peer(host: str | None) -> str:
    """Bucket a peer address into a fixed, bounded class.

    The buckets are chosen so each one names a DIFFERENT exposure on this fleet,
    not merely a different subnet:

    * ``k8s_pod``    — ``10.42.0.0/16``: any pod in the cluster, and also the
      hostNetwork API gateway, which SNATs to ``10.42.0.0``. So this bucket mixes
      "legitimate authenticated external traffic" with "any workload in the mesh";
      it is the bucket that cannot be narrowed without a gateway pre-arm.
    * ``k8s_svc``    — ``10.43.0.0/16``: ClusterIP source, i.e. a hairpin.
    * ``lan_192``    — ``192.168.0.0/16``: the 2026-04-18 SSR-proxy vector, where
      an EXTERNAL caller routed through an in-cluster proxy presented a private
      source. A non-zero count here is the most alarming single reading.
    * ``docker_172`` — ``172.16.0.0/12``: a sidecar or dind container on a node.
    * ``tailnet``    — ``100.64.0.0/10``: a tailnet host. NOT in the default CIDR
      list, so these should read ``trusted="false"``; a ``true`` here means an
      operator widened ``TRUSTED_CIDRS``.
    * ``private_10`` — the rest of ``10.0.0.0/8``.
    * ``loopback`` / ``public`` / ``unparseable`` — the remainder, including the
      ``host is None`` case (an ASGI scope with no client, e.g. a lifespan or a
      test transport), which lands in ``unparseable``.
    """
    if not host:
        return "unparseable"
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return "unparseable"
    if addr.is_loopback:
        return "loopback"
    for network, label in _PEER_CLASSES:
        if addr in network:
            return label
    if addr.version == 4 and addr in _PRIVATE_10:
        return "private_10"
    return "public"


def record_trusted_network_bypass(host: str | None, trusted: bool) -> None:
    """Count one evaluation of the credential-less trusted-CIDR predicate.

    Contracted never to raise: this is called from inside an auth predicate, and
    an observability failure must not be able to change an authentication
    decision. A broken counter that 500s the auth path would be a strictly worse
    outcome than the silence it was added to fix.
    """
    try:
        trusted_network_bypass_total.labels(
            service=resolve_service_label(),
            peer_class=classify_peer(host),
            trusted="true" if trusted else "false",
        ).inc()
    except Exception:  # pragma: no cover - defensive; must never break auth
        logger.warning("failed to record trusted-network bypass metric", exc_info=True)


def record_tokenless_tenant_assertion(has_header: bool, outcome: str) -> None:
    """Count one ``resolve_tokenless_tenant`` decision. Never raises."""
    try:
        tokenless_tenant_assertion_total.labels(
            service=resolve_service_label(),
            has_header="true" if has_header else "false",
            outcome=outcome,
        ).inc()
    except Exception:  # pragma: no cover - defensive; must never break auth
        logger.warning("failed to record tokenless tenant assertion metric", exc_info=True)
