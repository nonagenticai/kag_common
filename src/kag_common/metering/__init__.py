"""Shared cost-bus emitter for KAG backend services.

A single source of truth for emitting cost events to the cluster cost-bus Redis
stream, following the minimum-viable emitter shape in
``metering_service/docs/EMITTER_GUIDE.md``. This is a faithful port of
``w2v_common.metering.cost_bus`` so the kag lineage (ingestion_service et al.)
emits byte-identical events onto the SAME canonical stream that billing's
consumer reads — the two lineages share one cost bus.

Two public emit entry points:

* :func:`emit_cost_event` — an awaitable coroutine. Use it when you manage the
  task yourself or want to await the XADD (e.g. in tests). Transport failures
  are swallowed with a warning; an unusable ``tenant_id`` is the one deliberate
  exception and raises (see :mod:`kag_common.tenant`).
* :func:`schedule_cost_event` — fire-and-forget that **retains a strong
  reference** to the spawned task until it completes. ``asyncio`` only holds a
  weak reference to tasks, so a bare ``asyncio.create_task(emit(...))`` could be
  garbage-collected mid-flight and silently drop the cost event. Prefer this
  from request handlers.

Provenance (BYO vs owner-provided vs platform) is NOT a parameter — it travels
in ``usage_extra`` (``{"byo": "true"}`` or ``{"owner_provided": "true"}``), the
exact keys billing's rollup lifts into ``cost_daily``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlsplit, urlunsplit

from kag_common.attribution import (
    SERVICE_ACTOR_ID_ENV,
    get_job_id_from_context,
    get_project_id_from_context,
    parse_attribution_uuid,
    parse_job_id,
    resolve_actor,
    tenant_level_project_id,
)
from kag_common.env import _get_bool
from kag_common.metrics import (
    record_actor_missing,
    record_cost_event_emit_failed,
    record_cost_project_fallback,
)
from kag_common.tenant import require_tenant_id

if TYPE_CHECKING:
    from collections.abc import Mapping

    import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

__all__ = [
    "CANONICAL_COST_STREAM",
    "NO_LOOP_ERROR_TYPE",
    "SERVICE_ACTOR_ID_ENV",
    "NoRunningLoopError",
    "close_metering_redis",
    "drain_pending",
    "emit_cost_event",
    "init_metering_redis",
    "require_loop",
    "resolve_stream",
    "schedule_cost_event",
]

# Canonical cost-bus stream. The cluster renamed the cost bus to
# billing:costs (Layer 1a billing-bus rename; supersedes the prior
# improvement-loop:costs, itself renamed from metering:costs on 2026-06-24).
# This is the single place that name lives. Override per-deployment via the
# ``METERING_STREAM`` env var.
CANONICAL_COST_STREAM = "billing:costs"

# REMOVED — ``UNATTRIBUTED_TENANT_ID``, the nil-UUID sentinel this module
# SUBSTITUTED whenever the caller's tenant was missing
# (``safe_tenant_id = tenant_id or UNATTRIBUTED_TENANT_ID``).
#
# ⚠️ The comment that stood here justified the substitution with a contract that
# NO LONGER EXISTS. It claimed the nil UUID "normalises to __unattributed__ ->
# EXCLUDED from billing", i.e. that this was a fail-safe. Measured on
# billing_service origin/main, that is not what happens: ``_cost_schema.py``
# classifies the nil uuid as ``nil_tenant_id`` and DEAD-LETTERS the event
# (``_cost_schema.py:115``, DLQ reason listed at :86; the metric is
# ``billing_cost_dead_letter_total{reason="nil_tenant_id"}``). So the
# substitution never protected anything — it converted a caller bug into a row
# quarantined in a DLQ nobody reads, while every attribution metric here stayed
# green because a *valid, registered* UUID went out on the wire.
#
# A fabricated identity is strictly worse than a missing one. Product-owner
# ruling (2026-08-26, applied to ``w2v_common`` the same day): a tenant_id may
# never hold a sentinel. An emit with no real tenant is now a
# ``kag_common.tenant.MissingTenantError`` — raised at the call site, where the
# bug actually is — not a nil-UUID row. See ``kag_common/tenant.py``.

# Metadata keys billing lifts off the wire into ``billing_cost_events.metadata``.
#
# ⛔ This set MIRRORS the receiver's whitelist verbatim — billing_service
# ``src/services/_parsers.py``, ``COST_METADATA_WHITELIST``, the metadata
# allowlist the flusher loops over to build the ``metadata`` JSON column. (It is
# defined there, and NOT inline in ``cost_flusher``, on purpose: that one list
# also derives the placeholder counter's label domain.) The receiver landed
# FIRST on purpose: a producer that ships a key before the receiver knows it has
# that key dropped SILENTLY, three hops away, in a service we cannot see from
# here — and the row still looks correct. So this set must never grow ahead of
# that loop; widen the receiver first, then mirror it here.
#
# Byte-for-byte the same frozenset as ``w2v_common.metering.cost_bus``'s
# ``_METADATA_PASSTHROUGH_KEYS``. The two libraries emit onto the SAME canonical
# cost bus, so a divergence between them is a divergence in what billing can
# attribute. Change both or neither.
#
# Everything outside this set is dropped locally (with a DEBUG line naming it)
# rather than shipped, so a typo'd key fails at the emitter instead of
# evaporating three hops away in a consumer we cannot see from here.
_METADATA_PASSTHROUGH_KEYS: frozenset[str] = frozenset(
    {
        "schema_id",
        "job_id",
        "fallback_used",
        "stage",
        "worker_name",
        "caller_client_id",
        # WHO ACTED (the Keycloak JWT ``sub``), carried ALONGSIDE the top-level
        # ``subject_id``, which stays WHO PAYS. Receiver landed first, as the
        # rule above requires: billing alembic 0021 adds the column and
        # ``_parse_uuid`` reads it (malformed/empty -> NULL). It is nullable and
        # never defaulted there, so an absent actor is a first-class state.
        #
        # Produced by ``emit_cost_event`` (0.34.0): the request-bound
        # ``X-Actor-Id`` (kag_common.attribution), else this service's own
        # ``SERVICE_ACTOR_ID``, else omitted and counted on
        # ``kag_common_actor_missing_total``. See :func:`_resolve_actor`.
        "actor_id",
    }
)

# Default stream trim bound (approximate) — matches the fleet-wide value.
_DEFAULT_MAXLEN = 100_000

# Strong references to in-flight fire-and-forget emit tasks. Without this set the
# event loop's weak reference is the only one, so the task can be GC'd before the
# XADD completes. ``add_done_callback`` discards on completion.
_background_tasks: set[asyncio.Task[None]] = set()

# Bounded producer-side retry: the cost-bus Redis is a single-replica store;
# during a pod roll or a brief blip every XADD fails ONCE and the event is
# dropped (warning only). A short bounded retry on connection/timeout errors
# rides out that window. ``METERING_EMIT_RETRY_BACKOFFS`` is a comma-separated
# seconds list; the default is a safe small pair.
_DEFAULT_EMIT_RETRY_BACKOFFS = (0.1, 0.3)


def _parse_retry_backoffs() -> tuple[float, ...]:
    """Parse ``METERING_EMIT_RETRY_BACKOFFS`` (env), else the safe default."""
    raw = os.getenv("METERING_EMIT_RETRY_BACKOFFS")
    if not raw:
        return _DEFAULT_EMIT_RETRY_BACKOFFS
    try:
        parsed = tuple(float(part) for part in raw.split(",") if part.strip())
    except ValueError:
        logger.warning("invalid METERING_EMIT_RETRY_BACKOFFS=%r; using default", raw)
        return _DEFAULT_EMIT_RETRY_BACKOFFS
    return parsed or _DEFAULT_EMIT_RETRY_BACKOFFS


def _retryable_redis_errors() -> tuple[type[BaseException], ...]:
    """Connection/timeout errors worth a bounded retry (resolved lazily)."""
    try:
        from redis.exceptions import ConnectionError as RedisConnectionError
        from redis.exceptions import TimeoutError as RedisTimeoutError
    except Exception:  # noqa: BLE001 — if redis isn't importable, simply don't retry
        return ()
    return (RedisConnectionError, RedisTimeoutError)


def resolve_stream() -> str:
    """Return the cost-bus stream name (``METERING_STREAM`` env, else canonical)."""
    return os.getenv("METERING_STREAM", CANONICAL_COST_STREAM)


def _resolve_project_id(project_id: str | uuid.UUID | None, tenant_id: str) -> str | None:
    """The cost row's top-level ``project_id``: the CALLING APP's own project.

    ⛔ Owner ruling 2026-10-07. In order:

    1. An explicit ``project_id`` argument (canonical non-nil UUID). A malformed
       one is dropped (DEBUG) and the chain continues — never coerced.
    2. The project bound on this request context
       (:mod:`kag_common.attribution`: inbound ``X-W2V-Project-Id`` /
       ``X-Project-Id``, or ``set_project_context``).
    3. The tenant-level project of the event's tenant, counted
       ``kag_cost_project_fallback_total{reason="tenant_level"}``.
    4. Nothing (key omitted), counted ``reason="no_project"`` — a non-UUID
       legacy tenant has no tenant-level project.

    billing reads it top-level (``cost_flusher``: ``c.get("project_id")``), not
    out of ``metadata``.
    """
    if project_id:
        explicit = parse_attribution_uuid(project_id)
        if explicit is not None:
            return explicit
        logger.debug("cost_event_project_id_dropped reason=not_a_uuid")
    bound = get_project_id_from_context()
    if bound:
        return bound
    fallback = tenant_level_project_id(tenant_id)
    record_cost_project_fallback("tenant_level" if fallback else "no_project")
    return fallback


def _resolve_metadata(
    metadata_extra: Mapping[str, Any] | None, job_id: str | None
) -> Mapping[str, Any] | None:
    """Fold ``job_id`` into the metadata passthrough (billing: ``metadata.job_id``).

    Precedence: a valid explicit ``job_id`` argument → an explicit
    ``metadata_extra["job_id"]`` (INCLUDING an explicit ``None``, which is how a
    caller says "no job for this event" and suppresses the ambient one) → the
    job bound on the request context. Returns ``metadata_extra`` untouched when
    there is nothing to add, so the no-attribution wire shape is unchanged.
    """
    explicit = parse_job_id(job_id) if job_id else None
    if job_id and explicit is None:
        logger.debug("cost_event_job_id_dropped reason=malformed")
    if explicit is None:
        if metadata_extra is not None and "job_id" in metadata_extra:
            return metadata_extra
        explicit = get_job_id_from_context() or None
        if explicit is None:
            return metadata_extra
    merged = dict(metadata_extra or {})
    merged["job_id"] = explicit
    return merged


def _resolve_actor(
    metadata_extra: Mapping[str, Any] | None, service_key: str
) -> Mapping[str, Any] | None:
    """Fold ``actor_id`` (WHO ACTED) into the metadata passthrough.

    ⛔ Owner ruling 2026-10-07: the human's Keycloak sub when a human acted,
    otherwise the calling service's OWN service-account sub; never a sentinel.
    Precedence:

    1. An explicit truthy ``metadata_extra["actor_id"]`` — the caller's to state.
    2. The actor bound on this request context (inbound ``X-Actor-Id``, or
       :func:`kag_common.attribution.set_actor_context`) — the human's sub
       relayed from upstream, so it WINS over this service's own sub.
    3. Handling an inbound request with no valid actor: ``actor_id`` stays
       unset, counted ``kag_common_actor_missing_total{service=<service_key>,
       reason="inbound_without_actor"}`` — the service's own id is NOT
       substituted (0.36.0), so the caller's gap stays visible.
    4. Service-originated work (no inbound request): ``SERVICE_ACTOR_ID``.
    5. Nothing: unset, counted ``reason="no_service_actor"``.

    Resolution is :func:`kag_common.attribution.resolve_actor`.
    """
    if metadata_extra is not None and metadata_extra.get("actor_id"):
        return metadata_extra
    actor, missing = resolve_actor()
    if actor is None:
        record_actor_missing(service_key, missing or "unknown")
        return metadata_extra
    merged = dict(metadata_extra or {})
    merged["actor_id"] = actor
    return merged


def _build_fields(
    *,
    service_key: str,
    cost_source: str,
    tenant_id: str,
    license_id: str,
    subject_id: str,
    app_id: str,
    provider: str,
    model: str,
    served_model: str | None,
    input_tokens: int,
    output_tokens: int,
    latency_ms: int,
    cost_usd: float,
    provider_request_id: str,
    usage_extra: dict[str, Any] | None,
    metadata_extra: Mapping[str, Any] | None = None,
    event_key: str | None = None,
    project_id: str | None = None,
) -> dict[str, str]:
    """Marshal a cost event into the EMITTER_GUIDE.md string-field shape.

    ``tenant_id`` is expected to be already validated by the caller
    (:func:`kag_common.tenant.require_tenant_id`); no sentinel is substituted
    here. See the ``UNATTRIBUTED_TENANT_ID`` removal note at the top of this
    module.
    """
    fields = {
        # Producer-minted idempotency key: ONE per physical metered call.
        #
        # billing-service claims this key in an inbox table
        # (``ProcessedCostEventKey``, ``cost_flusher.py:732-780``) and drops any
        # event whose key it has already seen. An event that arrives WITHOUT the
        # field skips that claim entirely — ``key_rows = [p for p in survived if
        # p[0].get("event_key")]`` at :746, and the keyless remainder is added
        # back unconditionally at :780 — so it is billed every time. That is what
        # every event from this module used to do, because ``_build_fields``
        # never emitted the field: kag rows measured 0% event_key over 6h while
        # mlx-backend and inference-router were both 100%.
        #
        # That is a live double-bill, not a theoretical one: ``emit_cost_event``
        # RETRIES the XADD on ``RedisTimeoutError``/``ConnectionError`` (the
        # bounded-retry loop below). A timeout raised AFTER redis accepted the
        # write re-adds the same charge under a fresh stream message id, and
        # billing's other defence (``stream_msg_id``) cannot dedupe it because
        # the id genuinely differs. Billing is append-only — there is no refund,
        # void or reversal path anywhere in the estate — so the tenant pays twice.
        #
        # Minted HERE, in ``_build_fields``, which runs ONCE before the retry
        # loop: every attempt for one logical call therefore carries the SAME
        # key. Minting it inside the loop would make the retry undedupable again.
        #
        # A caller that already owns an idempotency key for the metered call
        # (a job id, an upstream request key) may pass it as ``event_key`` and it
        # is honoured verbatim. A falsy one falls back to minting rather than
        # shipping ``""``, which billing's ``.get("event_key")`` reads as absent —
        # i.e. as no dedup at all.
        "event_key": event_key or str(uuid.uuid7()),
        "tenant_id": tenant_id,
        "license_id": license_id,
        "subject_id": subject_id,
        "app_id": app_id,
        "service_key": service_key,
        "cost_source": cost_source,
        "provider": provider,
        "model": model,
        "served_model": served_model or model,
        "input_tokens": str(input_tokens),
        "output_tokens": str(output_tokens),
        "cost_usd": f"{cost_usd:.8f}",
        "latency_ms": str(latency_ms),
        "provider_request_id": provider_request_id,
        "usage_extra": json.dumps(usage_extra or {}, sort_keys=True),
        "timestamp": datetime.now(UTC).isoformat(),
    }
    if project_id:
        # Already resolved by ``_resolve_project_id``. Absent -> key OMITTED,
        # never "" (billing stores NULL for an absent key, and an empty string
        # would claim attribution was attempted).
        fields["project_id"] = project_id
    if not metadata_extra:
        # Additive contract: with the kwarg omitted (or empty) the emitted dict
        # is byte-identical to what every existing caller ships today.
        return fields
    dropped = []
    for key, value in metadata_extra.items():
        if key not in _METADATA_PASSTHROUGH_KEYS:
            dropped.append(key)
            continue
        if value is None:
            # ``str(None)`` is the truthy literal "None", which the receiver's
            # ``if c.get(k)`` would happily store as real metadata. A key with no
            # value is "not provided", not the string "None".
            continue
        fields[key] = str(value)
    if dropped:
        logger.debug(
            "cost_event_metadata_keys_dropped keys=%s allowed=%s",
            sorted(dropped),
            sorted(_METADATA_PASSTHROUGH_KEYS),
        )
    return fields


async def emit_cost_event(
    redis_conn: aioredis.Redis,
    *,
    service_key: str,
    cost_source: str,
    tenant_id: str,
    provider: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    latency_ms: int,
    license_id: str = "",
    subject_id: str = "",
    app_id: str = "",
    served_model: str | None = None,
    cost_usd: float = 0.0,
    provider_request_id: str = "",
    usage_extra: dict[str, Any] | None = None,
    metadata_extra: Mapping[str, Any] | None = None,
    event_key: str | None = None,
    stream: str | None = None,
    maxlen: int = _DEFAULT_MAXLEN,
    project_id: str | uuid.UUID | None = None,
    job_id: str | None = None,
) -> None:
    """XADD a cost event to the cost-bus stream.

    ``project_id`` is the CALLING APP's own project (owner ruling 2026-10-07),
    emitted as the top-level ``project_id`` field billing reads. Resolution:
    explicit argument → the project bound on the request context
    (:mod:`kag_common.attribution`) → the tenant-level project (counted on
    ``kag_cost_project_fallback_total``) → omitted. See :func:`_resolve_project_id`.

    ``job_id`` lands in ``metadata.job_id``: explicit argument →
    ``metadata_extra["job_id"]`` → the job bound on the request context.

    ``metadata.actor_id`` (WHO ACTED): explicit ``metadata_extra["actor_id"]`` →
    the actor bound on the request context (``X-Actor-Id``, the human's sub) →
    ``SERVICE_ACTOR_ID`` (this service's own sub) ONLY for service-originated
    work → unset, counted on ``kag_common_actor_missing_total{reason}``
    (``inbound_without_actor`` while handling an inbound request). See
    :func:`_resolve_actor`.

    Field shape matches EMITTER_GUIDE.md — every value is a string at the Redis
    layer. ``cost_usd`` is advisory (billing recomputes from the centralised
    ``provider_pricing`` table). ``stream`` defaults to :func:`resolve_stream`.

    ``metadata_extra`` carries originator attribution — the keys in
    :data:`_METADATA_PASSTHROUGH_KEYS`, which billing lifts into
    ``billing_cost_events.metadata``. Values are coerced to ``str``; keys outside
    that set are dropped here (DEBUG-logged) rather than shipped to be discarded
    silently by the receiver. Omitting it emits exactly today's field dict.

    ``event_key`` is the per-call idempotency key billing dedupes on. Omit it and
    one is minted (uuid7); pass one to reuse a key you already own.

    NEVER-RAISES CONTRACT, WITH ONE DELIBERATE EXCEPTION. Transport failures
    (Redis down, XADD timeout, an unserialisable usage payload) are still
    swallowed with a warning — dropping one cost event must not fail a customer
    request. A missing tenant_id is NOT a transport failure: it is a caller bug
    that used to be papered over with the nil-UUID sentinel, so it raises
    :class:`kag_common.tenant.TenantError` **out of this coroutine**, BEFORE the
    swallow. It is validated first, outside the ``try``, precisely so the
    never-raises handler cannot re-hide it.

    :raises kag_common.tenant.MissingTenantError: no tenant supplied.
    :raises kag_common.tenant.InvalidTenantIdError: tenant is not a ``str``.
    """
    tenant = require_tenant_id(tenant_id, source=f"cost event ({service_key}/{cost_source})")
    try:
        resolved_project = _resolve_project_id(project_id, tenant)
        metadata_extra = _resolve_metadata(metadata_extra, job_id)
        metadata_extra = _resolve_actor(metadata_extra, service_key)
        fields = _build_fields(
            service_key=service_key,
            cost_source=cost_source,
            tenant_id=tenant,
            license_id=license_id,
            subject_id=subject_id,
            app_id=app_id,
            provider=provider,
            model=model,
            served_model=served_model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            cost_usd=cost_usd,
            provider_request_id=provider_request_id,
            usage_extra=usage_extra,
            metadata_extra=metadata_extra,
            event_key=event_key,
            project_id=resolved_project,
        )
        target = stream or resolve_stream()
        retryable = _retryable_redis_errors()
        # Bounded retry on transient connection/timeout errors. The trailing
        # ``None`` sentinel marks the final attempt — re-raise so the outer
        # handler logs the warning (the never-raises contract is held).
        for backoff in (*_parse_retry_backoffs(), None):
            try:
                # redis-py stubs declare xadd's ``fields`` as bytes-typed; with
                # decode_responses=True the runtime accepts (and returns)
                # strings. Cast to satisfy the stub without runtime cost.
                await redis_conn.xadd(
                    target,
                    cast(dict[Any, Any], fields),
                    maxlen=maxlen,
                    approximate=True,
                )
                return
            except retryable:
                if backoff is None:
                    raise  # retries exhausted — fall through to the warning
                await asyncio.sleep(backoff)
    except Exception as exc:  # noqa: BLE001 — fire-and-forget; never block the caller
        # ⚠️ COUNTED, not merely logged. The neighbouring no-loop drop in
        # ``schedule_cost_event`` below was deliberately raised DEBUG -> WARNING
        # because "at DEBUG this loss was emitted into nothing". A WARNING is one
        # step better and still not MEASURABLE: nothing can alert on a log line,
        # and this is the SHARED emitter for the whole kag lineage, so a single
        # cost-bus blip drops every consuming service's spend at once while
        # Prometheus shows a flat, healthy graph. One counter here instruments
        # all of them.
        #
        # This is instrumentation, NOT a behaviour change: no re-raise is added,
        # the never-raises contract still holds (prometheus_client coerces label
        # values, so ``.inc()`` cannot throw), and the warning below is kept.
        record_cost_event_emit_failed(service_key, type(exc).__name__)
        logger.warning("cost_event_emit_failed", exc_info=True)


#: ``error_type`` label value for a cost event that was never handed to a loop.
#:
#: Deliberately a fourth value on the EXISTING
#: :data:`kag_common.metrics.cost_event_emit_failed_total` rather than a new
#: metric. That counter's question is "is this service losing billable spend?",
#: and a no-loop drop is the same loss as a failed XADD — same billable request,
#: same absent ledger row — differing only in WHERE it was lost. Splitting the
#: two across two metrics would mean every dashboard and every future alert has
#: to remember to sum both, and the one that gets forgotten is this one, because
#: it is the rarer.
#:
#: ⚠️ It is the ONE value of ``error_type`` that is not the class of an exception
#: that was actually raised: with escalation OFF (the default) nothing raises.
#: The string is still the exception CLASS NAME, because that is exactly what is
#: raised when ``METERING_REQUIRE_LOOP`` is on — the label does not move when the
#: flag does, so a series recorded in staging-with-escalation and one recorded in
#: production-without are the same series.
#:
#: ⛔ What this canNOT express, stated because the sibling fix in ``w2v_common``
#: can: a RATIO against the same service's successful emits. ``w2v_common`` puts
#: its drop on ``cost_events_total{outcome=...}``, whose other values include
#: ``ok``. This module has no success counter at all — the only cost-bus metric
#: here is failure-only — so "what fraction of this service's cost events are
#: being dropped?" is not answerable from kag metrics today, before or after this
#: change. That gap is real and is NOT closed here; adding an ``ok`` counter is a
#: separate change with a separate cardinality argument.
NO_LOOP_ERROR_TYPE = "NoRunningLoopError"

#: Env flag that ESCALATES a no-running-loop drop from counter + WARNING to a
#: raise. OFF by default, and it stays off by default: with no loop there is
#: nowhere to emit, so raising converts a lost BILLING RECORD into a failed
#: CUSTOMER REQUEST whose provider cost has ALREADY been incurred upstream. That
#: trades the revenue away as well as the evidence.
#:
#: ⭐ Its real use is a CI/staging tripwire: a service that believes all of its
#: call sites reach a running loop can set this in its test environment and turn
#: a latent production drop into a red build.
_REQUIRE_LOOP_ENV = "METERING_REQUIRE_LOOP"


class NoRunningLoopError(RuntimeError):
    """:func:`schedule_cost_event` was called with no running event loop.

    Only raised when :data:`_REQUIRE_LOOP_ENV` is truthy. With the flag OFF (the
    default) the drop is counted on
    :data:`kag_common.metrics.cost_event_emit_failed_total` as
    ``error_type="NoRunningLoopError"``, a WARNING reproduces the event's
    identity, and the call returns ``False``.

    Subclasses ``RuntimeError`` because that is what ``asyncio.get_running_loop()``
    itself raises for this condition, so a caller that already guards the
    sync/async boundary with ``except RuntimeError`` keeps working.

    ⚠️ That inheritance cuts BOTH ways, and the sibling repo measured the cost:
    an enclosing ``except RuntimeError`` CONVERTS this raise instead of letting
    it escape, which silently defeated the escalation flag on 5 of 10 paths
    there. The derived population table in this PR reports, per call path,
    whether the raise escapes, is converted, or is swallowed — do not assume
    turning the flag on reddens anything without reading it.
    """


def require_loop() -> bool:
    """Is no-running-loop escalation enabled? (``METERING_REQUIRE_LOOP``)."""
    return _get_bool(_REQUIRE_LOOP_ENV, False)


def _record_no_loop_drop(
    *,
    service_key: str,
    cost_source: str,
    tenant: str,
    license_id: str,
    subject_id: str,
    app_id: str,
    provider: str,
    model: str,
    served_model: str | None,
    input_tokens: int,
    output_tokens: int,
    latency_ms: int,
    cost_usd: float,
    provider_request_id: str,
) -> None:
    """Make a no-running-loop drop loud: count it, then reproduce it in the log.

    Ordering is deliberate — COUNT FIRST, then log, then (only if escalation is
    on) raise. A raise placed before the counter would mean that turning
    ``METERING_REQUIRE_LOOP`` on BLINDS the very metric that measures the problem
    it escalates, so the flag would trade one silence for another.

    The WARNING carries every field billing needs to reconstruct the row by hand.
    ``usage_extra``/``metadata_extra`` are deliberately NOT rendered: they are
    caller-controlled and unbounded, and this line is emitted once per dropped
    billable call, so inlining them turns an incident into a log flood.

    :raises NoRunningLoopError: ``METERING_REQUIRE_LOOP`` is truthy.
    """
    record_cost_event_emit_failed(service_key, NO_LOOP_ERROR_TYPE)
    logger.warning(
        "cost_event_dropped_no_running_loop service_key=%s cost_source=%s "
        "tenant_id=%s license_id=%s subject_id=%s app_id=%s provider=%s "
        "model=%s served_model=%s input_tokens=%d output_tokens=%d "
        "latency_ms=%d cost_usd=%r provider_request_id=%s",
        service_key,
        cost_source,
        tenant,
        license_id,
        subject_id,
        app_id,
        provider,
        model,
        served_model or model,
        input_tokens,
        output_tokens,
        latency_ms,
        # ⭐ ``%r``, and NO ``isfinite`` coercion. This line IS the durable
        # record — nothing downstream recomputes it — so every value that is not
        # a plain number has to survive to the human who adjudicates it. TWO
        # distinct ways to destroy that, both avoided here and both mutation-
        # tested:
        #
        #   1. A ``cost_usd if math.isfinite(cost_usd) else 0.0`` guard turns
        #      ``nan`` into a wholly plausible zero, indistinguishable from a
        #      genuine zero-cost call. The sibling w2v_common fix carries exactly
        #      that coercion and marks it a known gap; it is not inherited here.
        #   2. ``%.8f`` silently floors any cost below 1e-8 to
        #      ``0.00000000`` — a fabricated zero arrived at by FORMATTING, with
        #      no guard anywhere to blame. (It does render ``nan`` correctly,
        #      which is exactly why it reads as safe.)
        #
        # ⛔ Do not "tidy" this into a fixed-precision format. A repr a human
        # must squint at beats a zero they will bill.
        cost_usd,
        provider_request_id,
    )
    if require_loop():
        raise NoRunningLoopError(
            f"cost event ({service_key}/{cost_source}) was dropped: "
            f"schedule_cost_event was called with no running event loop"
        )


def schedule_cost_event(
    redis_conn: aioredis.Redis,
    *,
    service_key: str,
    cost_source: str,
    tenant_id: str,
    provider: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    latency_ms: int,
    license_id: str = "",
    subject_id: str = "",
    app_id: str = "",
    served_model: str | None = None,
    cost_usd: float = 0.0,
    provider_request_id: str = "",
    usage_extra: dict[str, Any] | None = None,
    metadata_extra: Mapping[str, Any] | None = None,
    event_key: str | None = None,
    stream: str | None = None,
    maxlen: int = _DEFAULT_MAXLEN,
    project_id: str | uuid.UUID | None = None,
    job_id: str | None = None,
) -> bool:
    """Fire-and-forget :func:`emit_cost_event`, GC-safe.

    ``project_id`` / ``job_id`` are forwarded verbatim; resolution against the
    request context happens inside the task, which ``create_task`` runs in a
    COPY of the caller's context, so the caller's bound attribution is seen.

    Spawns the emit as a background task and retains a strong reference until it
    completes, so the event can never be garbage-collected before the XADD
    lands. Returns immediately; never blocks the caller.

    The tenant is validated SYNCHRONOUSLY, in the caller's frame, before the task
    is spawned — a ``TenantError`` raised inside a fire-and-forget task would
    surface only as an "exception never retrieved" warning, i.e. exactly the
    silent mis-attribution this change exists to end.

    :returns: ⭐ A POSITIVE HANDOFF MARKER. ``True`` means the emit was handed to
        a running event loop as a retained task. ``False`` means there was no
        running loop, so nothing was handed off and the event was DROPPED (it is
        counted and logged — see below). Before this return value existed the two
        outcomes were INDISTINGUISHABLE at the call site: the function returned
        ``None`` and raised nothing on both paths, so a caller could only INFER
        success from the absence of an exception.

        ⚠️ ``True`` is a statement about the HANDOFF, not about delivery. The
        XADD can still fail inside the task; that terminal outcome is
        :data:`kag_common.metrics.cost_event_emit_failed_total` with the raising
        exception's class as ``error_type``. This return value distinguishes "the
        emit path ran" from "the emit path was never entered".

    NO-RUNNING-LOOP BEHAVIOUR (the drop, and why it stays a drop). When
    ``asyncio.get_running_loop()`` finds no loop there is nowhere to schedule the
    XADD, and this module holds no durable spool to defer it to. The event is
    therefore lost — but no longer lost SILENTLY:

    * :data:`kag_common.metrics.cost_event_emit_failed_total` is incremented with
      ``error_type="NoRunningLoopError"``, on the SAME series and under the same
      ``service`` label as a failed XADD, so one query covers both ways this
      module loses a billable event.
    * A **WARNING** reproduces the event's full identity — tenant, provider,
      model, token counts, latency, advisory cost and ``provider_request_id`` —
      so the billing row can be reconstructed by hand from the log line alone.
      That log line IS the durable record; there is no automatic replay, and
      pretending otherwise would be worse than the drop.
    * ``METERING_REQUIRE_LOOP=true`` escalates the drop to
      :class:`NoRunningLoopError`, with the counter incremented BEFORE the raise.

    ⛔ The raise is OPT-IN and stays opt-in. Raising by default would convert a
    lost billing record into a failed customer request — and by the time this
    function runs the provider call has already happened and already cost money,
    so the raise would forfeit the revenue as well as the evidence.

    :raises kag_common.tenant.MissingTenantError: no tenant supplied.
    :raises kag_common.tenant.InvalidTenantIdError: tenant is not a ``str``.
    :raises NoRunningLoopError: there is no running event loop AND
        ``METERING_REQUIRE_LOOP`` is on.
    """
    tenant = require_tenant_id(tenant_id, source=f"cost event ({service_key}/{cost_source})")
    # Resolve the loop BEFORE constructing the coroutine. The previous order built
    # it first and then had to ``coro.close()`` it on the no-loop path to suppress
    # a "coroutine was never awaited" warning. Not creating the coroutine is
    # strictly better than creating and closing it: it makes the orphaned-coroutine
    # class UNREACHABLE rather than merely handled, and it removes the only step
    # standing between detecting the drop and recording it.
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # ⛔ Do NOT collapse this into a bare ``return False``. The RECORDING is
        # the fix; the return value only lets the caller act on it.
        _record_no_loop_drop(
            service_key=service_key,
            cost_source=cost_source,
            tenant=tenant,
            license_id=license_id,
            subject_id=subject_id,
            app_id=app_id,
            provider=provider,
            model=model,
            served_model=served_model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            cost_usd=cost_usd,
            provider_request_id=provider_request_id,
        )
        return False
    task = loop.create_task(
        emit_cost_event(
            redis_conn,
            service_key=service_key,
            cost_source=cost_source,
            tenant_id=tenant,
            provider=provider,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            license_id=license_id,
            subject_id=subject_id,
            app_id=app_id,
            served_model=served_model,
            cost_usd=cost_usd,
            provider_request_id=provider_request_id,
            usage_extra=usage_extra,
            metadata_extra=metadata_extra,
            event_key=event_key,
            stream=stream,
            maxlen=maxlen,
            project_id=project_id,
            job_id=job_id,
        )
    )
    # Retain a strong ref until the task completes so it can't be GC'd mid-XADD.
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return True


# Placeholder emitted when a URL cannot be confidently taken apart. Redaction
# fails CLOSED: an unrecognised shape yields this, never the input.
_REDACTED_URL = "<redacted-url>"


def _redact_url(url: str) -> str:
    """Return ``url`` with every credential-bearing part removed.

    Keeps only what an operator actually needs from a connection string —
    scheme, host, port and path (for Redis, the db index). Everything that can
    carry a credential is dropped WHOLESALE rather than filtered:

    * userinfo (``user:password@``) — the obvious one;
    * the query string — ``redis://host:6379/0?password=...`` is a legitimate
      redis-py URL form, so a redaction that only stripped userinfo would still
      leak;
    * the fragment.

    Dropping whole components rather than substituting known-bad keys means a
    credential cannot survive in a part this function did not think to inspect.

    Fails CLOSED. Anything without a scheme AND a host — or that ``urlsplit``
    rejects outright — returns :data:`_REDACTED_URL` rather than the input, so
    an unparseable string is never echoed into a log on the assumption that it
    held nothing secret.
    """
    if not url:
        return ""
    try:
        parts = urlsplit(url)
        host = parts.hostname
        if not parts.scheme or not host:
            return _REDACTED_URL
        # urlsplit strips the brackets from an IPv6 literal; put them back or
        # the rebuilt netloc is ambiguous against the port separator.
        netloc = f"[{host}]" if ":" in host else host
        port = parts.port  # raises ValueError on a non-numeric/out-of-range port
        if port is not None:
            netloc = f"{netloc}:{port}"
        return urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    except ValueError, TypeError:
        return _REDACTED_URL


async def init_metering_redis(url: str) -> aioredis.Redis | None:
    """Open the metering Redis connection. Returns None when disabled/unreachable.

    The metering stream lives on a SEPARATE Redis from any service-local cache /
    Celery broker. When ``url`` is empty, metering is disabled — emits silently
    no-op.
    """
    if not url:
        logger.warning("METERING_REDIS_URL not set — cost events will not be emitted")
        return None
    try:
        import redis.asyncio as aioredis

        # ⛔ EVERY ONE OF THESE IS LOad-BEARING. A bare from_url() here can hang
        # the emitter FOREVER, silently, and the surrounding retry/logging cannot
        # see it happen.
        #
        # Without socket_timeout a half-open socket makes `await xadd(...)` block
        # indefinitely: it never raises, so the bounded retry below never runs,
        # the `except Exception` never fires, and the "cost_event_emit_failed"
        # warning never logs. Each subsequent emit spawns another task that also
        # hangs and accumulates in _background_tasks — an unbounded task leak
        # whose only symptom is silence. That is worse than an error: an error is
        # counted somewhere, a hang is invisible everywhere.
        #
        # ⚠️ health_check_interval is the one that prevents it rather than
        # recovering from it. The inference-router fork of this client already
        # sets it and names the cause in its own comment (src/main.py:187-196):
        # "redis.example's idle-reaper RSTs sockets that have been quiet for a
        # while". An emitter is idle by nature between bursts, so it is exactly
        # the client that gets reaped.
        #
        # ⭐ That sibling sets socket_connect_timeout / health_check_interval /
        # retry_on_timeout but NOT socket_timeout, so it still has the infinite
        # hang on a socket that is half-open rather than reaped. Fixed here in
        # full; the sibling is worth the same treatment.
        client = aioredis.from_url(
            url,
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=5,
            health_check_interval=30,
            retry_on_timeout=True,
        )
        # ping() returns Awaitable[bool] under decode_responses=True; cast for ty.
        await cast(Any, client.ping())
        # ⛔ NEVER log ``url`` itself: METERING_REDIS_URL carries the cost-bus
        # password, and this line runs at startup in every consumer of this
        # library, so the raw value landed in pod stdout -> the log aggregator
        # -> anything scraping it. Redacted through the helper so the host/port
        # /db an operator needs survives and the credential does not.
        logger.info("Metering Redis connected: %s", _redact_url(url))
        return client
    except Exception:  # noqa: BLE001 — metering must never fail boot
        logger.warning("metering_redis_init_failed; events will be dropped", exc_info=True)
        return None


async def drain_pending(timeout: float = 5.0) -> None:  # noqa: ASYNC109 — bounded drain budget is the intended public knob, not an asyncio.timeout cancel scope
    """Await in-flight fire-and-forget emit tasks. Never raises.

    ``schedule_cost_event`` spawns emits as background tasks; on SIGTERM the
    event loop stops and any still-pending XADD is cancelled mid-flight ->
    silent cost-event loss. Calling this on a normal lifespan shutdown lets the
    in-flight emits land first. Bounded by ``timeout`` so a wedged emit can't
    block shutdown forever. Safe to call with nothing pending (returns at once).
    """
    # Copy first: tasks remove themselves from the live set via done-callback.
    pending = [task for task in set(_background_tasks) if not task.done()]
    if not pending:
        return
    try:
        await asyncio.wait(pending, timeout=timeout)
    except Exception:  # noqa: BLE001 — drain is best-effort; never block shutdown
        logger.warning("metering_drain_pending_failed", exc_info=True)


async def close_metering_redis(
    client: aioredis.Redis | None, *, drain_timeout: float = 5.0
) -> None:
    """Close the metering Redis connection. Safe to call with None.

    Drains in-flight fire-and-forget emits BEFORE closing the client so a normal
    lifespan shutdown doesn't cancel a pending XADD. Bounded by ``drain_timeout``
    so shutdown can never hang on a wedged emit.
    """
    await drain_pending(timeout=drain_timeout)
    if client is None:
        return
    try:
        await client.aclose()
    except Exception:  # noqa: BLE001 — shutdown best-effort
        logger.warning("metering_redis_close_failed", exc_info=True)
