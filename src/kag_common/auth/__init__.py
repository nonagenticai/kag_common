"""Shared license-introspection + auth helpers for the KAG backends.

This carries only the *pure* and *identical* pieces of the license-authz
boundary that all four backends (``karma_service``, ``hirag_service``,
``kag_orchestrator``, ``ingestion_service``) had hand-rolled — and previously
duplicated again inside both ``auth/middleware.py`` and ``auth/tenant.py`` of
each service (8 copies total):

- ``introspect_license`` — a single process-scoped TTL-cached call against the
  licenses service, backed by one lazily-built pooled ``httpx.AsyncClient``. A
  per-token single-flight lock collapses a cold-cache burst of concurrent
  requests for the same token into ONE upstream POST (the 2026-06-27 TTS bug
  class: a stampede on a CPU-saturated box starved the loop and tripped the
  introspect timeout → spurious 401), and a short-TTL negative cache absorbs
  ``active: false`` results so a revoked token can't pin the licenses endpoint.
  The lock map is a bounded LRU, not a dict: it is keyed per BEARER TOKEN on a
  PRE-AUTH path, so an unbounded map is an attacker-driven memory leak.
- ``is_trusted_network`` / ``is_public_path`` / ``is_protected_path`` predicates,
  plus ``is_trusted_identity_source`` — the opt-in gate that must guard any
  tokenless, header-asserted identity (see the wire-format note below).
- ``extract_license_token`` (``X-Tenant-Id: Bearer <token>`` only), and since
  0.37.0 the OPT-IN ``extract_license_token_with_source`` +
  ``bind_plain_tenant`` pair for the gateway's ``Authorization`` carrier (below).
- the ``error_payload`` / ``unauthorized_response`` envelope.

What deliberately STAYS per-service: the ASGI middleware ``dispatch`` and its
``request.state`` population, each service's ``PUBLIC_ENDPOINTS`` /
``PROTECTED_PREFIXES`` sets (passed into the predicates here), and the
``User``-model construction. Those encode genuinely divergent auth contracts and
must not be hidden behind a config-driven base.

Wire format (identical across all backends): license tokens travel in
``X-Tenant-Id: Bearer <token>``; by default ``Authorization`` is reserved for the
caller's own auth. RFC1918 / loopback peers bypass introspection (the ASGI
``testclient`` name short-circuit was removed in 0.20.0 — see
``is_trusted_network``).

NEW IN 0.37.0 — OPT-IN: the licence in ``Authorization: Bearer <licence>``.
The istio ingress gateway validates ``Authorization: Bearer <licence>``, strips
client identity headers, injects a PLAIN uuid ``x-tenant-id`` and leaves
``Authorization`` in place. A service reading the licence only from
``X-Tenant-Id: Bearer`` therefore sees none on gateway traffic and drops to the
trusted-network path — where any in-mesh pod can assert any tenant with a bare
``X-Tenant-Id``. A service opts in with ``AUTH_ACCEPT_AUTHORIZATION_LICENCE=true``
(exactly ``"true"``; anything else is off) or ``accept_authorization=True``:

1. ``token, source = extract_license_token_with_source(request)`` —
   ``X-Tenant-Id: Bearer`` keeps precedence; ``Authorization`` is read only when
   opted in.
2. introspect; ``active: false`` ⇒ **401, hard, no fallback** (George
   2026-10-14: a Keycloak JWT or any other non-licence token in
   ``Authorization`` is a 401 once a service opts in — never retried as the
   caller's own auth, never downgraded to the trusted-network path).
3. ``requested = await bind_plain_tenant(request, credential_tenant=...,
   subject_id=..., source=source, resolve=<your resolver>)`` — raises
   ``LicenceTenantMismatch`` (render **403**) when a non-delegating caller's
   plain ``X-Tenant-Id`` or ``X-Effective-Tenant-Id`` names another tenant;
   for a delegating subject the plain header stands in for
   ``X-Effective-Tenant-Id``.
4. ``apply_effective_tenant(..., requested=requested)`` as before.

Off (the default), 0.37.0 changes nothing: ``extract_license_token`` is
untouched, nothing here calls the new helpers, and ``apply_effective_tenant``'s
new ``requested`` keyword defaults to the old header read. Reference
implementation: requirements_management #222 / #223 (``src/auth/middleware.py``).

NEW IN 0.20.0 — an OPT-IN gate for tokenless identity (nothing changes by
default). ``is_trusted_network()`` answers *"where did this come from"*; it does
NOT answer *"who is this"*, and the default ``TRUSTED_CIDRS`` includes
``10.0.0.0/8``, a superset of the k3s pod CIDR. A consumer that reads a bare
``X-Tenant-Id`` as a CREDENTIAL after an ``is_trusted_network()`` check is
therefore letting any pod name any tenant; RLS then binds ``app.current_tenant``
to the forged tenant and faithfully scopes the query to the victim.

``is_trusted_identity_source()`` is the predicate such a consumer should use
instead: it requires BOTH network membership AND an explicit
``AUTH_TRUST_INCLUSTER_IDENTITY=true``. This release only ADDS it —
``TRUSTED_NETWORKS``, ``is_trusted_network()`` and the shipped default CIDR list
are unchanged, so no existing caller's behaviour moves. Migration of the
consumers (and the gateway pre-arm that must precede it) is a separate change.

⛔ READ THIS BEFORE TRUSTING ANY HELPER BELOW — THE GATE IS AT *YOUR* CALL SITE
==============================================================================
This package ships **no ASGI dispatch on purpose** (see "What deliberately STAYS
per-service" above). Nothing in this library ever sees a request. Therefore:

    **Bumping your kag-common pin protects you from NOTHING.**

``trust_incluster_identity()`` / ``is_trusted_identity_source()`` /
``resolve_tokenless_tenant()`` cannot fire unless YOUR middleware calls them. A
consumer that upgrades and changes nothing else is exactly as exploitable as it
was before. Do not read the presence of these helpers as protection.

Two things make that statement enforceable rather than merely written down:

1. :func:`resolve_tokenless_tenant` — the single seam that performs the whole
   decision (peer + opt-in + header parse). Call it instead of assembling the
   predicates yourself; the assembly is where the bug gets re-derived.
2. ``kag_common.auth.conformance.assert_tokenless_identity_is_gated`` — a lint a
   consumer wires into its OWN test suite in one line, which fails the build if
   any branch in its source uses network membership as an identity gate. That is
   the closest this library can get to a guard that fires for someone else, and
   it is the reason the helpers above are not just decorative.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import os
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, Literal

import httpx
from cachetools import LRUCache, TTLCache
from starlette import status
from starlette.responses import JSONResponse

from kag_common.env import _get_bool
from kag_common.metrics import (
    TOKENLESS_ADMITTED,
    TOKENLESS_REFUSED_BEARER,
    TOKENLESS_REFUSED_NO_HEADER,
    TOKENLESS_REFUSED_PEER,
    record_tokenless_tenant_assertion,
    record_trusted_network_bypass,
)

from .outbound import outbound_headers

if TYPE_CHECKING:
    from collections.abc import Collection, Mapping

    from starlette.requests import Request

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_TRUSTED_CIDRS",
    "ACCEPT_AUTHORIZATION_LICENCE_ENV",
    "EFFECTIVE_TENANT_HEADER",
    "LICENCE_SOURCE_AUTHORIZATION",
    "LICENCE_SOURCE_X_TENANT_ID",
    "TRUSTED_NETWORKS",
    "LicenceSource",
    "LicenceTenantMismatch",
    "TenantResolver",
    "accept_authorization_licence",
    "apply_effective_tenant",
    "authorization_bearer",
    "bind_licence_tenant_claims",
    "bind_plain_tenant",
    "clear_license_cache",
    "close_license_introspect_client",
    "delegating_subjects",
    "error_payload",
    "extract_license_token",
    "extract_license_token_with_source",
    "get_license_http_client",
    "introspect_license",
    "is_protected_path",
    "is_public_path",
    "is_trusted_identity_source",
    "is_trusted_network",
    "outbound_headers",
    "parse_trusted_cidrs",
    "plain_tenant_header",
    "require_own_tenant",
    "resolve_tokenless_tenant",
    "trust_incluster_identity",
    "unauthorized_response",
]

# --------------------------------------------------------------------------- #
# Effective-tenant delegation (WS-4 on-behalf-of, receiver side). A trusted
# service account may act on behalf of another tenant by sending
# ``X-Effective-Tenant-Id`` alongside its own ``X-Tenant-Id: Bearer <SA>``. This
# mirrors ``w2v_common.auth.middleware._apply_effective_tenant`` so the kag
# lineage (ingestion_service et al.) can attribute a background run's REAL tenant
# downstream for cost metering + per-product BYO resolution. Gated by
# ``AUTH_DELEGATING_SUBJECTS`` (CSV env) — empty (default) disables it entirely,
# so existing consumers are unaffected until they opt in.
# --------------------------------------------------------------------------- #
EFFECTIVE_TENANT_HEADER = "X-Effective-Tenant-Id"


def delegating_subjects() -> frozenset[str]:
    """Subjects allowed to assert an effective tenant via X-Effective-Tenant-Id.

    Read from ``AUTH_DELEGATING_SUBJECTS`` (CSV env) at call time — like the rest
    of this module's env reads — so runtime config / test overrides are picked up
    without a reload. Empty (the default) disables delegation.
    """
    raw = os.getenv("AUTH_DELEGATING_SUBJECTS", "")
    return frozenset(s.strip() for s in raw.split(",") if s.strip())


def apply_effective_tenant(
    request: Request,
    auth_subject: str | None,
    tenant_id: str,
    subject_id: str,
    license_id: str | None,
    *,
    requested: str | None = None,
) -> tuple[str, str, str | None]:
    """Re-scope identity to X-Effective-Tenant-Id for a delegating service account.

    The Bearer license token authenticates the CALLER (a service account whose
    token introspects to the SA tenant). A trusted service account — its
    introspected ``auth_subject`` is in ``AUTH_DELEGATING_SUBJECTS`` — may act on
    behalf of another tenant by sending ``X-Effective-Tenant-Id``. This threads a
    background run's REAL tenant (not the SA tenant) downstream for cost
    attribution + BYO resolution. A customer token's subject is never a delegator,
    so a customer can never spoof another tenant; empty config ⇒ no-op.

    ``requested`` (0.37.0, keyword-only) overrides the header read: ``None`` (the
    default) reads ``X-Effective-Tenant-Id`` exactly as before. Pass the value
    returned by :func:`bind_plain_tenant` when the licence came in
    ``Authorization`` and the plain ``X-Tenant-Id`` stands in for it.

    Returns the (possibly re-scoped) ``(tenant_id, subject_id, license_id)``.
    The re-scoped tenant is RAW caller input; verify it against the registry
    before it reaches a uuid column / RLS GUC.
    """
    header = (request.headers.get(EFFECTIVE_TENANT_HEADER) or "").strip()
    eff_requested = header if requested is None else requested.strip()
    if not auth_subject or str(auth_subject) not in delegating_subjects():
        # A non-delegating caller asserting a DIFFERENT tenant is either a spoof
        # attempt or a receiver missing AUTH_DELEGATING_SUBJECTS config — surface
        # it instead of silently dropping. An equal-tenant value is a benign
        # no-op on the normal path (the S2S hook stamps this header
        # unconditionally): don't warn on it, that would be fleet-wide log spam.
        eff = eff_requested
        if eff and eff != tenant_id:
            logger.warning(
                "effective-tenant header rejected (subject not delegating): subject=%s",
                auth_subject or "<missing>",
            )
        return tenant_id, subject_id, license_id
    eff_tenant = eff_requested
    if not eff_tenant or eff_tenant == tenant_id:
        return tenant_id, subject_id, license_id
    logger.info(
        "effective-tenant delegation: subject=%s acting as tenant=%s (service-account tenant=%s)",
        auth_subject,
        eff_tenant,
        tenant_id,
    )
    # Carry the run's own subject/license when the delegator forwarded them, so
    # per-user metering attributes to the customer rather than the service account.
    fwd_subject = (request.headers.get("X-Subject-Id") or "").strip()
    fwd_license = (request.headers.get("X-License-Id") or "").strip()
    return eff_tenant, fwd_subject or subject_id, fwd_license or license_id


# --------------------------------------------------------------------------- #
# Trusted networks (RFC1918 / loopback) — read once at import, like the
# per-service copies it replaces.
#
# The shipped default is UNCHANGED by this release. It is only lifted out of the
# `os.getenv` call into an explicit named constant (`DEFAULT_TRUSTED_CIDRS`) with
# a reusable parser, so it is assertable in tests and greppable in review.
#
# ⚠️ Read what this list is and is not. It is WIDE — every entry supersets an
# attacker-reachable network in this fleet:
#
#   * `10.0.0.0/8`     ⊃ the k3s pod CIDR `10.42.0.0/16` (and svc `10.43.0.0/16`)
#                        ⇒ EVERY pod in the cluster is a trusted peer.
#   * `172.16.0.0/12`  ⊃ the default docker bridge `172.17.0.0/16`
#                        ⇒ any sidecar/dind container on a node.
#   * `192.168.0.0/16` was the w2v SSR-proxy bypass vector (2026-04-18): an
#                        EXTERNAL caller routed through an in-cluster proxy
#                        presents a 192.168.x source.
#
# It is therefore usable as a "where did this come from" hint for non-identity
# allowlists (unauthenticated `/metrics`, health probes) but NOT, on its own, as
# an answer to "who is this" — see `trust_incluster_identity()` below, which is
# the separate, explicit gate for tokenless identity assertion.
#
# The list stays as-is deliberately: the API gateway is `hostNetwork` and SNATs
# to `10.42.0.0`, so ALL authenticated external traffic arrives on this branch by
# design (`gitops-production/clusters/strato/policies/envoy-filters/
# ext-authz-enforce.yaml` strips the client `x-tenant-id`, validates the license
# token, and re-injects a bare `x-tenant-id`). Narrowing the default without a
# gateway pre-arm + caller migration would 401 all gateway traffic.
# --------------------------------------------------------------------------- #
DEFAULT_TRUSTED_CIDRS = "127.0.0.1/32,::1/128,192.168.0.0/16,172.16.0.0/12,10.0.0.0/8"


def parse_trusted_cidrs(raw: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse a CSV CIDR list into networks. Blank entries are ignored."""
    return [
        ipaddress.ip_network(cidr.strip(), strict=False) for cidr in raw.split(",") if cidr.strip()
    ]


TRUSTED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = parse_trusted_cidrs(
    os.getenv("TRUSTED_CIDRS", DEFAULT_TRUSTED_CIDRS)
)


def is_trusted_network(host: str | None) -> bool:
    """Pure NETWORK-membership predicate: is ``host`` inside ``TRUSTED_NETWORKS``?

    ⚠️ This answers "where did it come from", NOT "who is it". It is a legitimate
    input to non-identity allowlists (unauthenticated ``/metrics``, health probes
    from a known CIDR). It MUST NOT be used on its own to accept a client-supplied
    tenant — use :func:`is_trusted_identity_source` for that.

    REMOVED in 0.20.0: the ``host == "testclient"`` short-circuit. It returned
    True unconditionally — not CIDR-checked, not flag-gated — for any peer whose
    name is the literal string ``testclient``, i.e. a hardcoded unauthenticated
    bypass compiled into every consumer's shipped image. It is not prod-reachable
    (the name comes from the socket peername, and nothing here consumes
    ``X-Forwarded-For``), but a bypass that exists only to make tests convenient
    is a bypass that has to be reasoned about at every review, and
    ``graph_adapter_service/src/auth/resolver.py:52`` refused to adopt this
    function specifically because adopting it would "silently defeat this repo's
    auth-bypass tests — a strict weakening of the test surface".

    Consumer note: a test suite that relied on the sentinel must give its client
    a real peer instead — starlette's ``TestClient(app, client=("127.0.0.1",
    50000))`` puts it back inside the loopback CIDR, which is a genuine
    membership rather than a name match.
    """
    trusted = _evaluate_trusted_network(host)
    # ⛔ OBSERVATION ONLY — this line changes no decision. `trusted` is already
    # computed above and is returned unchanged; `record_*` is contracted never to
    # raise. See kag_common.metrics for what the series does and does NOT mean
    # (it counts predicate EVALUATIONS, and three consumers evaluate it twice per
    # request, so it is an upper bound on requests rather than a request count).
    record_trusted_network_bypass(host, trusted)
    return trusted


def _evaluate_trusted_network(host: str | None) -> bool:
    """The membership test itself, with no instrumentation.

    Split out of :func:`is_trusted_network` so the counter cannot be confused
    with the decision: everything that decides lives here, everything that
    observes lives in the caller.
    """
    if not host:
        return False
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(addr in net for net in TRUSTED_NETWORKS)


# --------------------------------------------------------------------------- #
# Opt-in in-cluster identity trust
#
# Mirrors w2v_common, which closed this identical class in 0.6.9 by flipping the
# trusted-network fail-open to opt-in (`w2v_common/src/w2v_common/config/base.py`
# `AuthSettings.trust_incluster_identity`, consumed at
# `w2v_common/src/w2v_common/auth/middleware.py:794` as
# `if _trust_incluster_identity() and _is_trusted_network(client_host):`).
# Same env var name (`AUTH_TRUST_INCLUSTER_IDENTITY`), same default (false), same
# call-time read. kag_common has no `AuthSettings` class, so the value is read
# with this module's own `_get_bool` env convention (cf. `delegating_subjects()`)
# rather than importing pydantic settings — semantics mirrored, local idiom kept.
#
# THE BUG THIS EXISTS TO CLOSE: consumers (`kag_orchestrator/src/auth/
# middleware.py`, `ingestion_service/src/auth/middleware.py`) gate a tokenless
# bypass on `is_trusted_network()` alone and then take the tenant straight off a
# bare `X-Tenant-Id` header. With `10.0.0.0/8` in the default CIDRs that lets ANY
# pod in the cluster assert ANY tenant with no credential. RLS then binds
# `app.current_tenant` to the FORGED tenant and faithfully scopes the query to
# the victim — a confused deputy, not a backstop.
#
# ⛔ NOTHING BELOW GATES A REQUEST BY ITSELF, AND IT NEVER WILL. This library has
# no ASGI dispatch, so these helpers are inert until a CONSUMER's middleware
# calls them. `is_trusted_network()` and the default CIDR list are untouched, so
# a consumer that merely bumps its kag-common pin sees NO behaviour change and
# gains NO protection. Since 0.21.0 the two enforcement aids are
# `resolve_tokenless_tenant()` (below — one call, whole decision, invoked by this
# module's own tests so a regression is caught here) and
# `kag_common.auth.conformance.assert_tokenless_identity_is_gated()` (a lint the
# consumer wires into its own suite, which FAILS on the exploitable shape).
# Flipping a consumer onto `is_trusted_identity_source()` is a
# SEPARATE change that must be sequenced with the gateway: the API gateway is
# `hostNetwork` and SNATs to `10.42.0.0`, so it lands on the trusted-network
# branch by design and asserts the tenant it validated with a bare
# `x-tenant-id`. Migrating a consumer before the gateway forwards a credential
# the consumer accepts would 401 all external traffic to it.
# --------------------------------------------------------------------------- #
def trust_incluster_identity() -> bool:
    """Whether a trusted-network peer may assert its own tenant WITHOUT a token.

    Reads ``AUTH_TRUST_INCLUSTER_IDENTITY`` at call time (like
    :func:`delegating_subjects`) so runtime config and test overrides are picked
    up without a module reload.

    Defaults to **False** — fail closed. A consumer must fall through to normal
    token authentication when this is off. Operators mid-migration can stage the
    rollout by setting it to ``true``.
    """
    return _get_bool("AUTH_TRUST_INCLUSTER_IDENTITY", False)


def is_trusted_identity_source(host: str | None) -> bool:
    """True only if ``host`` may assert an identity with no license token.

    The ONLY predicate a caller may use to accept a bare ``X-Tenant-Id`` as a
    credential. Requires BOTH the explicit opt-in flag AND network membership,
    so neither a widened ``TRUSTED_CIDRS`` nor the flag alone re-opens forgery.
    """
    return trust_incluster_identity() and is_trusted_network(host)


def resolve_tokenless_tenant(host: str | None, headers: Mapping[str, str]) -> str | None:
    """The ONE supported way to accept a tenant that arrived without a token.

    Returns the tenant a caller may assert with no credential, or ``None`` when
    the request must fall through to normal token authentication (i.e. fail
    closed). This is the whole decision — peer check, opt-in check, and header
    parse — in one call, so a consumer cannot re-derive the confused-deputy bug
    by wiring the predicates together incorrectly.

    ``None`` is returned when ANY of these hold:

    * :func:`is_trusted_identity_source` says no — either
      ``AUTH_TRUST_INCLUSTER_IDENTITY`` is not explicitly enabled (the default)
      or ``host`` is outside ``TRUSTED_NETWORKS``;
    * the tenant header is absent or blank;
    * the tenant header carries ``Bearer <token>``. That is a LICENSE TOKEN in
      the wire format this package documents, not a tokenless assertion — it
      must go through :func:`introspect_license`, and returning it here would
      hand the caller a tenant whose value is a secret.

    Header lookup is case-insensitive, so a plain ``dict`` and a Starlette
    ``Headers`` both work.

    Usage in a consumer's middleware, replacing an ``is_trusted_network`` branch::

        tenant = resolve_tokenless_tenant(request.client.host, request.headers)
        if tenant is not None:
            ...  # bind tenant, skip introspection
    """
    raw = ""
    for key, value in headers.items():
        if key.lower() == "x-tenant-id":
            raw = (value or "").strip()
            break
    # `has_header` is the HEADER-ABSENT / HEADER-PRESENT split, and it is the
    # whole point of this series: the two cases are different exposures. A caller
    # that sends a tenant it made up reads someone else's data under a name it
    # chose; a caller that sends NOTHING is served under whatever the consumer's
    # own `or DEFAULT_TENANT_ID` fallback names — a tenant nobody chose per
    # request, which is the shape that writes into a system tenant every tenant
    # inherits. Computed BEFORE the peer check so the refused rows carry it too.
    has_header = bool(raw)

    if not is_trusted_identity_source(host):
        record_tokenless_tenant_assertion(has_header, TOKENLESS_REFUSED_PEER)
        return None
    if not raw:
        record_tokenless_tenant_assertion(has_header, TOKENLESS_REFUSED_NO_HEADER)
        return None
    if raw.lower().startswith("bearer "):
        record_tokenless_tenant_assertion(has_header, TOKENLESS_REFUSED_BEARER)
        return None
    record_tokenless_tenant_assertion(has_header, TOKENLESS_ADMITTED)
    return raw


# --------------------------------------------------------------------------- #
# Path predicates — each service passes its own endpoint/prefix sets.
# --------------------------------------------------------------------------- #
# Implicit public trees. Matching is anchored to a path SEGMENT: `/docs` and
# `/docs/oauth2-redirect` are public, `/docsecret` is NOT. A bare `startswith`
# here was an auth-bypass class — the same shape that let `/storage/api/buckets/ready`
# reach MinIO unauthenticated (gitops #2204). No service ships a route that needs
# the loose form today, so this is a strict tightening, not a behaviour change.
_PUBLIC_PREFIXES = ("/docs", "/redoc", "/static", "/health")

# `/healthz` is served by every KAG-family service but listed in none of their
# PUBLIC_ENDPOINTS sets — it was public only via `"/healthz".startswith("/health")`.
# Kept explicit so the segment anchoring above cannot auth-wall a liveness probe.
# Deliberately NOT extended to `/readyz` or `/livez`: neither ever matched the old
# prefix rule, so adding them here would widen the exemption inside a fix whose
# entire point is to narrow it.
_PUBLIC_PROBE_PATHS = frozenset({"/healthz"})


def is_public_path(path: str, public_endpoints: Collection[str]) -> bool:
    """True for health/docs/static and any explicitly public endpoint."""
    clean = path.rstrip("/") or "/"
    if clean in public_endpoints or clean in _PUBLIC_PROBE_PATHS:
        return True
    return any(clean == prefix or clean.startswith(prefix + "/") for prefix in _PUBLIC_PREFIXES)


def is_protected_path(path: str, protected_prefixes: Collection[str]) -> bool:
    """True when ``path`` is under one of the service's protected prefixes."""
    clean = path.rstrip("/") or "/"
    return any(clean.startswith(prefix) for prefix in protected_prefixes)


def extract_license_token(request: Request) -> str | None:
    """Pull the license token out of ``X-Tenant-Id: Bearer <token>`` only.

    Unchanged since before 0.37.0 and deliberately so: it never reads
    ``Authorization``. A service that opts in to the gateway's carrier uses
    :func:`extract_license_token_with_source` instead.
    """
    x_tenant_id = request.headers.get("X-Tenant-Id", "")
    if x_tenant_id and x_tenant_id.lower().startswith("bearer "):
        return x_tenant_id[7:].strip() or None
    return None


# --------------------------------------------------------------------------- #
# 0.37.0 — OPT-IN: the licence in `Authorization: Bearer <licence>`.
#
# The istio ingress gateway validates `Authorization: Bearer <licence>`, strips
# every client identity header, injects a PLAIN uuid `x-tenant-id`, and leaves
# `Authorization` in place. A service that reads the licence only from
# `X-Tenant-Id: Bearer` sees no licence on that request, falls to the
# trusted-network path, and admits the bare header — the same branch on which
# ANY in-mesh pod can assert ANY tenant. Accepting the licence from
# `Authorization` puts gateway traffic back on the verified introspection path,
# which is what lets a service later close the tokenless path at all.
#
# Lifted from requirements_management (#222 0c14a613, #223 43dc8f1) so a service
# adopts by version bump + a few lines of dispatch, not by re-deriving it.
#
# INERT BY DEFAULT: nothing in this module calls these helpers, and
# `extract_license_token_with_source` ignores `Authorization` unless the caller
# passes `accept_authorization=True` or the env flag is exactly "true".
#
# ⛔ George 2026-10-14: once a service opts in, a NON-licence token in
# `Authorization` (a Keycloak JWT, anything else) is a HARD 401 — introspection
# says inactive ⇒ 401, with NO fallback to the caller's other auth and NO
# fallback to the trusted-network path. Do not add one.
# --------------------------------------------------------------------------- #
ACCEPT_AUTHORIZATION_LICENCE_ENV = "AUTH_ACCEPT_AUTHORIZATION_LICENCE"

#: Which header carried the licence returned by
#: :func:`extract_license_token_with_source`.
LicenceSource = Literal["x_tenant_id", "authorization"]
LICENCE_SOURCE_X_TENANT_ID: LicenceSource = "x_tenant_id"
LICENCE_SOURCE_AUTHORIZATION: LicenceSource = "authorization"

#: ``async (tenant_name_or_uuid) -> canonical tenant uuid``. Supplied by the
#: consumer (e.g. its ``resolve_tenant_to_uuid``); this library has no registry.
TenantResolver = Callable[[str], Awaitable[str]]


def accept_authorization_licence() -> bool:
    """Whether ``AUTH_ACCEPT_AUTHORIZATION_LICENCE`` is exactly ``"true"``.

    Read at call time. Anything else — unset, ``"True"``, ``"1"``, ``"yes"``, a
    typo — is False: fail closed to the 0.36 behaviour (``Authorization`` ignored).
    Stricter than :func:`trust_incluster_identity` on purpose: arming this changes
    which credential a service authenticates, so it needs the exact string.
    """
    return os.getenv(ACCEPT_AUTHORIZATION_LICENCE_ENV, "") == "true"


def authorization_bearer(request: Request) -> str | None:
    """The token in ``Authorization: Bearer <token>`` (scheme case-insensitive), else None.

    An empty / whitespace-only token is None. Says nothing about WHAT the token is —
    a licence and a Keycloak JWT look the same here; introspection decides.
    """
    raw = (request.headers.get("Authorization") or "").strip()
    if raw[:7].lower() != "bearer ":
        return None
    return raw[7:].strip() or None


def extract_license_token_with_source(
    request: Request, *, accept_authorization: bool | None = None
) -> tuple[str | None, LicenceSource | None]:
    """The licence and the header that carried it, or ``(None, None)``.

    ``X-Tenant-Id: Bearer <token>`` keeps precedence (exactly
    :func:`extract_license_token`). Only when it carries none, and only when
    ``accept_authorization`` is true, is ``Authorization: Bearer <token>`` read.
    ``accept_authorization=None`` defers to :func:`accept_authorization_licence`
    (env, default off) — so with no argument and no env this returns precisely
    what 0.36 did, with ``"x_tenant_id"`` attached.

    A token returned with source ``"authorization"`` MUST be introspected and an
    inactive result rendered 401 — never retried as the caller's own auth and
    never downgraded to the trusted-network path (George 2026-10-14). Then pass
    the source to :func:`bind_plain_tenant` so the gateway's plain
    ``X-Tenant-Id`` is bound to the licence tenant rather than ignored.
    """
    token = extract_license_token(request)
    if token is not None:
        return token, LICENCE_SOURCE_X_TENANT_ID
    if accept_authorization is None:
        accept_authorization = accept_authorization_licence()
    if not accept_authorization:
        return None, None
    token = authorization_bearer(request)
    if token is None:
        return None, None
    return token, LICENCE_SOURCE_AUTHORIZATION


def plain_tenant_header(request: Request) -> str:
    """A non-Bearer ``X-Tenant-Id`` value (stripped), or ``""``.

    Only the auth scheme itself (``"Bearer"`` / ``"Bearer <tok>"``, any case) is
    not a tenant. A tenant NAME that merely starts with "bearer" (``"bearerco"``)
    is a tenant claim.
    """
    raw = (request.headers.get("X-Tenant-Id") or "").strip()
    low = raw.lower()
    return "" if low == "bearer" or low.startswith("bearer ") else raw


class LicenceTenantMismatch(Exception):  # noqa: N818 — name mirrors RM; services catch it by name
    """A tenant header names a tenant the presented licence does not belong to.

    Services render this as **403** (the caller IS authenticated; it asked for a
    tenant it may not act for). Never 401, never a silent downgrade to the
    licence's own tenant.
    """


def _same_tenant_text(a: str, b: str) -> bool:
    """Textual tenant equality: stripped, case-insensitive (uuids spell both ways)."""
    return a.strip().lower() == b.strip().lower()


async def require_own_tenant(
    credential_tenant: str,
    claimed: Collection[str],
    *,
    resolve: TenantResolver | None = None,
) -> None:
    """Raise :class:`LicenceTenantMismatch` unless every non-empty claim IS the licence tenant.

    Textual match first (no network). Otherwise, with a ``resolve`` callable, both
    sides are resolved and compared as uuids; resolver exceptions propagate (the
    consumer maps them to 400/502/503 as it already does). With NO resolver a
    textual mismatch is a mismatch — fail closed, never "probably the same".
    """
    pending = [
        c for c in claimed if c and c.strip() and not _same_tenant_text(c, credential_tenant)
    ]
    if not pending:
        return
    if resolve is None:
        logger.warning("auth.licence_tenant_mismatch (no resolver)")
        raise LicenceTenantMismatch(
            f"Tenant '{pending[0]}' does not match the tenant of the presented licence"
        )
    own = await resolve(credential_tenant)
    for claim in pending:
        if not _same_tenant_text(await resolve(claim), own):
            logger.warning("auth.licence_tenant_mismatch")
            raise LicenceTenantMismatch(
                f"Tenant '{claim}' does not match the tenant of the presented licence"
            )


async def bind_licence_tenant_claims(
    *,
    credential_tenant: str,
    subject_id: str | None,
    source: LicenceSource | None,
    plain_tenant: str,
    effective_tenant: str,
    resolve: TenantResolver | None = None,
) -> str:
    """Bind the tenant HEADERS of a licence-authenticated request to the licence.

    Pure (no request object); :func:`bind_plain_tenant` is the request wrapper.
    Call it after a successful (``active``) introspection. Returns the tenant the
    caller REQUESTS to act as (``""`` = none) — pass it to
    :func:`apply_effective_tenant` as ``requested=``, which keeps the existing
    delegation rules (allowlist on the introspected subject) authoritative.

    * ``plain_tenant`` counts only when ``source == "authorization"`` (with the
      licence in ``X-Tenant-Id`` there is no plain header to speak of).
    * NON-delegating subject: every non-empty claim — that plain header, and
      ``effective_tenant`` (``X-Effective-Tenant-Id``) for ANY source — must be
      the licence's own tenant (:func:`require_own_tenant`) or
      :class:`LicenceTenantMismatch` is raised. A same-tenant value (the
      gateway's injected uuid; the S2S hook's stamped effective header) passes.
    * DELEGATING subject (introspected subject in :func:`delegating_subjects`):
      the plain header stands in for ``X-Effective-Tenant-Id``; an explicit
      ``X-Effective-Tenant-Id`` wins. A plain header textually equal to the
      licence tenant is not a delegation claim.
    """
    plain = plain_tenant.strip() if source == LICENCE_SOURCE_AUTHORIZATION else ""
    eff = effective_tenant.strip()
    delegating = bool(subject_id) and str(subject_id) in delegating_subjects()
    if not delegating:
        await require_own_tenant(credential_tenant, [plain, eff], resolve=resolve)
        return eff
    if plain and _same_tenant_text(plain, credential_tenant):
        plain = ""
    return eff or plain


async def bind_plain_tenant(
    request: Request,
    *,
    credential_tenant: str,
    subject_id: str | None,
    source: LicenceSource | None,
    resolve: TenantResolver | None = None,
) -> str:
    """:func:`bind_licence_tenant_claims` reading the two headers off ``request``."""
    return await bind_licence_tenant_claims(
        credential_tenant=credential_tenant,
        subject_id=subject_id,
        source=source,
        plain_tenant=plain_tenant_header(request),
        effective_tenant=request.headers.get(EFFECTIVE_TENANT_HEADER) or "",
        resolve=resolve,
    )


# --------------------------------------------------------------------------- #
# Pooled introspect client — one process-scoped AsyncClient, built lazily so it
# binds to the running event loop. Close it from each service's lifespan
# shutdown via close_license_introspect_client().
# --------------------------------------------------------------------------- #
_LICENSE_LIMITS = httpx.Limits(
    max_keepalive_connections=10,
    max_connections=20,
    keepalive_expiry=30.0,
)
_license_client: httpx.AsyncClient | None = None


def _license_timeout() -> httpx.Timeout:
    """Build the introspect timeout. Read/write budget defaults to 10s and is
    tunable via ``LICENSE_INTROSPECT_TIMEOUT`` (connect/pool stay tight at 1s).

    The old hardcoded 2s wall-clock was the cold-box trap: on a CPU-saturated
    host the event loop can starve long enough that a tighter budget fires
    before the licenses endpoint replies, surfacing as a spurious 401. Resolved
    at client-build time so an env override applies after a reconnect.
    """
    budget = float(os.getenv("LICENSE_INTROSPECT_TIMEOUT", "10.0"))
    return httpx.Timeout(budget, connect=1.0, read=budget, write=budget, pool=1.0)


def get_license_http_client() -> httpx.AsyncClient:
    """Return the process-wide pooled ``httpx.AsyncClient`` for introspection."""
    global _license_client
    if _license_client is None or _license_client.is_closed:
        _license_client = httpx.AsyncClient(timeout=_license_timeout(), limits=_LICENSE_LIMITS)
    return _license_client


async def close_license_introspect_client() -> None:
    """Close the shared introspection client (call from lifespan shutdown)."""
    global _license_client
    if _license_client is not None and not _license_client.is_closed:
        await _license_client.aclose()
    _license_client = None


# --------------------------------------------------------------------------- #
# Introspection cache + call. One shared positive TTLCache so a service's
# middleware and its tenant-dependency path share cached results (keyed by
# SHA-256 prefix), plus a short-TTL negative cache for ``active: false`` so a
# revoked token can't pin every request against the licenses endpoint.
# --------------------------------------------------------------------------- #
_license_cache: TTLCache[str, dict[str, Any]] = TTLCache(maxsize=1000, ttl=300)
_license_neg_cache: TTLCache[str, dict[str, Any]] = TTLCache(
    maxsize=1000,
    ttl=int(os.getenv("LICENSE_INTROSPECT_NEG_TTL", "60")),
)

# Per-token single-flight locks. A cold-cache burst of concurrent requests for
# the SAME token (e.g. a narration render firing many synth calls at once) would
# otherwise each miss the cache and independently POST the licenses endpoint. On
# a CPU-saturated box that stampede starves the event loop and trips the
# introspection timeout → spurious 401 (the 2026-06-27 TTS bug class). The lock
# collapses the burst into one upstream call; the rest read the cache.
#
# BOUNDED — this MUST NOT be a plain dict. The key is ``sha256(token)[:16]``, i.e.
# per distinct BEARER TOKEN and *not* per tenant, and introspection is reached
# PRE-AUTH: each service's middleware hands us the caller's raw header before
# anything about it has been validated. A caller sending a fresh random token per
# request therefore grew the map without bound — ~183 bytes/entry, so ~16 MiB/day
# sustained at a 60/min ingress rate limit and minutes-to-OOM from an unrate-limited
# in-cluster peer, in every service that imports this module. The comment that used
# to sit here claimed the map was "bounded in practice by the small number of
# distinct tenant tokens"; that is the per-TENANT mental model and it was WRONG.
#
# LRU rather than TTL is deliberate: the entry single-flight actually needs is the
# HOT token's lock, and least-recently-used is precisely the policy that keeps it.
#
# Evicting a lock that a coroutine is currently HOLDING is safe. The holder owns a
# strong reference on its own stack, so the object outlives its map slot and the
# ``async with`` still releases it normally — eviction can neither deadlock nor
# strand a waiter, and the lock is collected once the last waiter drops it. The
# only consequence is that a *subsequent* caller for the same token misses the map,
# creates a FRESH lock and proceeds concurrently: one duplicate upstream POST, which
# is exactly the pre-lock behaviour this optimisation improves on. That is tolerable
# because the lock guards no invariant — ``_introspect_uncached`` only assigns whole
# values into two TTLCaches (no read-modify-write), and two concurrent introspections
# of the same token write equivalent payloads. Correctness is independent of the
# lock; only the stampede saving degrades. In practice an in-flight lock was
# necessarily touched at acquisition, so it sits at the MRU end and is never the
# victim unless more than ``_INTROSPECT_LOCKS_MAXSIZE`` distinct tokens are in
# flight at the same instant.
_INTROSPECT_LOCKS_MAXSIZE = 1000
_introspect_locks: LRUCache[str, asyncio.Lock] = LRUCache(maxsize=_INTROSPECT_LOCKS_MAXSIZE)


def clear_license_cache() -> None:
    """Drop all cached introspection results, positive and negative (test helper).

    Also drops the single-flight lock map, so a test that drives many distinct
    tokens cannot leak locks into the next test's assertions. Safe to call on a
    live process for the same reason LRU eviction is (see the lock-map comment
    above): a lock dropped while held stays alive via its holder, and the worst
    case is a single duplicate upstream introspection.
    """
    _license_cache.clear()
    _license_neg_cache.clear()
    _introspect_locks.clear()


def _resolve_introspect_url(url: str | None) -> str:
    """Resolve the introspect endpoint each call so env/test overrides win."""
    if url is not None:
        return url
    return os.getenv("LICENSE_INTROSPECT_URL", "")


def _cached(cache_key: str) -> dict[str, Any] | None:
    """Return a positive- or negative-cache hit for ``cache_key`` (or ``None``)."""
    hit = _license_cache.get(cache_key)
    if hit is not None:
        return hit
    return _license_neg_cache.get(cache_key)


async def introspect_license(token: str, *, url: str | None = None) -> dict[str, Any] | None:
    """Validate ``token`` against the licenses service.

    ``url`` defaults to the ``LICENSE_INTROSPECT_URL`` env var, resolved per call.
    Returns the introspection payload (or ``None`` on any failure / empty URL).
    ``active`` payloads are cached 5 min; ``active: false`` payloads are cached
    briefly in the negative cache (``LICENSE_INTROSPECT_NEG_TTL``, default 60s)
    so re-issuance is still picked up quickly. A cold-cache burst for the same
    token is collapsed into a single upstream POST via a per-token lock.
    """
    cache_key = hashlib.sha256(token.encode()).hexdigest()[:16]
    hit = _cached(cache_key)
    if hit is not None:
        return hit

    resolved = _resolve_introspect_url(url)
    if not resolved:
        logger.warning("LICENSE_INTROSPECT_URL not configured; rejecting bearer token")
        return None

    # Cache miss: single-flight so a concurrent burst for the same cold token
    # collapses into ONE upstream introspection. Re-check the caches inside the
    # lock — a prior waiter may have populated them while we were blocked.
    # ``setdefault`` on the LRU is a hit-then-insert: a hit refreshes recency (so
    # a token under active burst is never the eviction victim) and an insert may
    # evict the least-recently-used lock, which is safe — see the map's comment.
    lock = _introspect_locks.setdefault(cache_key, asyncio.Lock())
    async with lock:
        hit = _cached(cache_key)
        if hit is not None:
            return hit
        return await _introspect_uncached(token, resolved, cache_key)


async def _introspect_uncached(token: str, resolved: str, cache_key: str) -> dict[str, Any] | None:
    """Perform the introspection POST and populate the caches.

    Always called under the per-token single-flight lock held by
    :func:`introspect_license`.
    """
    try:
        client = get_license_http_client()
        resp = await client.post(resolved, json={"token": token})
    except (httpx.HTTPError, OSError) as e:
        logger.warning("license_introspect_failed", extra={"error": str(e)})
        return None

    if resp.status_code != 200:
        return None
    try:
        data: dict[str, Any] = resp.json()
    except ValueError:
        return None
    if data.get("active"):
        _license_cache[cache_key] = data
    else:
        _license_neg_cache[cache_key] = data
    return data


# --------------------------------------------------------------------------- #
# Error envelope (byte-identical across all four services).
# --------------------------------------------------------------------------- #
def error_payload(code: str, message: str, http_status: int) -> dict[str, Any]:
    """The shared ``{"error": {...}}`` envelope used across the KAG backends."""
    return {
        "error": {
            "code": code,
            "message": message,
            "status": http_status,
        }
    }


def unauthorized_response(message: str) -> JSONResponse:
    """401 JSONResponse with the shared envelope + ``WWW-Authenticate: Bearer``."""
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content=error_payload("AUTHENTICATION_REQUIRED", message, 401),
        headers={"WWW-Authenticate": "Bearer"},
    )
