"""Tests for the shared license-introspection + auth helpers."""

from __future__ import annotations

import asyncio
import hashlib

import httpx
import pytest
from starlette.requests import Request

from kag_common import auth


@pytest.fixture(autouse=True)
async def _reset_auth_state():
    """Each test starts with an empty cache and no installed client."""
    auth.clear_license_cache()
    await auth.close_license_introspect_client()
    yield
    auth.clear_license_cache()
    await auth.close_license_introspect_client()


def _install_mock(handler) -> list[httpx.Request]:
    """Route the shared introspect client through a MockTransport; return the
    captured request log so tests can assert call count + target URL."""
    seen: list[httpx.Request] = []

    def _wrapped(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    auth._license_client = httpx.AsyncClient(transport=httpx.MockTransport(_wrapped))
    return seen


def _make_request(headers: dict[str, str]) -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "headers": raw})


# --------------------------------------------------------------------------- #
# is_trusted_network
# --------------------------------------------------------------------------- #
# NB the shipped default TRUSTED_CIDRS is UNCHANGED by 0.20.0 — it still carries
# the full RFC1918 set, so these rows keep their pre-0.20.0 expectations. That
# list is deliberately wide (the hostNetwork API gateway SNATs to 10.42.0.0 and
# lands here by design); narrowing it is a separate, gateway-sequenced change.
# What 0.20.0 adds is a SEPARATE gate for using this predicate as an IDENTITY —
# see the is_trusted_identity_source block below.
@pytest.mark.parametrize(
    ("host", "expected"),
    [
        (None, False),
        ("", False),
        # 0.20.0 removed the `host == "testclient"` short-circuit: a hardcoded,
        # never-CIDR-checked, never-flag-gated True for a peer NAME. Not
        # prod-reachable, but a bypass shipped in every consumer image.
        ("testclient", False),
        ("127.0.0.1", True),
        ("::1", True),
        ("10.1.2.3", True),
        # k3s pod CIDR: inside the default 10.0.0.0/8, hence a "trusted network"
        # — which is exactly why naming a tenant needs its own opt-in gate.
        ("10.42.7.31", True),
        ("192.168.4.4", True),
        ("172.16.5.5", True),
        ("8.8.8.8", False),
        ("not-an-ip", False),
    ],
)
def test_is_trusted_network(host, expected):
    assert auth.is_trusted_network(host) is expected


# --------------------------------------------------------------------------- #
# Opt-in in-cluster identity trust (CVE-class: tokenless cross-tenant forgery)
#
# The trusted-network CONCEPT is untouched (health/metrics allowlisting still
# uses it, and the shipped default CIDRs are unchanged). What 0.20.0 ADDS is a
# separate predicate a consumer can move onto before it treats a bare
# X-Tenant-Id from such a peer AS A CREDENTIAL. It is inert until a consumer
# does; `_consumer_trusted_network_branch` below is that future consumer.
# --------------------------------------------------------------------------- #
POD_CIDR_PEER = "10.42.7.31"
VICTIM_TENANT = "00000000-0000-0000-0000-victim000001"
SHIPPED_DEFAULT_CIDRS = "127.0.0.1/32,::1/128,192.168.0.0/16,172.16.0.0/12,10.0.0.0/8"


def _consumer_trusted_network_branch(
    client_host: str | None, headers: dict[str, str]
) -> str | None:
    """Faithful replica of the CONSUMER bypass this library's predicate feeds.

    Mirrors ``kag_orchestrator/src/auth/middleware.py:147-153`` and
    ``ingestion_service/src/auth/middleware.py:215-222``: with no license token,
    a peer inside the trusted network may name its own tenant in a bare
    ``X-Tenant-Id``, which is then bound to ``app.current_tenant`` for RLS.

    Returns the tenant the consumer would bind, or ``None`` when the request
    must fall through to normal token authentication (and thus fail closed).
    """
    if auth.is_trusted_identity_source(client_host):
        raw_tenant = headers.get("X-Tenant-Id", "").strip()
        if raw_tenant.lower().startswith("bearer "):
            raw_tenant = ""
        return raw_tenant or None
    return None


def test_testclient_name_is_not_a_trusted_network():
    """0.20.0 removes the hardcoded `host == "testclient"` bypass.

    This is the one behaviour this release actually CHANGES, and it is the one
    assertion here that fails against pristine main for a real reason rather than
    an ``AttributeError`` about a symbol that did not exist yet: the sentinel
    returned True unconditionally — never CIDR-checked, never flag-gated — for
    any peer whose *name* was the literal string ``testclient``.

    A peer name is not a network. Membership must come from an address.
    """
    assert auth.is_trusted_network("testclient") is False
    assert auth.is_trusted_network("TESTCLIENT") is False
    assert auth.is_trusted_network("testclient.example") is False
    # ...while a real loopback peer — what a TestClient should present — still is.
    assert auth.is_trusted_network("127.0.0.1") is True


def test_identity_gate_actually_gates_and_is_not_a_constant(monkeypatch):
    """The flag must be load-bearing in BOTH directions.

    Deliberately structured so a stub cannot satisfy it. ``lambda h: False``
    fails the opted-in assertion; ``is_trusted_identity_source = is_trusted_
    network`` fails the flag-off assertion; ``lambda h: True`` fails the
    off-network assertion. Only a real conjunction of flag AND membership passes.
    """
    # Membership is real and unchanged: the pod CIDR is inside the default 10/8.
    assert auth.is_trusted_network(POD_CIDR_PEER) is True

    monkeypatch.delenv("AUTH_TRUST_INCLUSTER_IDENTITY", raising=False)
    assert auth.is_trusted_identity_source(POD_CIDR_PEER) is False

    monkeypatch.setenv("AUTH_TRUST_INCLUSTER_IDENTITY", "true")
    assert auth.is_trusted_identity_source(POD_CIDR_PEER) is True

    # ...and the flag widens nothing beyond TRUSTED_NETWORKS.
    assert auth.is_trusted_identity_source("8.8.8.8") is False


def test_default_trusted_cidrs_is_unchanged():
    """0.20.0 must NOT move the shipped default — this release is additive only.

    Lifting the literal into ``DEFAULT_TRUSTED_CIDRS`` is a readability refactor,
    not a behaviour change. The list is deliberately wide: the API gateway is
    ``hostNetwork`` and SNATs to ``10.42.0.0``, so every authenticated external
    request arrives from inside ``10.0.0.0/8`` by design. Narrowing it here would
    401 all gateway traffic to consumers that allowlist on it, so that belongs to
    a separate, gateway-sequenced change — not to shipping the opt-in gate.
    """
    assert auth.DEFAULT_TRUSTED_CIDRS == SHIPPED_DEFAULT_CIDRS
    assert auth.parse_trusted_cidrs(auth.DEFAULT_TRUSTED_CIDRS) == auth.parse_trusted_cidrs(
        SHIPPED_DEFAULT_CIDRS
    )


def test_trust_incluster_identity_defaults_false(monkeypatch):
    """Fail-closed by default — mirrors w2v_common 0.6.9."""
    monkeypatch.delenv("AUTH_TRUST_INCLUSTER_IDENTITY", raising=False)
    assert auth.trust_incluster_identity() is False


@pytest.mark.parametrize("raw", ["true", "True", "1", "yes", "on"])
def test_trust_incluster_identity_opt_in(monkeypatch, raw):
    monkeypatch.setenv("AUTH_TRUST_INCLUSTER_IDENTITY", raw)
    assert auth.trust_incluster_identity() is True


@pytest.mark.parametrize("raw", ["false", "0", "no", "off", "", "garbage"])
def test_trust_incluster_identity_non_affirmative_stays_false(monkeypatch, raw):
    """Anything that is not an explicit opt-in must fail closed."""
    monkeypatch.setenv("AUTH_TRUST_INCLUSTER_IDENTITY", raw)
    assert auth.trust_incluster_identity() is False


def test_pod_cidr_peer_cannot_assert_tenant_once_a_consumer_migrates(monkeypatch):
    """What a MIGRATED consumer does — NOT what the shipped consumers do today.

    ``_consumer_trusted_network_branch`` is a stand-in that already calls
    ``is_trusted_identity_source``. The real consumers still call
    ``is_trusted_network`` and are still exploitable; this test pins the contract
    they get once they switch, it does not demonstrate a closed hole.
    """
    monkeypatch.delenv("AUTH_TRUST_INCLUSTER_IDENTITY", raising=False)
    resolved = _consumer_trusted_network_branch(POD_CIDR_PEER, {"X-Tenant-Id": VICTIM_TENANT})
    assert resolved is None


def test_pod_cidr_peer_rejected_even_with_the_wide_cidr_list(monkeypatch):
    """The flag is the load-bearing gate, not the CIDR list.

    The shipped default already allowlists 10.0.0.0/8 (health/metrics probes, and
    the hostNetwork gateway's SNAT source). Membership alone must not amount to
    an identity.
    """
    monkeypatch.delenv("AUTH_TRUST_INCLUSTER_IDENTITY", raising=False)
    monkeypatch.setattr(auth, "TRUSTED_NETWORKS", auth.parse_trusted_cidrs(SHIPPED_DEFAULT_CIDRS))

    assert auth.is_trusted_network(POD_CIDR_PEER) is True  # concept preserved (req 2)
    assert _consumer_trusted_network_branch(POD_CIDR_PEER, {"X-Tenant-Id": VICTIM_TENANT}) is None


def test_incluster_identity_available_when_explicitly_opted_in(monkeypatch):
    """(b) Staged rollout: operators can enable the in-cluster path deliberately.

    Requires BOTH network membership AND an explicit opt-in flag. The flag is not
    the default, so a migrated consumer can never reach this path by accident.
    """
    monkeypatch.setenv("AUTH_TRUST_INCLUSTER_IDENTITY", "true")
    monkeypatch.setattr(auth, "TRUSTED_NETWORKS", auth.parse_trusted_cidrs(SHIPPED_DEFAULT_CIDRS))

    resolved = _consumer_trusted_network_branch(POD_CIDR_PEER, {"X-Tenant-Id": VICTIM_TENANT})
    assert resolved == VICTIM_TENANT


def test_opt_in_still_refuses_a_bearer_shaped_tenant_header(monkeypatch):
    """Even opted in, a `Bearer ...` value is a failed token, not a tenant name."""
    monkeypatch.setenv("AUTH_TRUST_INCLUSTER_IDENTITY", "true")
    monkeypatch.setattr(auth, "TRUSTED_NETWORKS", auth.parse_trusted_cidrs(SHIPPED_DEFAULT_CIDRS))

    resolved = _consumer_trusted_network_branch(
        POD_CIDR_PEER, {"X-Tenant-Id": "Bearer not-a-real-token"}
    )
    assert resolved is None


def test_untrusted_peer_never_asserts_identity_even_when_opted_in(monkeypatch):
    """The flag widens nothing beyond TRUSTED_NETWORKS."""
    monkeypatch.setenv("AUTH_TRUST_INCLUSTER_IDENTITY", "true")
    assert auth.is_trusted_identity_source("8.8.8.8") is False
    assert _consumer_trusted_network_branch("8.8.8.8", {"X-Tenant-Id": VICTIM_TENANT}) is None


def test_configured_trusted_cidrs_are_honoured():
    """(req 2) The trusted-network concept itself is untouched and still usable."""
    nets = auth.parse_trusted_cidrs(SHIPPED_DEFAULT_CIDRS)
    assert len(nets) == 5
    assert auth.parse_trusted_cidrs("") == []
    assert auth.parse_trusted_cidrs(" 10.0.0.0/8 , 127.0.0.1/32 ") == auth.parse_trusted_cidrs(
        "10.0.0.0/8,127.0.0.1/32"
    )


# --------------------------------------------------------------------------- #
# path predicates
# --------------------------------------------------------------------------- #
def test_is_public_path():
    public = {"/", "/health", "/openapi.json"}
    assert auth.is_public_path("/health", public) is True
    assert auth.is_public_path("/health/ready", public) is True  # /health prefix
    assert auth.is_public_path("/docs", public) is True  # implicit doc prefix
    assert auth.is_public_path("/openapi.json", public) is True
    assert auth.is_public_path("/", public) is True
    assert auth.is_public_path("/api/karma/run", public) is False


def test_is_public_path_trailing_slash_normalized():
    assert auth.is_public_path("/openapi.json/", {"/openapi.json"}) is True


def test_is_public_path_anchors_to_segment_boundary():
    """An unanchored prefix match is an auth-bypass class: any route merely
    STARTING with a public prefix would be exempted. Anchor to a segment."""
    public = {"/", "/health"}
    # Real public trees stay public.
    assert auth.is_public_path("/health/ready", public) is True
    assert auth.is_public_path("/docs/oauth2-redirect", public) is True
    assert auth.is_public_path("/static/logo.svg", public) is True
    # Look-alikes that merely share a prefix must NOT be exempted.
    for bypass in (
        "/healthcheck-admin",
        "/health-secrets/dump",
        "/staticfiles/../etc/passwd",
        "/docsecret",
        "/redocs-internal",
    ):
        assert auth.is_public_path(bypass, public) is False, bypass


def test_is_public_path_keeps_healthz_public():
    """Every KAG-family service serves /healthz without listing it in its own
    PUBLIC_ENDPOINTS — it was public only via "/healthz".startswith("/health").
    Segment anchoring must not auth-wall a liveness probe."""
    assert auth.is_public_path("/healthz", set()) is True


def test_is_public_path_does_not_widen_to_other_probe_aliases():
    """/readyz and /livez never matched the old prefix rule either; a bypass fix
    must not quietly widen the exemption it exists to narrow."""
    assert auth.is_public_path("/readyz", set()) is False
    assert auth.is_public_path("/livez", set()) is False


def test_is_protected_path():
    prefixes = {"/api/karma"}
    assert auth.is_protected_path("/api/karma", prefixes) is True
    assert auth.is_protected_path("/api/karma/run", prefixes) is True
    assert auth.is_protected_path("/api/other", prefixes) is False
    assert auth.is_protected_path("/", prefixes) is False


# --------------------------------------------------------------------------- #
# extract_license_token
# --------------------------------------------------------------------------- #
def test_extract_license_token_bearer():
    assert auth.extract_license_token(_make_request({"X-Tenant-Id": "Bearer abc"})) == "abc"


def test_extract_license_token_case_insensitive():
    assert auth.extract_license_token(_make_request({"X-Tenant-Id": "bearer xyz"})) == "xyz"


def test_extract_license_token_absent():
    assert auth.extract_license_token(_make_request({})) is None


def test_extract_license_token_raw_value_is_not_a_token():
    # A raw tenant id (no "Bearer " prefix) is not a license token.
    assert auth.extract_license_token(_make_request({"X-Tenant-Id": "tenant-123"})) is None


def test_extract_license_token_empty_bearer():
    assert auth.extract_license_token(_make_request({"X-Tenant-Id": "Bearer "})) is None


# --------------------------------------------------------------------------- #
# error envelope
# --------------------------------------------------------------------------- #
def test_error_payload_shape():
    assert auth.error_payload("X", "msg", 418) == {
        "error": {"code": "X", "message": "msg", "status": 418}
    }


def test_unauthorized_response():
    resp = auth.unauthorized_response("nope")
    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"] == "Bearer"
    assert b"AUTHENTICATION_REQUIRED" in resp.body


# --------------------------------------------------------------------------- #
# pooled client lifecycle
# --------------------------------------------------------------------------- #
def test_get_client_is_singleton():
    c1 = auth.get_license_http_client()
    c2 = auth.get_license_http_client()
    assert c1 is c2


async def test_close_then_rebuild():
    c1 = auth.get_license_http_client()
    await auth.close_license_introspect_client()
    assert c1.is_closed
    c2 = auth.get_license_http_client()
    assert c2 is not c1
    assert not c2.is_closed


async def test_close_is_idempotent():
    auth.get_license_http_client()
    await auth.close_license_introspect_client()
    await auth.close_license_introspect_client()  # no error on second close


async def test_introspect_timeout_default_is_10s(monkeypatch):
    monkeypatch.delenv("LICENSE_INTROSPECT_TIMEOUT", raising=False)
    await auth.close_license_introspect_client()
    client = auth.get_license_http_client()
    # default read/write budget is 10s (was a 2s cold-box trap); connect stays tight
    assert client.timeout.read == 10.0
    assert client.timeout.connect == 1.0


async def test_introspect_timeout_env_tunable(monkeypatch):
    monkeypatch.setenv("LICENSE_INTROSPECT_TIMEOUT", "3.5")
    await auth.close_license_introspect_client()
    client = auth.get_license_http_client()
    assert client.timeout.read == 3.5
    assert client.timeout.write == 3.5


# --------------------------------------------------------------------------- #
# introspect_license
# --------------------------------------------------------------------------- #
async def test_introspect_empty_url_returns_none(monkeypatch):
    monkeypatch.delenv("LICENSE_INTROSPECT_URL", raising=False)
    assert await auth.introspect_license("tok") is None


async def test_introspect_active_caches(monkeypatch):
    monkeypatch.setenv("LICENSE_INTROSPECT_URL", "http://lic/introspect")
    seen = _install_mock(lambda req: httpx.Response(200, json={"active": True, "tenant_id": "t1"}))

    first = await auth.introspect_license("tok")
    second = await auth.introspect_license("tok")

    assert first == {"active": True, "tenant_id": "t1"}
    assert second == first
    assert len(seen) == 1  # second call served from cache
    assert str(seen[0].url) == "http://lic/introspect"


async def test_introspect_inactive_negative_cached(monkeypatch):
    monkeypatch.setenv("LICENSE_INTROSPECT_URL", "http://lic/introspect")
    seen = _install_mock(lambda req: httpx.Response(200, json={"active": False}))

    first = await auth.introspect_license("tok")
    second = await auth.introspect_license("tok")

    assert first == {"active": False}
    assert second == first
    # active:false is held in the short-TTL negative cache, so the second call
    # within the TTL is served from cache and does NOT re-hit the endpoint.
    assert len(seen) == 1


async def test_introspect_single_flight_cold_burst(monkeypatch):
    """A cold-cache burst of concurrent calls for the same token collapses into
    exactly ONE upstream POST (the 2026-06-27 stampede regression guard)."""
    monkeypatch.setenv("LICENSE_INTROSPECT_URL", "http://lic/introspect")
    seen = _install_mock(lambda req: httpx.Response(200, json={"active": True, "tenant_id": "t1"}))

    results = await asyncio.gather(*[auth.introspect_license("tok") for _ in range(12)])

    assert all(r == {"active": True, "tenant_id": "t1"} for r in results)
    assert len(seen) == 1  # 12-way burst → single introspection


async def test_introspect_single_flight_distinct_tokens(monkeypatch):
    """Distinct tokens are NOT serialized behind one lock — each introspects once."""
    monkeypatch.setenv("LICENSE_INTROSPECT_URL", "http://lic/introspect")
    seen = _install_mock(lambda req: httpx.Response(200, json={"active": True}))

    await asyncio.gather(*[auth.introspect_license(f"tok-{i}") for i in range(5)])

    assert len(seen) == 5  # one POST per distinct token


async def test_introspect_non_200_returns_none(monkeypatch):
    monkeypatch.setenv("LICENSE_INTROSPECT_URL", "http://lic/introspect")
    _install_mock(lambda req: httpx.Response(503))
    assert await auth.introspect_license("tok") is None


async def test_introspect_invalid_json_returns_none(monkeypatch):
    monkeypatch.setenv("LICENSE_INTROSPECT_URL", "http://lic/introspect")
    _install_mock(lambda req: httpx.Response(200, content=b"not-json"))
    assert await auth.introspect_license("tok") is None


async def test_introspect_transport_error_returns_none(monkeypatch):
    monkeypatch.setenv("LICENSE_INTROSPECT_URL", "http://lic/introspect")

    def _boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    _install_mock(_boom)
    assert await auth.introspect_license("tok") is None


async def test_introspect_explicit_url_overrides_env(monkeypatch):
    monkeypatch.setenv("LICENSE_INTROSPECT_URL", "http://env/introspect")
    seen = _install_mock(lambda req: httpx.Response(200, json={"active": True}))

    await auth.introspect_license("tok", url="http://override/introspect")

    assert str(seen[0].url) == "http://override/introspect"


async def test_clear_license_cache(monkeypatch):
    monkeypatch.setenv("LICENSE_INTROSPECT_URL", "http://lic/introspect")
    seen = _install_mock(lambda req: httpx.Response(200, json={"active": True}))

    await auth.introspect_license("tok")
    auth.clear_license_cache()
    await auth.introspect_license("tok")

    assert len(seen) == 2  # cache cleared between calls forces a re-check


# --------------------------------------------------------------------------- #
# Single-flight lock map is BOUNDED (pre-auth memory-exhaustion guard)
# --------------------------------------------------------------------------- #
async def test_introspect_lock_map_is_bounded(monkeypatch):
    """Driving many DISTINCT bearer tokens must not grow the lock map without bound.

    The map is keyed by ``sha256(token)[:16]`` — per distinct TOKEN, not per tenant
    — and is populated PRE-AUTH from the caller's raw ``X-Tenant-Id`` header, so an
    unbounded map is an attacker-driven memory leak (~183 bytes/entry) in every
    service that imports this module. Against the pre-fix plain ``dict`` this
    assertion fails with 5000 entries.
    """
    monkeypatch.setenv("LICENSE_INTROSPECT_URL", "http://lic/introspect")
    seen = _install_mock(lambda req: httpx.Response(200, json={"active": True}))

    n_tokens = 5000
    for i in range(n_tokens):
        await auth.introspect_license(f"attacker-token-{i}")

    # Non-vacuity: every distinct token really did traverse the introspect path
    # (a short-circuit anywhere upstream would satisfy the bound trivially).
    assert len(seen) == n_tokens
    assert len(auth._introspect_locks) > 0

    observed = len(auth._introspect_locks)
    # Stated without reference to the cap, so this reads as a real regression on a
    # reintroduced plain dict rather than an AttributeError on a missing constant.
    assert observed < n_tokens, (
        f"single-flight lock map is unbounded: {observed} entries after {n_tokens} distinct tokens"
    )
    assert observed <= auth._INTROSPECT_LOCKS_MAXSIZE, (
        f"single-flight lock map grew to {observed} entries "
        f"(cap {auth._INTROSPECT_LOCKS_MAXSIZE}) after {n_tokens} distinct tokens"
    )


async def test_clear_license_cache_drops_the_lock_map(monkeypatch):
    """``clear_license_cache`` also drops the lock map, so a test driving many
    distinct tokens cannot leak locks into the next test's assertions."""
    monkeypatch.setenv("LICENSE_INTROSPECT_URL", "http://lic/introspect")
    _install_mock(lambda req: httpx.Response(200, json={"active": True}))

    for i in range(5):
        await auth.introspect_license(f"tok-{i}")
    assert len(auth._introspect_locks) == 5

    auth.clear_license_cache()

    assert len(auth._introspect_locks) == 0


async def test_single_flight_holds_while_the_lock_map_is_full(monkeypatch):
    """Bounding must not cost single-flight: with the map already at capacity, a
    concurrent burst for one cold token still collapses into ONE upstream POST.

    The burst token is inserted (evicting the least-recently-used entry) and then
    re-read by every other waiter, which keeps it at the MRU end for the whole
    burst — so it can never be the eviction victim while it is in flight.
    """
    monkeypatch.setenv("LICENSE_INTROSPECT_URL", "http://lic/introspect")
    seen = _install_mock(lambda req: httpx.Response(200, json={"active": True}))

    for i in range(auth._INTROSPECT_LOCKS_MAXSIZE):
        await auth.introspect_license(f"filler-{i}")
    assert len(auth._introspect_locks) == auth._INTROSPECT_LOCKS_MAXSIZE
    before = len(seen)

    results = await asyncio.gather(*[auth.introspect_license("hot") for _ in range(12)])

    assert all(r == {"active": True} for r in results)
    assert len(seen) - before == 1  # 12-way burst on a FULL map → single introspection


async def test_lock_evicted_while_held_neither_deadlocks_nor_strands_the_holder(
    monkeypatch,
):
    """Evicting a lock a coroutine is CURRENTLY holding is safe.

    The holder keeps a strong reference on its own stack, so the lock object
    outlives its map slot and ``async with`` still releases it normally — eviction
    can neither deadlock the holder nor strand a waiter. The one permitted
    consequence is that a later caller for the same token misses the map, builds a
    FRESH lock and proceeds concurrently: exactly ONE duplicate upstream
    introspection, which is the pre-lock behaviour this optimisation improves on.
    That is acceptable because the lock guards no invariant — the introspect path
    only assigns whole values into the TTLCaches, with no read-modify-write.
    """
    monkeypatch.setenv("LICENSE_INTROSPECT_URL", "http://lic/introspect")
    _install_mock(lambda req: httpx.Response(200, json={"active": True}))

    released = asyncio.Event()
    calls: list[str] = []

    async def _fake_uncached(token: str, resolved: str, cache_key: str):
        calls.append(token)
        if token == "hot-token":
            await released.wait()  # hold the lock across an await point
        return {"active": True, "tenant_id": token}

    monkeypatch.setattr(auth, "_introspect_uncached", _fake_uncached)

    hot_key = hashlib.sha256(b"hot-token").hexdigest()[:16]
    holder = asyncio.create_task(auth.introspect_license("hot-token"))
    while hot_key not in auth._introspect_locks:
        await asyncio.sleep(0)
    assert auth._introspect_locks[hot_key].locked()  # genuinely held, not just present
    held_lock = auth._introspect_locks[hot_key]

    # Flood past capacity so the HELD lock becomes least-recently-used and is evicted.
    for i in range(auth._INTROSPECT_LOCKS_MAXSIZE + 10):
        await auth.introspect_license(f"flood-{i}")
    assert hot_key not in auth._introspect_locks  # evicted mid-flight
    assert held_lock.locked()  # the holder still owns the object

    # A second caller for the same token now builds a fresh lock and proceeds.
    latecomer = asyncio.create_task(auth.introspect_license("hot-token"))
    while hot_key not in auth._introspect_locks:
        await asyncio.sleep(0)
    assert auth._introspect_locks[hot_key] is not held_lock

    released.set()
    first, second = await asyncio.wait_for(asyncio.gather(holder, latecomer), timeout=5)

    assert first == {"active": True, "tenant_id": "hot-token"}
    assert second == first
    # The documented, tolerated cost of evicting a held lock: one duplicate call.
    assert calls.count("hot-token") == 2
    assert not held_lock.locked()  # released normally despite being evicted


# --------------------------------------------------------------------------- #
# Effective-tenant delegation (WS-4 receiver side)
# --------------------------------------------------------------------------- #
def test_delegating_subjects_empty_by_default(monkeypatch):
    monkeypatch.delenv("AUTH_DELEGATING_SUBJECTS", raising=False)
    assert auth.delegating_subjects() == frozenset()


def test_delegating_subjects_parses_csv(monkeypatch):
    monkeypatch.setenv("AUTH_DELEGATING_SUBJECTS", " sa-worker , sa-kag ,")
    assert auth.delegating_subjects() == frozenset({"sa-worker", "sa-kag"})


def test_effective_tenant_rescopes_for_delegating_subject(monkeypatch):
    monkeypatch.setenv("AUTH_DELEGATING_SUBJECTS", "sa-worker")
    req = _make_request(
        {
            "X-Effective-Tenant-Id": "real-tenant",
            "X-Subject-Id": "run-user",
            "X-License-Id": "run-lic",
        }
    )
    tenant, subject, license_id = auth.apply_effective_tenant(
        req, "sa-worker", "sa-tenant", "sa-subject", "sa-lic"
    )
    assert tenant == "real-tenant"
    # forwarded run subject/license win over the SA's own
    assert subject == "run-user"
    assert license_id == "run-lic"


def test_effective_tenant_ignored_for_non_delegating_subject(monkeypatch):
    monkeypatch.setenv("AUTH_DELEGATING_SUBJECTS", "sa-worker")
    req = _make_request({"X-Effective-Tenant-Id": "victim-tenant"})
    # A customer subject is never a delegator — the header is a no-op (spoof-safe).
    tenant, subject, license_id = auth.apply_effective_tenant(
        req, "customer-subject", "customer-tenant", "customer-subject", "cust-lic"
    )
    assert tenant == "customer-tenant"
    assert subject == "customer-subject"
    assert license_id == "cust-lic"


def test_effective_tenant_disabled_when_config_empty(monkeypatch):
    monkeypatch.delenv("AUTH_DELEGATING_SUBJECTS", raising=False)
    req = _make_request({"X-Effective-Tenant-Id": "other-tenant"})
    tenant, _subject, _lic = auth.apply_effective_tenant(
        req, "sa-worker", "sa-tenant", "sa-subject", "sa-lic"
    )
    assert tenant == "sa-tenant"


def test_effective_tenant_noop_when_header_absent(monkeypatch):
    monkeypatch.setenv("AUTH_DELEGATING_SUBJECTS", "sa-worker")
    req = _make_request({})
    tenant, subject, license_id = auth.apply_effective_tenant(
        req, "sa-worker", "sa-tenant", "sa-subject", "sa-lic"
    )
    assert (tenant, subject, license_id) == ("sa-tenant", "sa-subject", "sa-lic")


def test_effective_tenant_noop_when_equal(monkeypatch):
    monkeypatch.setenv("AUTH_DELEGATING_SUBJECTS", "sa-worker")
    req = _make_request({"X-Effective-Tenant-Id": "sa-tenant"})
    tenant, subject, license_id = auth.apply_effective_tenant(
        req, "sa-worker", "sa-tenant", "sa-subject", "sa-lic"
    )
    # Equal effective tenant → keep the SA's own subject/license (no forward).
    assert (tenant, subject, license_id) == ("sa-tenant", "sa-subject", "sa-lic")


def test_effective_tenant_missing_subject_is_noop(monkeypatch):
    monkeypatch.setenv("AUTH_DELEGATING_SUBJECTS", "sa-worker")
    req = _make_request({"X-Effective-Tenant-Id": "real-tenant"})
    tenant, _subject, _lic = auth.apply_effective_tenant(
        req, None, "sa-tenant", "sa-subject", "sa-lic"
    )
    assert tenant == "sa-tenant"
