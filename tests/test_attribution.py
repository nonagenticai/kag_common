"""Cost-event project/job attribution (owner ruling 2026-10-07).

Covers: the request-scoped context + header binding + outbound stamping in
``kag_common.attribution``, and how ``kag_common.metering.emit_cost_event``
resolves ``project_id`` (explicit → bound → tenant-level, counted) and
``metadata.job_id`` onto the wire.
"""

from __future__ import annotations

import asyncio
import uuid

import fakeredis.aioredis
import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from kag_common import attribution, metering, metrics

_SVC = "test_service"
_TENANT = "0195f48b-d000-7000-8000-000000000100"
# Fixed vector shared with billing_service tenancy.tenant_level_project_id.
_TENANT_LEVEL = "00100000-0000-0008-0007-000db84f5910"
_P1 = "11111111-2222-4333-8444-555555555555"
_P2 = "66666666-7777-4888-9999-aaaaaaaaaaaa"


@pytest.fixture(autouse=True)
def _clean_context():
    attribution.clear_attribution_context()
    yield
    attribution.clear_attribution_context()


@pytest.fixture
async def redis_conn():
    conn = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield conn
    await conn.aclose()


def _fallback(reason: str) -> float:
    value = metrics.cost_project_fallback_total.labels(reason=reason)._value.get()
    return float(value)


async def _emit(redis_conn, **kwargs) -> dict[str, str]:
    params = dict(
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id=_TENANT,
        provider="p",
        model="m",
        input_tokens=1,
        output_tokens=1,
        latency_ms=1,
        stream="s",
    )
    params.update(kwargs)
    await metering.emit_cost_event(redis_conn, **params)
    entries = await redis_conn.xrange("s")
    assert len(entries) == 1
    await redis_conn.delete("s")
    return entries[0][1]


# --------------------------------------------------------------------------- #
# pure helpers
# --------------------------------------------------------------------------- #


def test_tenant_level_project_id_matches_billing_fixed_vector():
    assert attribution.tenant_level_project_id(_TENANT) == _TENANT_LEVEL
    assert attribution.tenant_level_project_id(uuid.UUID(_TENANT)) == _TENANT_LEVEL
    # involution: applying it twice returns the tenant
    assert attribution.tenant_level_project_id(_TENANT_LEVEL) == _TENANT


@pytest.mark.parametrize("bad", [None, "", "n8n-dev", "tenant-1", str(uuid.UUID(int=0)), 7])
def test_tenant_level_project_id_refuses_non_tenants(bad):
    assert attribution.tenant_level_project_id(bad) is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (_P1, _P1),
        (_P1.upper(), _P1),
        (f"  {_P1} ", _P1),
        (uuid.UUID(_P1), _P1),
        (_P1.replace("-", ""), None),
        ("{" + _P1 + "}", None),
        (f"urn:uuid:{_P1}", None),
        (str(uuid.UUID(int=0)), None),
        (uuid.UUID(int=0), None),
        ("not-a-uuid", None),
        ("", None),
        (None, None),
    ],
)
def test_parse_attribution_uuid_is_strict(raw, expected):
    assert attribution.parse_attribution_uuid(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("run-42", "run-42"),
        (" job:1.a_b ", "job:1.a_b"),
        (uuid.UUID(_P1), _P1),
        ("-leading", None),
        ("has space", None),
        ("x" * 129, None),
        ("a\nb", None),
        ("", None),
        (None, None),
    ],
)
def test_parse_job_id_is_bounded(raw, expected):
    assert attribution.parse_job_id(raw) == expected


def test_set_context_is_strict():
    with pytest.raises(ValueError):
        attribution.set_project_context("nope")
    with pytest.raises(ValueError):
        attribution.set_job_context("has space")
    attribution.set_project_context(_P1)
    attribution.set_job_context("run-1")
    assert attribution.get_project_id_from_context() == _P1
    assert attribution.get_job_id_from_context() == "run-1"
    attribution.set_project_context(None)
    attribution.set_job_context(None)
    assert attribution.get_project_id_from_context() == ""
    assert attribution.get_job_id_from_context() == ""


# --------------------------------------------------------------------------- #
# inbound binding
# --------------------------------------------------------------------------- #


def test_bind_generic_headers():
    bound = attribution.bind_attribution_from_headers({"X-Project-Id": _P1, "X-Job-Id": "run-1"})
    assert bound == (_P1, "run-1")
    assert attribution.get_project_id_from_context() == _P1
    assert attribution.get_job_id_from_context() == "run-1"


def test_w2v_headers_win_over_generic():
    attribution.bind_attribution_from_headers(
        {
            "X-Project-Id": _P1,
            "X-Job-Id": "generic",
            "X-W2V-Project-Id": _P2,
            "X-W2V-Job-Id": "w2v-run",
        }
    )
    assert attribution.get_project_id_from_context() == _P2
    assert attribution.get_job_id_from_context() == "w2v-run"


def test_malformed_w2v_header_falls_through_to_generic():
    attribution.bind_attribution_from_headers(
        {"X-W2V-Project-Id": "garbage", "X-Project-Id": _P1, "X-W2V-Job-Id": "bad id"}
    )
    assert attribution.get_project_id_from_context() == _P1
    assert attribution.get_job_id_from_context() == ""


def test_bind_is_case_tolerant_and_replaces_stale_values():
    attribution.set_project_context(_P2)
    attribution.set_job_context("stale")
    attribution.bind_attribution_from_headers({"x-project-id": _P1})
    assert attribution.get_project_id_from_context() == _P1
    # absent from every spelling -> unbound, not inherited
    assert attribution.get_job_id_from_context() == ""


def test_middleware_binds_per_request_and_resets():
    seen: dict[str, str] = {}

    async def endpoint(request):
        seen["project"] = attribution.get_project_id_from_context()
        seen["job"] = attribution.get_job_id_from_context()
        return JSONResponse({})

    app = Starlette(routes=[Route("/", endpoint)])
    app.add_middleware(attribution.AttributionContextMiddleware)
    with TestClient(app) as client:
        client.get("/", headers={"X-W2V-Project-Id": _P2, "X-Job-Id": "run-9"})
        assert seen == {"project": _P2, "job": "run-9"}
        client.get("/")
        assert seen == {"project": "", "job": ""}


# --------------------------------------------------------------------------- #
# outbound stamping
# --------------------------------------------------------------------------- #


def test_get_attribution_headers_omits_unbound():
    assert attribution.get_attribution_headers() == {}
    attribution.set_project_context(_P1)
    assert attribution.get_attribution_headers() == {"X-Project-Id": _P1}
    attribution.set_job_context("run-1")
    assert attribution.get_attribution_headers() == {"X-Project-Id": _P1, "X-Job-Id": "run-1"}


async def test_event_hook_stamps_per_request_and_never_overrides_caller():
    captured: list[httpx.Headers] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request.headers)
        return httpx.Response(200)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        event_hooks={"request": [attribution.attribution_event_hook]},
    ) as client:
        await client.get("http://x/")  # unbound
        attribution.set_project_context(_P1)
        attribution.set_job_context("run-1")
        await client.get("http://x/")
        await client.get("http://x/", headers={"X-Project-Id": _P2})

        async def other_request():
            # a concurrent task bound to a different project sees its own value
            attribution.set_project_context(_P2)
            attribution.set_job_context(None)
            await client.get("http://x/")

        await asyncio.create_task(other_request())

    assert "x-project-id" not in captured[0] and "x-job-id" not in captured[0]
    assert captured[1]["x-project-id"] == _P1 and captured[1]["x-job-id"] == "run-1"
    assert captured[2]["x-project-id"] == _P2  # caller's explicit header wins
    assert captured[3]["x-project-id"] == _P2 and "x-job-id" not in captured[3]


# --------------------------------------------------------------------------- #
# cost event resolution
# --------------------------------------------------------------------------- #


async def test_explicit_project_beats_context_and_is_top_level(redis_conn):
    attribution.set_project_context(_P2)
    fields = await _emit(redis_conn, project_id=_P1)
    assert fields["project_id"] == _P1
    fields = await _emit(redis_conn, project_id=uuid.UUID(_P1))
    assert fields["project_id"] == _P1


async def test_bound_project_used_when_no_explicit(redis_conn):
    attribution.bind_attribution_from_headers({"X-Project-Id": _P2})
    before = _fallback("tenant_level")
    fields = await _emit(redis_conn)
    assert fields["project_id"] == _P2
    assert _fallback("tenant_level") == before  # not a fallback


async def test_malformed_explicit_project_falls_through_not_coerced(redis_conn):
    attribution.set_project_context(_P2)
    fields = await _emit(redis_conn, project_id="not-a-uuid")
    assert fields["project_id"] == _P2


async def test_tenant_level_fallback_is_emitted_and_counted(redis_conn):
    before = _fallback("tenant_level")
    fields = await _emit(redis_conn)
    assert fields["project_id"] == _TENANT_LEVEL
    assert fields["project_id"] != fields["tenant_id"]
    assert _fallback("tenant_level") == before + 1


async def test_legacy_string_tenant_omits_project_and_counts_no_project(redis_conn):
    before = _fallback("no_project")
    fields = await _emit(redis_conn, tenant_id="n8n-dev")
    assert "project_id" not in fields
    assert _fallback("no_project") == before + 1


def test_fallback_series_are_preinitialised():
    names = {
        s.labels["reason"]
        for metric in metrics.cost_project_fallback_total.collect()
        for s in metric.samples
        if s.name == "kag_cost_project_fallback_total"
    }
    assert names == set(metrics.COST_PROJECT_FALLBACK_REASONS)


async def test_job_id_precedence(redis_conn):
    # nothing anywhere -> no job key at all
    fields = await _emit(redis_conn)
    assert "job_id" not in fields
    # bound context
    attribution.set_job_context("ctx-job")
    assert (await _emit(redis_conn))["job_id"] == "ctx-job"
    # metadata_extra beats context
    fields = await _emit(redis_conn, metadata_extra={"job_id": "md-job"})
    assert fields["job_id"] == "md-job"
    # an explicit None in metadata_extra suppresses the ambient job
    fields = await _emit(redis_conn, metadata_extra={"job_id": None})
    assert "job_id" not in fields
    # explicit param beats both
    fields = await _emit(redis_conn, job_id="arg-job", metadata_extra={"job_id": "md-job"})
    assert fields["job_id"] == "arg-job"
    # malformed explicit param is dropped, chain continues
    fields = await _emit(redis_conn, job_id="bad job")
    assert fields["job_id"] == "ctx-job"


async def test_schedule_sees_the_callers_bound_context(redis_conn):
    attribution.set_project_context(_P1)
    attribution.set_job_context("run-7")
    assert metering.schedule_cost_event(
        redis_conn,
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id=_TENANT,
        provider="p",
        model="m",
        input_tokens=1,
        output_tokens=1,
        latency_ms=1,
        stream="s",
    )
    # unbinding in the caller AFTER scheduling must not change the event
    attribution.clear_attribution_context()
    await metering.drain_pending()
    entries = await redis_conn.xrange("s")
    assert entries[0][1]["project_id"] == _P1
    assert entries[0][1]["job_id"] == "run-7"


async def test_schedule_forwards_explicit_attribution(redis_conn):
    metering.schedule_cost_event(
        redis_conn,
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id=_TENANT,
        provider="p",
        model="m",
        input_tokens=1,
        output_tokens=1,
        latency_ms=1,
        stream="s",
        project_id=_P2,
        job_id="run-8",
    )
    await metering.drain_pending()
    entries = await redis_conn.xrange("s")
    assert entries[0][1]["project_id"] == _P2
    assert entries[0][1]["job_id"] == "run-8"


# --------------------------------------------------------------------------- #
# actor (X-Actor-Id / SERVICE_ACTOR_ID) and app (X-App-Id)
# --------------------------------------------------------------------------- #

_HUMAN = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
_SERVICE_SUB = "12345678-9abc-4def-8123-456789abcdef"


@pytest.fixture(autouse=True)
def _no_service_actor(monkeypatch):
    monkeypatch.delenv("SERVICE_ACTOR_ID", raising=False)


def _actor_missing(service: str = _SVC, reason: str = "no_service_actor") -> float:
    return float(metrics.actor_missing_total.labels(service=service, reason=reason)._value.get())


def _actor_malformed(service: str) -> float:
    return float(metrics.actor_header_malformed_total.labels(service=service)._value.get())


async def test_inbound_actor_and_app_are_bound_forwarded_and_stamped(redis_conn):
    """Inbound X-Actor-Id / X-App-Id -> bound -> forwarded downstream -> on the cost event."""
    seen: dict[str, str] = {}
    captured: list[httpx.Headers] = []

    def downstream(request: httpx.Request) -> httpx.Response:
        captured.append(request.headers)
        return httpx.Response(200)

    async def endpoint(request):
        seen["actor"] = attribution.get_actor_id_from_context()
        seen["app"] = attribution.get_app_id_from_context()
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(downstream),
            event_hooks={"request": [attribution.attribution_event_hook]},
        ) as client:
            await client.get("http://downstream/")
        seen["wire"] = (await _emit(redis_conn)).get("actor_id", "")
        return JSONResponse({})

    app = Starlette(routes=[Route("/", endpoint)])
    app.add_middleware(attribution.AttributionContextMiddleware)
    with TestClient(app) as client:
        # Upper-case input: bound canonical (lower-case).
        client.get("/", headers={"X-Actor-Id": _HUMAN.upper(), "X-App-Id": "portal"})
        assert seen == {"actor": _HUMAN, "app": "portal", "wire": _HUMAN}
        assert captured[0]["x-actor-id"] == _HUMAN
        assert captured[0]["x-app-id"] == "portal"
        # Next request with no headers: reset, nothing forwarded.
        client.get("/")
        assert seen["actor"] == "" and seen["app"] == ""
        assert "x-actor-id" not in captured[1] and "x-app-id" not in captured[1]


def test_get_attribution_headers_includes_actor_and_app():
    attribution.set_actor_context(_HUMAN)
    attribution.set_app_id_context("portal")
    assert attribution.get_attribution_headers() == {"X-Actor-Id": _HUMAN, "X-App-Id": "portal"}


async def test_service_actor_id_fallback(redis_conn, monkeypatch):
    monkeypatch.setenv("SERVICE_ACTOR_ID", _SERVICE_SUB)
    before = _actor_missing()
    fields = await _emit(redis_conn)
    assert fields["actor_id"] == _SERVICE_SUB
    assert _actor_missing() == before


async def test_human_sub_wins_over_service_sub(redis_conn, monkeypatch):
    monkeypatch.setenv("SERVICE_ACTOR_ID", _SERVICE_SUB)
    attribution.bind_attribution_from_headers({"X-Actor-Id": _HUMAN})
    fields = await _emit(redis_conn)
    assert fields["actor_id"] == _HUMAN


async def test_no_actor_anywhere_is_unset_and_counted(redis_conn):
    before = _actor_missing()
    fields = await _emit(redis_conn)
    assert "actor_id" not in fields
    assert _actor_missing() == before + 1


async def test_malformed_service_actor_env_is_absent_not_shipped(redis_conn, monkeypatch):
    monkeypatch.setenv("SERVICE_ACTOR_ID", "svc-nlp")
    before = _actor_missing()
    fields = await _emit(redis_conn)
    assert "actor_id" not in fields
    assert _actor_missing() == before + 1


@pytest.mark.parametrize(
    "bad",
    [
        "not-a-uuid",
        "00000000-0000-0000-0000-000000000000",  # nil sentinel
        "aaaaaaaabbbb4ccc8dddeeeeeeeeeeee",  # bare hex, non-canonical
        "{aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee}",
    ],
)
async def test_malformed_actor_header_is_dropped_and_counted(redis_conn, monkeypatch, bad):
    monkeypatch.setenv("OTEL_SERVICE_NAME", "actor-test-svc")
    monkeypatch.setenv("SERVICE_ACTOR_ID", _SERVICE_SUB)
    attribution.set_actor_context(_HUMAN)  # stale value must not survive
    before = _actor_malformed("actor-test-svc")
    missing_before = _actor_missing(reason="inbound_without_actor")
    attribution.bind_attribution_from_headers({"X-Actor-Id": bad})
    assert attribution.get_actor_id_from_context() == ""
    # malformed == absent on an inbound request: never relayed, and the service's
    # own sub is NOT substituted (0.36.0) — the caller's gap stays visible
    assert "X-Actor-Id" not in attribution.get_attribution_headers()
    assert _actor_malformed("actor-test-svc") == before + 1
    assert "actor_id" not in await _emit(redis_conn)
    assert _actor_missing(reason="inbound_without_actor") == missing_before + 1


def test_absent_actor_header_is_not_counted_as_malformed(monkeypatch):
    monkeypatch.setenv("OTEL_SERVICE_NAME", "actor-test-svc")
    before = _actor_malformed("actor-test-svc")
    attribution.bind_attribution_from_headers({"X-Project-Id": _P1})
    assert _actor_malformed("actor-test-svc") == before


async def test_explicit_metadata_actor_beats_context(redis_conn):
    attribution.set_actor_context(_HUMAN)
    fields = await _emit(redis_conn, metadata_extra={"actor_id": _SERVICE_SUB})
    assert fields["actor_id"] == _SERVICE_SUB


def test_set_actor_context_is_strict():
    with pytest.raises(ValueError):
        attribution.set_actor_context("not-a-uuid")
    with pytest.raises(ValueError):
        attribution.set_actor_context("00000000-0000-0000-0000-000000000000")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("portal", "portal"),
        ("  portal\t", "portal"),
        ("portal\r", None),  # never repaired into a clean value
        ("por\ntal", None),
        ("", None),
        ("x" * 129, None),
        (None, None),
    ],
)
def test_parse_app_id_screens_header_injection(raw, expected):
    assert attribution.parse_app_id(raw) == expected


async def test_event_hook_never_overrides_caller_app_or_actor():
    captured: list[httpx.Headers] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request.headers)
        return httpx.Response(200)

    attribution.set_actor_context(_HUMAN)
    attribution.set_app_id_context("portal")
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        event_hooks={"request": [attribution.attribution_event_hook]},
    ) as client:
        await client.get("http://x/", headers={"X-App-Id": "explicit", "X-Actor-Id": _SERVICE_SUB})
    assert captured[0]["x-app-id"] == "explicit"
    assert captured[0]["x-actor-id"] == _SERVICE_SUB


# --------------------------------------------------------------------------- #
# outbound: unbound actor -> this service's own SERVICE_ACTOR_ID (0.35.0)
# --------------------------------------------------------------------------- #


async def _outbound(headers: dict[str, str] | None = None) -> httpx.Headers:
    captured: list[httpx.Headers] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request.headers)
        return httpx.Response(200)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        event_hooks={"request": [attribution.attribution_event_hook]},
    ) as client:
        await client.get("http://downstream/", headers=headers)
    return captured[0]


async def test_outbound_unbound_actor_sends_service_actor_id(monkeypatch):
    monkeypatch.setenv("SERVICE_ACTOR_ID", _SERVICE_SUB)
    assert (await _outbound())["x-actor-id"] == _SERVICE_SUB
    assert attribution.get_attribution_headers() == {"X-Actor-Id": _SERVICE_SUB}


async def test_outbound_bound_human_actor_wins_over_service_actor(monkeypatch):
    monkeypatch.setenv("SERVICE_ACTOR_ID", _SERVICE_SUB)
    attribution.bind_attribution_from_headers({"X-Actor-Id": _HUMAN})
    assert (await _outbound())["x-actor-id"] == _HUMAN


async def test_outbound_explicit_caller_header_wins_over_service_actor(monkeypatch):
    monkeypatch.setenv("SERVICE_ACTOR_ID", _SERVICE_SUB)
    assert (await _outbound({"X-Actor-Id": _HUMAN}))["x-actor-id"] == _HUMAN


async def test_outbound_no_actor_anywhere_sends_no_header():
    assert "x-actor-id" not in await _outbound()


async def test_outbound_malformed_service_actor_is_not_sent(monkeypatch):
    monkeypatch.setenv("SERVICE_ACTOR_ID", "svc-nlp")
    assert "x-actor-id" not in await _outbound()


async def test_outbound_malformed_inbound_actor_is_absent_and_counted(monkeypatch):
    monkeypatch.setenv("SERVICE_ACTOR_ID", _SERVICE_SUB)
    monkeypatch.setenv("OTEL_SERVICE_NAME", "actor-test-svc")
    before = _actor_missing("actor-test-svc", "inbound_without_actor")
    attribution.bind_attribution_from_headers({"X-Actor-Id": "garbage"})
    assert "x-actor-id" not in await _outbound()
    assert _actor_missing("actor-test-svc", "inbound_without_actor") == before + 1


def test_middleware_inbound_without_actor_is_absent_and_counted(monkeypatch, redis_conn):
    """Inbound with no X-Actor-Id: absent on emit AND outbound, counted; never the service id."""
    monkeypatch.setenv("SERVICE_ACTOR_ID", _SERVICE_SUB)
    monkeypatch.setenv("OTEL_SERVICE_NAME", "actor-test-svc")
    seen: dict[str, object] = {}
    captured: list[httpx.Headers] = []

    def downstream(request: httpx.Request) -> httpx.Response:
        captured.append(request.headers)
        return httpx.Response(200)

    async def endpoint(request):
        seen["inbound"] = attribution.is_inbound_request_context()
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(downstream),
            event_hooks={"request": [attribution.attribution_event_hook]},
        ) as client:
            await client.get("http://downstream/")
        seen["wire"] = (await _emit(redis_conn)).get("actor_id", "")
        return JSONResponse({})

    app = Starlette(routes=[Route("/", endpoint)])
    app.add_middleware(attribution.AttributionContextMiddleware)
    emit_before = _actor_missing(_SVC, "inbound_without_actor")
    out_before = _actor_missing("actor-test-svc", "inbound_without_actor")
    with TestClient(app) as client:
        client.get("/")
        assert seen == {"inbound": True, "wire": ""}
        assert "x-actor-id" not in captured[0]
        assert _actor_missing(_SVC, "inbound_without_actor") == emit_before + 1
        assert _actor_missing("actor-test-svc", "inbound_without_actor") == out_before + 1
        # inbound WITH an actor: forwarded and stamped, nothing counted
        client.get("/", headers={"X-Actor-Id": _HUMAN})
        assert seen == {"inbound": True, "wire": _HUMAN}
        assert captured[1]["x-actor-id"] == _HUMAN
        assert _actor_missing(_SVC, "inbound_without_actor") == emit_before + 1
    # the inbound flag does not leak past the request
    assert attribution.is_inbound_request_context() is False


async def test_background_work_without_request_uses_service_actor(redis_conn, monkeypatch):
    """No inbound request (worker / scheduler): SERVICE_ACTOR_ID on emit and outbound."""
    monkeypatch.setenv("SERVICE_ACTOR_ID", _SERVICE_SUB)
    assert attribution.is_inbound_request_context() is False
    assert (await _emit(redis_conn))["actor_id"] == _SERVICE_SUB
    assert (await _outbound())["x-actor-id"] == _SERVICE_SUB


async def test_explicit_caller_header_wins_inbound_without_actor_and_is_not_counted(monkeypatch):
    monkeypatch.setenv("OTEL_SERVICE_NAME", "actor-test-svc")
    attribution.bind_attribution_from_headers({})
    before = _actor_missing("actor-test-svc", "inbound_without_actor")
    assert (await _outbound({"X-Actor-Id": _HUMAN}))["x-actor-id"] == _HUMAN
    assert _actor_missing("actor-test-svc", "inbound_without_actor") == before


async def test_middleware_resets_inbound_flag_in_the_same_task():
    """Same task, no thread hop: the inbound flag must not outlive the request."""
    seen: dict[str, bool] = {}

    async def app(scope, receive, send):
        seen["inside"] = attribution.is_inbound_request_context()

    mw = attribution.AttributionContextMiddleware(app)
    await mw({"type": "http", "headers": []}, None, None)
    assert seen["inside"] is True
    assert attribution.is_inbound_request_context() is False
