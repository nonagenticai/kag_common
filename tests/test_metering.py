"""Tests for the shared cost-bus emitter (``kag_common.metering``)."""

from __future__ import annotations

import json
import logging
import uuid

import fakeredis.aioredis
import pytest

from kag_common import metering, metrics
from kag_common.tenant import InvalidTenantIdError, MissingTenantError, TenantError

# Product/service key under test. A module constant keeps the literal out of
# every call site so detect-secrets' Secret-Keyword plugin does not flag
# ``service_key="..."`` (it is a product identifier, never a credential).
_SVC = "ingestion"


@pytest.fixture
async def redis_conn():
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


def test_resolve_stream_default(monkeypatch):
    monkeypatch.delenv("METERING_STREAM", raising=False)
    assert metering.resolve_stream() == metering.CANONICAL_COST_STREAM


def test_resolve_stream_env_override(monkeypatch):
    monkeypatch.setenv("METERING_STREAM", "custom:stream")
    assert metering.resolve_stream() == "custom:stream"


async def _read_one(redis_conn, stream: str) -> dict[str, str]:
    entries = await redis_conn.xrange(stream)
    assert len(entries) == 1, f"expected exactly one event, got {len(entries)}"
    return entries[0][1]


async def test_emit_writes_canonical_field_shape(redis_conn, monkeypatch):
    monkeypatch.delenv("METERING_STREAM", raising=False)
    await metering.emit_cost_event(
        redis_conn,
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
        subject_id="sub-1",
        usage_extra={"byo": "true"},
    )
    fields = await _read_one(redis_conn, metering.CANONICAL_COST_STREAM)
    assert fields["tenant_id"] == "tenant-1"
    assert fields["service_key"] == _SVC
    assert fields["cost_source"] == "self_hosted"
    assert fields["provider"] == "webscraper"
    assert fields["subject_id"] == "sub-1"
    assert fields["cost_usd"] == "0.00000000"
    assert json.loads(fields["usage_extra"]) == {"byo": "true"}
    # every field is a string at the redis layer
    assert all(isinstance(v, str) for v in fields.values())


# ---------------------------------------------------------------------------
# defect 2: a fabricated tenant is worse than a missing one
# ---------------------------------------------------------------------------
#
# ⛔ REPLACED `test_emit_coerces_falsy_tenant_to_unattributed`, which asserted
# `fields["tenant_id"] == metering.UNATTRIBUTED_TENANT_ID`. That test PINNED the
# defect as the specification: it passed for exactly the behaviour we are here
# to remove, and it would have out-voted this fix in review. The substitution it
# guarded bought nothing — billing classifies the nil uuid as `nil_tenant_id`
# and dead-letters the event (`billing_service _cost_schema.py:115`) — while
# every attribution metric on this side stayed green because a valid, REGISTERED
# uuid went out on the wire.


@pytest.mark.parametrize(
    ("bad_tenant", "expected_message"),
    [
        pytest.param(None, "no tenant id present", id="none"),
        pytest.param("", "tenant id is empty", id="empty"),
        pytest.param("   ", "tenant id is empty", id="whitespace"),
    ],
)
async def test_emit_refuses_a_falsy_tenant_rather_than_fabricating_one(
    redis_conn, bad_tenant, expected_message
):
    """⛔ FAILS ON origin/main, where this emitted a nil-UUID row and returned None.

    A falsy tenant must raise, not be papered over with a sentinel. The raise
    happens OUTSIDE the never-raises `try`, so the transport-failure handler
    cannot re-hide it — assert the exception AND that nothing reached the stream.
    """
    with pytest.raises(MissingTenantError) as excinfo:
        await metering.emit_cost_event(
            redis_conn,
            service_key=_SVC,
            cost_source="self_hosted",
            tenant_id=bad_tenant,
            provider="webscraper",
            model="",
            input_tokens=0,
            output_tokens=0,
            latency_ms=0,
        )
    # The message names the lane that produced the unusable tenant, so an
    # operator can tell WHICH caller is broken from the traceback alone.
    assert expected_message in str(excinfo.value)
    assert f"cost event ({_SVC}/self_hosted)" in str(excinfo.value)
    # Refused before the XADD: no fabricated row on the bus.
    assert await redis_conn.xlen(metering.CANONICAL_COST_STREAM) == 0


async def test_an_explicitly_passed_nil_uuid_still_goes_out_today(redis_conn):
    """⚠️ OPEN GAP, pinned deliberately so it is not closed blind. NOT a spec.

    `w2v_common` rejects the nil uuid BY VALUE; this library does not, yet. The
    reason is measured, not an oversight: `ingestion_service` uses the nil uuid
    as an intentional, Prometheus-counted UNATTRIBUTED SINK (`src/config.py:46`
    -> `src/tenancy.py:58` -> `src/routes/ingest_routes.py:135`), and it reaches
    this emitter from `submit.py:404`, which is NOT wrapped in a try/except —
    so rejecting nil here would turn an already-successful, already-persisted
    scrape into an HTTP 500.

    This asserts what the library ACTUALLY does today so that whoever closes the
    gap has to delete this test on purpose, having read why it exists, rather
    than discovering the 500 in production. ⛔ Fix `ingestion_service` first;
    then delete this test and add the rejection.

    What this PR removes is the FABRICATION — the library inventing the sentinel
    on the caller's behalf. A caller that CHOOSES the sink is making a visible,
    counted claim, and that is its own repo's decision to change.
    """
    await metering.emit_cost_event(
        redis_conn,
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="00000000-0000-0000-0000-000000000000",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
    )
    fields = await _read_one(redis_conn, metering.CANONICAL_COST_STREAM)
    assert fields["tenant_id"] == "00000000-0000-0000-0000-000000000000"


async def test_a_non_str_tenant_is_refused(redis_conn):
    """`InvalidTenantIdError` is reachable, not a class that can never be raised."""
    with pytest.raises(InvalidTenantIdError):
        await metering.emit_cost_event(
            redis_conn,
            service_key=_SVC,
            cost_source="self_hosted",
            tenant_id=12345,  # type: ignore[arg-type]
            provider="webscraper",
            model="",
            input_tokens=0,
            output_tokens=0,
            latency_ms=0,
        )
    assert await redis_conn.xlen(metering.CANONICAL_COST_STREAM) == 0


async def test_tenant_errors_share_a_catchable_base(redis_conn):
    """A caller that treats "no usable tenant" as one condition can catch it.

    Both subclass `TenantError`, itself a `ValueError` — the same grammar as
    `w2v_common.tenant`, so the estate's two metering clients agree.
    """
    assert issubclass(MissingTenantError, TenantError)
    assert issubclass(InvalidTenantIdError, TenantError)
    assert issubclass(TenantError, ValueError)


def test_schedule_refuses_a_falsy_tenant_in_the_callers_frame():
    """The raise must be SYNCHRONOUS, not deferred into the background task.

    A `TenantError` raised inside the fire-and-forget task would surface only as
    an "exception never retrieved" warning — i.e. exactly the silent
    mis-attribution this change exists to end. No running loop is needed: if the
    validation were inside the coroutine this call would return quietly.
    """
    with pytest.raises(MissingTenantError):
        metering.schedule_cost_event(
            object(),  # type: ignore[arg-type]
            service_key=_SVC,
            cost_source="self_hosted",
            tenant_id="",
            provider="webscraper",
            model="",
            input_tokens=0,
            output_tokens=0,
            latency_ms=0,
        )


def test_the_nil_sentinel_constant_is_gone():
    """`UNATTRIBUTED_TENANT_ID` must not come back as an importable default.

    While the name exists, a consumer can import it and re-introduce the
    fabrication at ITS call site, where this library cannot see it.
    """
    assert not hasattr(metering, "UNATTRIBUTED_TENANT_ID")
    assert "UNATTRIBUTED_TENANT_ID" not in metering.__all__


# ---------------------------------------------------------------------------
# defect 1: the producer-minted idempotency key billing dedupes on
# ---------------------------------------------------------------------------
#
# billing_service `cost_flusher.py` claims `event_key` in an inbox table and
# drops any event whose key it has already seen — but ONLY for rows that carry
# the field (`key_rows = [p for p in survived if p[0].get("event_key")]`, :746);
# the keyless remainder is added back unconditionally at :780 and billed every
# time. Measured before this change: kag rows were 0% event_key over 6h while
# mlx-backend and inference-router were both 100%.


async def test_emit_mints_a_uuid7_event_key(redis_conn):
    """⛔ FAILS ON origin/main, where `_build_fields` never put this on the wire.

    Without it billing's dedup claim is skipped entirely and the charge is
    applied unconditionally — a live double-bill, because the XADD retry below
    re-sends the same charge under a NEW stream message id and `stream_msg_id`
    (billing's only other defence) cannot see that the two are one call.
    """
    await metering.emit_cost_event(
        redis_conn,
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
    )
    fields = await _read_one(redis_conn, metering.CANONICAL_COST_STREAM)
    assert "event_key" in fields, "no event_key -> billing skips its dedup claim"
    # A string at the redis layer, and a real uuid7 — not a truncated value, not
    # a uuid4 (which would still dedupe, but breaks the time-ordering the rest of
    # the estate mints; w2v_common uses uuid7 and the two must agree).
    parsed = uuid.UUID(fields["event_key"])
    assert parsed.version == 7, f"expected a uuid7, got a uuid{parsed.version}"
    assert str(parsed) == fields["event_key"], "not the canonical uuid spelling"


async def test_every_retry_of_one_call_carries_the_same_event_key():
    """The key must be minted ONCE per logical call, not once per XADD attempt.

    This is the whole mechanism of the double-bill: a timeout raised AFTER redis
    accepted the write makes the bounded retry re-send the charge. If the key
    were minted inside the retry loop each attempt would carry a different one
    and billing could not dedupe them — the fix would look present and do
    nothing.
    """
    seen_keys: list[str] = []

    class _FlakyRedis:
        def __init__(self) -> None:
            self.calls = 0

        async def xadd(self, _stream, fields, **_kwargs):  # noqa: ANN001, ANN003
            self.calls += 1
            seen_keys.append(fields["event_key"])
            if self.calls < 3:
                from redis.exceptions import TimeoutError as RedisTimeoutError

                raise RedisTimeoutError("accepted the write, then timed out")
            return "1-1"

    await metering.emit_cost_event(
        _FlakyRedis(),  # type: ignore[arg-type]
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
    )
    assert len(seen_keys) == 3, f"expected 3 XADD attempts, got {len(seen_keys)}"
    assert len(set(seen_keys)) == 1, f"retries minted different keys: {seen_keys}"


async def test_two_separate_calls_get_different_event_keys(redis_conn):
    """One key per PHYSICAL metered call — a constant would dedupe real charges.

    The mirror of the test above: a fix that minted one module-level key would
    satisfy "same key across retries" and silently drop every legitimate second
    charge for a tenant.
    """
    for _ in range(2):
        await metering.emit_cost_event(
            redis_conn,
            service_key=_SVC,
            cost_source="self_hosted",
            tenant_id="tenant-1",
            provider="webscraper",
            model="",
            input_tokens=0,
            output_tokens=0,
            latency_ms=0,
        )
    entries = await redis_conn.xrange(metering.CANONICAL_COST_STREAM)
    assert len(entries) == 2
    keys = {fields["event_key"] for _id, fields in entries}
    assert len(keys) == 2, "distinct calls must not share an idempotency key"


async def test_caller_supplied_event_key_is_honoured_not_overwritten(redis_conn):
    await metering.emit_cost_event(
        redis_conn,
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
        event_key="caller-owned-key-1",
    )
    fields = await _read_one(redis_conn, metering.CANONICAL_COST_STREAM)
    assert fields["event_key"] == "caller-owned-key-1"


async def test_a_falsy_caller_event_key_falls_back_to_minting(redis_conn):
    """`""` must not reach the wire: billing's `.get("event_key")` reads an empty
    string as ABSENT, i.e. as no dedup at all — the defect wearing the fix's
    clothes."""
    await metering.emit_cost_event(
        redis_conn,
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
        event_key="",
    )
    fields = await _read_one(redis_conn, metering.CANONICAL_COST_STREAM)
    assert uuid.UUID(fields["event_key"]).version == 7


async def test_metadata_extra_cannot_forge_an_event_key(redis_conn):
    """`event_key` is not in the passthrough whitelist and must stay unforgeable.

    A caller that could overwrite it through `metadata_extra` could collide two
    real charges onto one key and billing would drop the second as a duplicate.
    """
    await metering.emit_cost_event(
        redis_conn,
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
        metadata_extra={"event_key": "forged"},
    )
    fields = await _read_one(redis_conn, metering.CANONICAL_COST_STREAM)
    assert fields["event_key"] != "forged"
    assert uuid.UUID(fields["event_key"]).version == 7


async def test_schedule_also_mints_an_event_key(redis_conn):
    metering.schedule_cost_event(
        redis_conn,
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
    )
    await metering.drain_pending(timeout=2.0)
    fields = await _read_one(redis_conn, metering.CANONICAL_COST_STREAM)
    assert uuid.UUID(fields["event_key"]).version == 7


async def test_emit_owner_provided_provenance(redis_conn):
    await metering.emit_cost_event(
        redis_conn,
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
        usage_extra={"owner_provided": "true"},
    )
    fields = await _read_one(redis_conn, metering.CANONICAL_COST_STREAM)
    assert json.loads(fields["usage_extra"]) == {"owner_provided": "true"}


async def test_emit_respects_stream_override(redis_conn, monkeypatch):
    monkeypatch.setenv("METERING_STREAM", "override:costs")
    await metering.emit_cost_event(
        redis_conn,
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
    )
    assert await redis_conn.xlen("override:costs") == 1
    assert await redis_conn.xlen(metering.CANONICAL_COST_STREAM) == 0


async def test_emit_never_raises_on_broken_connection():
    class _BrokenRedis:
        async def xadd(self, *a, **k):  # noqa: ANN002, ANN003
            raise RuntimeError("redis down")

    # Never raises — the fire-and-forget contract holds even on a hard failure.
    await metering.emit_cost_event(
        _BrokenRedis(),  # type: ignore[arg-type]
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
    )


async def test_schedule_then_drain_lands_event(redis_conn):
    metering.schedule_cost_event(
        redis_conn,
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
    )
    await metering.drain_pending(timeout=2.0)
    assert await redis_conn.xlen(metering.CANONICAL_COST_STREAM) == 1


def test_schedule_no_running_loop_is_noop():
    # Sync context (no running loop): must not raise, must not warn-crash.
    # ⚠️ No longer a NO-OP in the "nothing observable happened" sense — the drop
    # is now counted and marked. What survives from the original contract is the
    # part that matters to the caller: it still does not raise. The observable
    # half is asserted in the no-loop block at the end of this file.
    dropped = metering.schedule_cost_event(
        object(),  # type: ignore[arg-type]
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
    )
    assert dropped is False


async def test_init_metering_redis_empty_url_returns_none():
    assert await metering.init_metering_redis("") is None


async def test_close_metering_redis_none_is_safe():
    await metering.close_metering_redis(None)


async def test_init_metering_redis_sets_the_timeouts_that_prevent_a_silent_hang(monkeypatch):
    """⛔ A bare from_url() here hangs the emitter FOREVER, silently.

    Without `socket_timeout`, a half-open socket makes `await xadd(...)` block
    indefinitely. It never raises, so the bounded retry in emit_cost_event never
    runs, the `except` never fires, and `cost_event_emit_failed` never logs —
    the symptom is total silence with a healthy-looking pod, and the pending
    tasks accumulate without bound. An error is counted somewhere; a hang is
    invisible everywhere, which is why this is pinned rather than left to review.

    `health_check_interval` is the one that PREVENTS it rather than recovering:
    the inference-router fork of this client sets it and names the cause in its
    own comment — redis.example's idle-reaper RSTs quiet sockets, and an
    emitter is idle by nature between bursts.

    This asserts the kwargs rather than the behaviour on purpose: reproducing a
    half-open socket in a unit test needs a packet-level fake, and the thing that
    actually regresses is someone simplifying the call back to `from_url(url,
    decode_responses=True)`. That is what this catches.
    """
    seen: dict[str, object] = {}

    class _FakeClient:
        async def ping(self) -> bool:
            return True

    def _fake_from_url(url: str, **kwargs: object) -> _FakeClient:
        seen.update(kwargs)
        seen["url"] = url
        return _FakeClient()

    import redis.asyncio as aioredis

    monkeypatch.setattr(aioredis, "from_url", _fake_from_url)

    client = await metering.init_metering_redis("redis://example.invalid:6379/0")
    assert client is not None

    assert seen.get("socket_timeout"), "socket_timeout missing — a half-open socket hangs forever"
    assert seen.get("socket_connect_timeout"), "socket_connect_timeout missing"
    assert seen.get("health_check_interval"), (
        "health_check_interval missing — idle sockets get reaped"
    )
    assert seen.get("retry_on_timeout") is True, "retry_on_timeout missing"
    assert seen.get("decode_responses") is True, (
        "decode_responses must stay True (ping/cast rely on it)"
    )


# ---------------------------------------------------------------------------
# metadata passthrough (billing_cost_events.metadata attribution)
# ---------------------------------------------------------------------------
#
# Context: 62,669 ledger rows / $812.35 of spend carry a JSON-null `metadata`,
# so the money is unattributable to any originator. Billing's receiver whitelist
# (billing_service cost_flusher, the `extra_meta` loop) landed FIRST on purpose.
# These tests pin the producer half against that whitelist.


async def test_metadata_extra_forwards_whitelisted_keys(redis_conn, monkeypatch):
    monkeypatch.delenv("METERING_STREAM", raising=False)
    # Distinct value per key on purpose: a single shared value would let an
    # implementation that hardcodes one key (or writes the same value to all)
    # pass this test.
    await metering.emit_cost_event(
        redis_conn,
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
        metadata_extra={
            "schema_id": "schema-a",
            "job_id": "job-b",
            "fallback_used": "yes-c",
            "stage": "stage-d",
            "worker_name": "worker-e",
            "caller_client_id": "caller-f",
            "actor_id": "actor-g",
        },
    )
    fields = await _read_one(redis_conn, metering.CANONICAL_COST_STREAM)
    assert fields["schema_id"] == "schema-a"
    assert fields["job_id"] == "job-b"
    assert fields["fallback_used"] == "yes-c"
    assert fields["stage"] == "stage-d"
    assert fields["worker_name"] == "worker-e"
    assert fields["caller_client_id"] == "caller-f"
    assert fields["actor_id"] == "actor-g"


def test_metadata_passthrough_set_mirrors_the_billing_receiver():
    """⛔ This set must never grow ahead of billing's `extra_meta` whitelist.

    A key this producer ships that the receiver's loop omits is dropped silently
    and the resulting row still looks correct — the exact failure the receiver's
    own comment records. Widen billing_service first, then this.
    """
    assert metering._METADATA_PASSTHROUGH_KEYS == frozenset(
        {
            "schema_id",
            "job_id",
            "fallback_used",
            "stage",
            "worker_name",
            "caller_client_id",
            "actor_id",
        }
    )


async def test_metadata_extra_drops_unknown_keys(redis_conn, caplog):
    caplog.set_level(logging.DEBUG, logger="kag_common.metering")
    await metering.emit_cost_event(
        redis_conn,
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
        metadata_extra={"worker_name": "kept", "not_a_real_key": "x", "cost_usd": "999"},
    )
    fields = await _read_one(redis_conn, metering.CANONICAL_COST_STREAM)
    assert fields["worker_name"] == "kept"
    assert "not_a_real_key" not in fields
    # A non-whitelisted key must never be able to overwrite a canonical field.
    assert fields["cost_usd"] == "0.00000000"
    # The drop is silent on the wire but named in the log.
    assert "cost_event_metadata_keys_dropped" in caplog.text
    assert "not_a_real_key" in caplog.text


async def test_metadata_extra_coerces_values_to_str_and_skips_none(redis_conn):
    await metering.emit_cost_event(
        redis_conn,
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
        metadata_extra={"job_id": 12345, "fallback_used": True, "stage": None},
    )
    fields = await _read_one(redis_conn, metering.CANONICAL_COST_STREAM)
    assert fields["job_id"] == "12345"
    assert fields["fallback_used"] == "True"
    # `str(None)` is the truthy literal "None"; the receiver's `if c.get(k)`
    # would store that as real metadata. Absent means absent.
    assert "stage" not in fields


def test_metadata_extra_omitted_is_byte_identical_to_today():
    """The change is additive: no kwarg -> exactly the pre-change field dict."""
    kwargs = dict(
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        license_id="lic-1",
        subject_id="sub-1",
        app_id="app-1",
        provider="webscraper",
        model="m",
        served_model=None,
        input_tokens=1,
        output_tokens=2,
        latency_ms=3,
        cost_usd=0.5,
        provider_request_id="req-1",
        usage_extra={"byo": "true"},
    )
    fields = metering._build_fields(**kwargs)
    # `timestamp` is wall-clock and `event_key` is freshly minted per call; every
    # other key/value is fully determined.
    timestamp = fields.pop("timestamp")
    assert timestamp  # still emitted
    event_key = fields.pop("event_key")
    assert uuid.UUID(event_key).version == 7  # still emitted, still a uuid7
    assert fields == {
        "tenant_id": "tenant-1",
        "license_id": "lic-1",
        "subject_id": "sub-1",
        "app_id": "app-1",
        "service_key": _SVC,
        "cost_source": "self_hosted",
        "provider": "webscraper",
        "model": "m",
        "served_model": "m",
        "input_tokens": "1",
        "output_tokens": "2",
        "cost_usd": "0.50000000",
        "latency_ms": "3",
        "provider_request_id": "req-1",
        "usage_extra": '{"byo": "true"}',
    }
    # An explicit empty mapping must also add nothing.
    empty = metering._build_fields(**kwargs, metadata_extra={})
    empty.pop("timestamp")
    assert uuid.UUID(empty.pop("event_key")).version == 7
    assert empty == fields


async def test_schedule_forwards_metadata_extra(redis_conn):
    metering.schedule_cost_event(
        redis_conn,
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
        metadata_extra={"worker_name": "requirements", "bogus": "drop-me"},
    )
    await metering.drain_pending(timeout=2.0)
    fields = await _read_one(redis_conn, metering.CANONICAL_COST_STREAM)
    assert fields["worker_name"] == "requirements"
    assert "bogus" not in fields


def test_schedule_no_running_loop_warns_rather_than_whispering(caplog):
    """⚠️ This branch DROPS a billable event; at DEBUG the loss was invisible.

    Services run at LOG_LEVEL=INFO, so the old `logger.debug` meant a dropped
    cost event produced no line anywhere. Control flow is unchanged — it must
    still never raise — but the loss is now on the record.

    ⚠️ The needle moved from ``schedule_cost_event_no_loop`` to
    ``cost_event_dropped_no_running_loop``, matching the w2v_common port of this
    same function so one log query covers both lineages. Measured before
    renaming: zero consumers of the old string outside the two emitters — no
    gitops rule, no alert, no dashboard.
    """
    caplog.set_level(logging.WARNING, logger="kag_common.metering")
    metering.schedule_cost_event(
        object(),  # type: ignore[arg-type]
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
    )
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, "the dropped cost event must be visible at LOG_LEVEL=INFO"
    assert "cost_event_dropped_no_running_loop" in caplog.text
    assert _SVC in caplog.text


# --- credential redaction -------------------------------------------------
#
# METERING_REDIS_URL carries the cost-bus password. `init_metering_redis` used
# to log the raw URL at startup, so the credential was printed to stdout by
# every pod running this library and landed in the log aggregator in plaintext.
# The canary below is an obviously fake value; it must never reach a log record.
_LEAK_CANARY = "totally-fake-canary-value"


def test_redact_url_strips_every_credential_carrying_component():
    """Userinfo, query and fragment all go; host/port/db survive.

    The query string matters as much as the userinfo here:
    ``redis://host:6379/0?password=...`` is a legitimate redis-py URL form, so a
    redaction that only stripped ``user:pass@`` would still leak.
    """
    assert (
        metering._redact_url(f"redis://metering:{_LEAK_CANARY}@redis.example:6379/3")
        == "redis://redis.example:6379/3"
    )
    # Password-only userinfo (no username) — the common Redis shape.
    assert (
        metering._redact_url(f"rediss://:{_LEAK_CANARY}@redis.example:6380/0")
        == "rediss://redis.example:6380/0"
    )
    # Credential in the query string.
    assert (
        metering._redact_url(f"redis://redis.example:6379/0?password={_LEAK_CANARY}")
        == "redis://redis.example:6379/0"
    )
    # Fragment dropped too.
    assert (
        metering._redact_url(f"redis://redis.example:6379/0#{_LEAK_CANARY}")
        == "redis://redis.example:6379/0"
    )
    # IPv6 literal keeps its brackets, or the rebuilt netloc is ambiguous.
    assert metering._redact_url("redis://[fd00::1]:6379/1") == "redis://[fd00::1]:6379/1"
    # No port is fine.
    assert metering._redact_url("redis://redis.example/0") == "redis://redis.example/0"


def test_redact_url_fails_closed_on_anything_it_cannot_parse():
    """An unrecognised shape yields the placeholder, never the input.

    Failing OPEN here (echoing the input when parsing is uncertain) is exactly
    how a redactor leaks: the one URL shape it did not anticipate is the one it
    prints verbatim. So the guard errs toward redacting too much.
    """
    for hostile in (
        f"localhost:{_LEAK_CANARY}",  # no scheme -> no netloc -> nothing is parsed
        f"{_LEAK_CANARY}",  # not a URL at all
        f"redis://host:not-a-port/0?p={_LEAK_CANARY}",  # urlsplit.port raises
        f"//metering:{_LEAK_CANARY}@redis.example:6379/3",  # scheme-relative
    ):
        assert metering._redact_url(hostile) == "<redacted-url>", hostile
    # Empty in, empty out — metering-disabled is not an error to redact.
    assert metering._redact_url("") == ""


async def test_init_metering_redis_never_logs_the_password(monkeypatch, caplog):
    """The regression this whole change exists for.

    ``logger.info("Metering Redis connected: %s", url)`` printed the full
    METERING_REDIS_URL — password included — to pod stdout at startup, in every
    service that uses this library.

    Asserted against the emitted LogRecords rather than only ``caplog.text``:
    lazy ``%s`` logging keeps the argument in ``record.args``, so a structured
    (JSON) formatter would serialise it even if the rendered message somehow
    did not. Both halves have to be clean.
    """

    class _FakeClient:
        async def ping(self) -> bool:
            return True

    def _fake_from_url(url: str, **kwargs: object) -> _FakeClient:
        return _FakeClient()

    import redis.asyncio as aioredis

    monkeypatch.setattr(aioredis, "from_url", _fake_from_url)
    caplog.set_level(logging.DEBUG, logger="kag_common.metering")

    secret_url = f"redis://metering:{_LEAK_CANARY}@redis.example:6379/3"
    client = await metering.init_metering_redis(secret_url)
    assert client is not None

    assert _LEAK_CANARY not in caplog.text
    for record in caplog.records:
        assert _LEAK_CANARY not in record.getMessage()
        assert _LEAK_CANARY not in repr(record.args)

    # ...and the line is still worth having: host, port and db index survive.
    assert "redis://redis.example:6379/3" in caplog.text


# ── The dropped cost event is COUNTED, not merely logged ──────────────────────
#
# ``emit_cost_event`` is contracted never to raise, so a failed XADD leaves the
# request succeeding and the spend simply absent from the ledger. Until now the
# only trace was a ``logger.warning``, and nothing can alert on a log line. This
# is the SHARED emitter for the whole kag lineage, so one cost-bus blip drops
# every consuming service's spend at once — the counter is the only instrument
# that can see it.


def _emit_failed_value(service: str, error_type: str) -> float:
    return metrics.cost_event_emit_failed_total.labels(
        service=service, error_type=error_type
    )._value.get()


@pytest.fixture
def _reset_emit_failed_counter():
    metrics.cost_event_emit_failed_total.clear()
    yield
    metrics.cost_event_emit_failed_total.clear()


async def test_emit_failure_increments_the_counter_and_still_does_not_raise(
    _reset_emit_failed_counter,
):
    class _BrokenRedis:
        async def xadd(self, *a, **k):  # noqa: ANN002, ANN003
            raise RuntimeError("redis down")

    # The never-raises contract is unchanged — this is instrumentation only.
    await metering.emit_cost_event(
        _BrokenRedis(),  # type: ignore[arg-type]
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
    )

    # ``service`` is the emitting service, ``error_type`` the exception CLASS —
    # bounded cardinality, and it separates a cost-bus outage from a marshalling
    # bug in the emitter itself.
    assert _emit_failed_value(_SVC, "RuntimeError") == 1.0


async def test_emit_failure_still_warns(caplog, _reset_emit_failed_counter):
    """Counting REPLACES nothing: the warning that existed before is kept."""

    class _BrokenRedis:
        async def xadd(self, *a, **k):  # noqa: ANN002, ANN003
            raise RuntimeError("redis down")

    caplog.set_level(logging.WARNING, logger="kag_common.metering")
    await metering.emit_cost_event(
        _BrokenRedis(),  # type: ignore[arg-type]
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
    )

    assert "cost_event_emit_failed" in caplog.text
    assert _emit_failed_value(_SVC, "RuntimeError") == 1.0


async def test_exhausted_retries_count_the_dropped_event_not_each_attempt(
    monkeypatch, _reset_emit_failed_counter
):
    """A bounded retry is ONE lost cost event, so it must be ONE increment.

    The counter sits on the outer handler, past the retry loop. Were it inside
    the loop, a cost-bus outage would inflate the ledger-loss rate by the retry
    count and every alert threshold derived from it would be wrong.
    """
    from redis.exceptions import ConnectionError as RedisConnectionError

    monkeypatch.setenv("METERING_EMIT_RETRY_BACKOFFS", "0,0")
    attempts = 0

    class _FlappingRedis:
        async def xadd(self, *a, **k):  # noqa: ANN002, ANN003
            nonlocal attempts
            attempts += 1
            raise RedisConnectionError("cost bus unreachable")

    await metering.emit_cost_event(
        _FlappingRedis(),  # type: ignore[arg-type]
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
    )

    assert attempts == 3, "two backoffs plus the final attempt"
    assert _emit_failed_value(_SVC, "ConnectionError") == 1.0


# ── The NO-LOOP drop: counted, marked, and reconstructible ────────────────────
#
# Called with no running event loop, ``schedule_cost_event`` used to close the
# orphaned coroutine, log a WARNING, and ``return``. The WARNING half was already
# fixed. Two halves were not: there was NO COUNTER (a log line is greppable, not
# queryable, and nothing can alert on it) and NO RETURN MARKER (``None`` on the
# drop path AND on the success path, so a caller could not tell them apart).
#
# By the time this function runs the provider call has already cost money, so a
# dropped cost event is unrecoverable revenue evidence.


def _no_loop_value(service: str = _SVC) -> float:
    return _emit_failed_value(service, metering.NO_LOOP_ERROR_TYPE)


def _schedule_in_sync_frame(**overrides):
    """Call ``schedule_cost_event`` from a frame with no running event loop."""
    kwargs = {
        "service_key": _SVC,
        "cost_source": "self_hosted",
        "tenant_id": "tenant-1",
        "provider": "webscraper",
        "model": "gpt-oss-120b",
        "input_tokens": 11,
        "output_tokens": 22,
        "latency_ms": 33,
        "license_id": "lic-1",
        "subject_id": "sub-1",
        "app_id": "app-1",
        "served_model": "gpt-oss-120b-mlx",
        "cost_usd": 0.0,
        "provider_request_id": "req-1",
    }
    kwargs.update(overrides)
    return metering.schedule_cost_event(object(), **kwargs)  # type: ignore[arg-type]


def test_no_loop_drop_increments_the_existing_counter(_reset_emit_failed_counter):
    """⭐ A fourth value on the EXISTING series, not a new metric.

    Both values of ``error_type`` on ``kag_cost_event_emit_failed_total`` mean the
    same thing to an operator — a billable request whose ledger row does not
    exist. A separate metric would mean every dashboard has to remember to sum
    two series, and the rarer one is the one that gets forgotten.
    """
    assert _no_loop_value() == 0.0
    _schedule_in_sync_frame()
    assert _no_loop_value() == 1.0
    # The transport-failure value on the same series is untouched: this is a new
    # LABEL VALUE, not a re-purposing of an existing one.
    assert _emit_failed_value(_SVC, "ConnectionError") == 0.0


def test_no_loop_drop_returns_false_the_positive_marker(_reset_emit_failed_counter):
    """``False`` is a POSITIVE marker: before this, both paths returned ``None``."""
    assert _schedule_in_sync_frame() is False


async def test_handoff_to_a_running_loop_returns_true(redis_conn, _reset_emit_failed_counter):
    """The other half of the marker — and it must not touch the drop counter."""
    handed_off = metering.schedule_cost_event(
        redis_conn,
        service_key=_SVC,
        cost_source="self_hosted",
        tenant_id="tenant-1",
        provider="webscraper",
        model="",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
    )
    assert handed_off is True
    await metering.drain_pending(timeout=2.0)
    assert _no_loop_value() == 0.0


def test_no_loop_warning_carries_every_field_billing_needs(caplog, _reset_emit_failed_counter):
    """The log line IS the durable record — there is no replay behind it.

    Asserted field by field rather than against one long string, so a future edit
    that drops a single field reddens here and names WHICH one.
    """
    caplog.set_level(logging.WARNING, logger="kag_common.metering")
    _schedule_in_sync_frame()

    text = caplog.text
    assert "cost_event_dropped_no_running_loop" in text
    for needle in (
        f"service_key={_SVC}",
        "cost_source=self_hosted",
        "tenant_id=tenant-1",
        "license_id=lic-1",
        "subject_id=sub-1",
        "app_id=app-1",
        "provider=webscraper",
        "model=gpt-oss-120b",
        "served_model=gpt-oss-120b-mlx",
        "input_tokens=11",
        "output_tokens=22",
        "latency_ms=33",
        "cost_usd=0.0",
        "provider_request_id=req-1",
    ):
        assert needle in text, f"the durable record lost {needle!r}"


def test_no_loop_warning_renders_a_non_finite_cost_verbatim(caplog, _reset_emit_failed_counter):
    """⛔ ``nan`` must NOT be coerced to a plausible ``0.00000000``.

    This line is the only record of the row; a coerced zero is indistinguishable
    from a genuine zero-cost call, so it would be a FABRICATED figure in the one
    place a human goes to adjudicate. The sibling w2v_common fix left that
    coercion in and marked it a known gap; ``%r`` avoids inheriting it.
    """
    caplog.set_level(logging.WARNING, logger="kag_common.metering")
    _schedule_in_sync_frame(cost_usd=float("nan"))
    assert "cost_usd=nan" in caplog.text
    assert "cost_usd=0" not in caplog.text


def test_no_loop_warning_does_not_floor_a_sub_cent_cost_to_zero(caplog, _reset_emit_failed_counter):
    """⛔ The OTHER way to fabricate a zero, and it needs no guard to do it.

    ``%.8f`` renders ``1e-12`` as ``0.00000000``. That is a fabricated figure
    produced by FORMATTING alone, in the one line that exists to be the durable
    record — and unlike the ``isfinite`` coercion there is no conditional in the
    source to point at afterwards.
    """
    caplog.set_level(logging.WARNING, logger="kag_common.metering")
    _schedule_in_sync_frame(cost_usd=1e-12)
    assert "cost_usd=1e-12" in caplog.text


def test_no_loop_never_constructs_the_coroutine_it_cannot_schedule(
    monkeypatch, _reset_emit_failed_counter
):
    """The loop is resolved BEFORE the coroutine is built.

    The old order built the coroutine, then had to ``coro.close()`` it to silence
    a "coroutine was never awaited" warning. Not creating it makes that class
    UNREACHABLE rather than merely handled.
    """
    called = False

    def _tripwire(*a, **k):  # noqa: ANN002, ANN003
        nonlocal called
        called = True
        raise AssertionError("emit_cost_event must not be entered with no loop")

    monkeypatch.setattr(metering, "emit_cost_event", _tripwire)
    assert _schedule_in_sync_frame() is False
    assert called is False


def test_no_loop_drop_does_not_raise_by_default(monkeypatch, _reset_emit_failed_counter):
    """⛔ RECORD DURABLY, THEN CONTINUE. The raise is opt-in and stays opt-in.

    The provider call has already happened and already cost money by the time
    this runs, so raising by default would forfeit the revenue as well as the
    evidence.
    """
    monkeypatch.delenv("METERING_REQUIRE_LOOP", raising=False)
    assert metering.require_loop() is False
    assert _schedule_in_sync_frame() is False


def test_require_loop_escalates_the_drop_to_a_raise(monkeypatch, _reset_emit_failed_counter):
    monkeypatch.setenv("METERING_REQUIRE_LOOP", "true")
    assert metering.require_loop() is True
    with pytest.raises(metering.NoRunningLoopError) as excinfo:
        _schedule_in_sync_frame()
    assert _SVC in str(excinfo.value)
    assert "self_hosted" in str(excinfo.value)


def test_escalation_counts_the_drop_before_it_raises(monkeypatch, _reset_emit_failed_counter):
    """⭐ Ordering, not decoration.

    A raise placed before the increment would mean that turning the escalation on
    BLINDS the very metric that measures the problem it escalates — one silence
    traded for another.
    """
    monkeypatch.setenv("METERING_REQUIRE_LOOP", "1")
    with pytest.raises(metering.NoRunningLoopError):
        _schedule_in_sync_frame()
    assert _no_loop_value() == 1.0


def test_escalation_also_logs_before_it_raises(monkeypatch, caplog, _reset_emit_failed_counter):
    """The durable record survives the escalation too, for the same reason."""
    monkeypatch.setenv("METERING_REQUIRE_LOOP", "yes")
    caplog.set_level(logging.WARNING, logger="kag_common.metering")
    with pytest.raises(metering.NoRunningLoopError):
        _schedule_in_sync_frame()
    assert "cost_event_dropped_no_running_loop" in caplog.text


def test_no_running_loop_error_is_a_runtime_error():
    """⚠️ Deliberate, and it cuts both ways — the consumer table depends on it.

    ``asyncio.get_running_loop()`` raises ``RuntimeError`` for this condition, so
    a caller already guarding the sync/async boundary with ``except RuntimeError``
    keeps working. The same inheritance means such a caller CONVERTS the
    escalation instead of letting it escape. In w2v_common that silently defeated
    the flag on 5 of 10 paths, which is why this PR derives the per-path fate
    rather than asserting "the flag reddens the build".
    """
    assert issubclass(metering.NoRunningLoopError, RuntimeError)


def test_no_loop_label_value_is_the_class_name(monkeypatch, _reset_emit_failed_counter):
    """The label must not move when the escalation flag does.

    A series recorded in staging-with-escalation and one recorded in
    production-without have to be THE SAME SERIES, or the staging tripwire and
    the production alert are measuring different things.
    """
    assert metering.NO_LOOP_ERROR_TYPE == metering.NoRunningLoopError.__name__

    monkeypatch.delenv("METERING_REQUIRE_LOOP", raising=False)
    _schedule_in_sync_frame()
    monkeypatch.setenv("METERING_REQUIRE_LOOP", "true")
    with pytest.raises(metering.NoRunningLoopError):
        _schedule_in_sync_frame()
    assert _no_loop_value() == 2.0


def test_tenant_validation_still_precedes_the_no_loop_drop(_reset_emit_failed_counter):
    """An unusable tenant is the ONE deliberate raise, and it still wins.

    Otherwise a missing tenant in a sync frame would be recorded as a no-loop
    drop and the caller bug would be filed under the wrong cause.
    """
    with pytest.raises(MissingTenantError):
        _schedule_in_sync_frame(tenant_id="")
    assert _no_loop_value() == 0.0
