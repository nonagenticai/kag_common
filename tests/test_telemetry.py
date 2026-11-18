"""Tests for the shared setup_telemetry helper."""

from __future__ import annotations

import pytest

from kag_common import telemetry


@pytest.fixture(autouse=True)
def _reset_latch():
    telemetry._reset_for_tests()
    yield
    telemetry._reset_for_tests()


def test_disabled_via_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OTEL_SDK_DISABLED", "true")
    assert telemetry.setup_telemetry(None, "svc") is False


def test_no_endpoint_and_no_default_disables_exporter(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("OTEL_TRACES_ENDPOINT", raising=False)
    monkeypatch.delenv("OTLP_TRACES_ENDPOINT", raising=False)
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    assert telemetry.setup_telemetry(None, "svc", otlp_endpoint_default=None) is False


def test_unreachable_endpoint_still_initializes(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("OTLP_TRACES_ENDPOINT", raising=False)
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    # Discard port 9 is unreachable → exporter is skipped but the provider is
    # still set and instrumentation runs, so the call reports success.
    ok = telemetry.setup_telemetry(
        None,
        "svc",
        instrumentors=("httpx",),  # instrumentation wheel absent here → guarded no-op
        otlp_endpoint_default="http://127.0.0.1:9/v1/traces",
    )
    assert ok is True
    # Idempotent: a second call short-circuits on the latch.
    assert telemetry.setup_telemetry(None, "svc") is True


def test_unknown_instrumentor_is_warned_not_raised():
    telemetry._apply_instrumentor("does-not-exist", None)  # must not raise
