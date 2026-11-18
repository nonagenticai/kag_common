"""Tests for the shared prom counter helpers."""

from __future__ import annotations

import pytest

from kag_common import metrics


@pytest.fixture(autouse=True)
def _reset_counters():
    for counter in (
        metrics.tenant_id_required_total,
        metrics.dual_write_total,
        metrics.stage_degraded_total,
        metrics.phi_access_audit_failures_total,
        metrics.cost_event_emit_failed_total,
    ):
        for sample in list(counter.collect()):
            for s in sample.samples:
                counter.clear()
                break
    yield


def _value(counter, **labels) -> float:
    return counter.labels(**labels)._value.get()


def test_record_tenant_id_required_increments_per_service():
    metrics.record_tenant_id_required("kag_graph_service")
    metrics.record_tenant_id_required("kag_graph_service")
    metrics.record_tenant_id_required("kag_orchestrator")

    assert _value(metrics.tenant_id_required_total, service="kag_graph_service") == 2.0
    assert _value(metrics.tenant_id_required_total, service="kag_orchestrator") == 1.0


def test_record_dual_write_carries_all_three_labels():
    metrics.record_dual_write("hirag_service", "tenant-a", "succeeded")
    metrics.record_dual_write("hirag_service", "tenant-a", "failed")
    metrics.record_dual_write("hirag_service", "tenant-b", "succeeded")

    assert (
        _value(
            metrics.dual_write_total,
            service="hirag_service",
            tenant="tenant-a",
            outcome="succeeded",
        )
        == 1.0
    )
    assert (
        _value(
            metrics.dual_write_total,
            service="hirag_service",
            tenant="tenant-a",
            outcome="failed",
        )
        == 1.0
    )


def test_record_stage_degraded_tags_tenant_and_stage():
    metrics.record_stage_degraded("kag_orchestrator", "tenant-a", "karma")
    metrics.record_stage_degraded("kag_orchestrator", "tenant-a", "karma")
    metrics.record_stage_degraded("kag_orchestrator", "tenant-a", "hirag")

    assert (
        _value(
            metrics.stage_degraded_total,
            service="kag_orchestrator",
            tenant="tenant-a",
            stage="karma",
        )
        == 2.0
    )
    assert (
        _value(
            metrics.stage_degraded_total,
            service="kag_orchestrator",
            tenant="tenant-a",
            stage="hirag",
        )
        == 1.0
    )


def test_empty_tenant_falls_back_to_unknown():
    metrics.record_dual_write("hirag_service", "", "skipped")
    metrics.record_stage_degraded("kag_orchestrator", "", "karma")

    assert (
        _value(
            metrics.dual_write_total,
            service="hirag_service",
            tenant="unknown",
            outcome="skipped",
        )
        == 1.0
    )
    assert (
        _value(
            metrics.stage_degraded_total,
            service="kag_orchestrator",
            tenant="unknown",
            stage="karma",
        )
        == 1.0
    )


def test_record_phi_audit_failure_tags_service_and_action():
    metrics.record_phi_audit_failure("kag_graph_service", "chunks.search.dense")
    metrics.record_phi_audit_failure("kag_graph_service", "chunks.search.dense")
    metrics.record_phi_audit_failure("kag_graph_service", "chunks.by_ids")

    assert (
        _value(
            metrics.phi_access_audit_failures_total,
            service="kag_graph_service",
            action="chunks.search.dense",
        )
        == 2.0
    )
    assert (
        _value(
            metrics.phi_access_audit_failures_total,
            service="kag_graph_service",
            action="chunks.by_ids",
        )
        == 1.0
    )


def test_record_phi_audit_failure_empty_falls_back_to_unknown():
    metrics.record_phi_audit_failure("", "")
    assert (
        _value(metrics.phi_access_audit_failures_total, service="unknown", action="unknown") == 1.0
    )


def test_make_metrics_app_returns_asgi_callable():
    app = metrics.make_metrics_app()
    assert callable(app)


def test_record_cost_event_emit_failed_tags_service_and_error_type():
    metrics.record_cost_event_emit_failed("ingestion", "ConnectionError")
    metrics.record_cost_event_emit_failed("ingestion", "ConnectionError")
    metrics.record_cost_event_emit_failed("kag_graph_service", "TimeoutError")

    assert (
        _value(
            metrics.cost_event_emit_failed_total,
            service="ingestion",
            error_type="ConnectionError",
        )
        == 2.0
    )
    assert (
        _value(
            metrics.cost_event_emit_failed_total,
            service="kag_graph_service",
            error_type="TimeoutError",
        )
        == 1.0
    )


def test_record_cost_event_emit_failed_empty_falls_back_to_unknown():
    metrics.record_cost_event_emit_failed("", "")
    assert (
        _value(metrics.cost_event_emit_failed_total, service="unknown", error_type="unknown") == 1.0
    )
