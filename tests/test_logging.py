"""Tests for the shared structlog configuration."""

from __future__ import annotations

import json
import logging
from typing import Any
from unittest.mock import MagicMock

import pytest
import structlog

from kag_common import logging as kclog

# Every line a consumer can query on. This is the product requirement — not
# "the line is JSON", but "the line answers level/when/who/what".
QUERYABLE_FIELDS = {"level", "event", "timestamp", "service", "logger"}


@pytest.fixture(autouse=True)
def _reset_logging():
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    kclog._reset_for_tests()
    yield
    kclog._reset_for_tests()
    # configure_logging deliberately REPLACES root's handlers; put back
    # whatever the surrounding process (pytest's own capture) had installed.
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)


def _emitted(capsys: pytest.CaptureFixture[str]) -> list[dict[str, Any]]:
    """Parse every line configure_logging wrote to stdout as JSON.

    Fails loudly on a non-JSON line so a regression that drops back to bare
    plaintext cannot pass as "no output".
    """
    out = capsys.readouterr().out
    lines = [ln for ln in out.strip().splitlines() if ln.strip()]
    assert lines, "nothing was written to stdout"
    parsed = []
    for ln in lines:
        try:
            parsed.append(json.loads(ln))
        except json.JSONDecodeError as exc:  # pragma: no cover - failure path
            pytest.fail(f"non-JSON log line {ln!r}: {exc}")
    return parsed


def test_configure_logging_is_idempotent():
    kclog.configure_logging(service_name="svc-a")
    # Second call with a different name must be a no-op (latch held).
    kclog.configure_logging(service_name="svc-b")
    assert kclog._default_service_name == "svc-a"


def test_add_service_context_uses_default(monkeypatch):
    monkeypatch.delenv("OTEL_SERVICE_NAME", raising=False)
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    kclog.configure_logging(service_name="karma-service")
    event = kclog.add_service_context(None, "info", {})
    assert event["service"] == "karma-service"
    assert event["environment"] == "development"


def test_otel_service_name_env_wins(monkeypatch):
    monkeypatch.setenv("OTEL_SERVICE_NAME", "from-env")
    kclog.configure_logging(service_name="karma-service")
    event = kclog.add_service_context(None, "info", {})
    assert event["service"] == "from-env"


def test_add_trace_context_noop_without_span():
    # No active recording span in a bare test process → dict unchanged.
    out = kclog.add_trace_context(None, "info", {"k": "v"})
    assert out == {"k": "v"}


def test_filter_health_access_attaches_filter():
    kclog.configure_logging(
        service_name="kag-orchestrator",
        suppress_loggers=("httpx", "httpcore", "urllib3"),
        filter_health_access=True,
    )
    access = logging.getLogger("uvicorn.access")
    assert any(isinstance(f, kclog._HealthFilter) for f in access.filters)
    # The /health filter drops probe lines but keeps real requests.
    health_filter = next(f for f in access.filters if isinstance(f, kclog._HealthFilter))
    probe = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, "GET /health 200", None, None)
    real = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, "GET /api/jobs 200", None, None)
    assert health_filter.filter(probe) is False
    assert health_filter.filter(real) is True


def test_suppress_loggers_set_to_warning():
    kclog.configure_logging(service_name="ingestion-service", suppress_loggers=("celery",))
    assert logging.getLogger("celery").level == logging.WARNING


def test_get_logger_returns_bound_logger():
    logger = kclog.get_logger("my.module", service_name="hirag-service")
    assert logger is not None
    # structlog bound loggers expose .info/.error.
    assert hasattr(logger, "info")
    assert kclog._default_service_name == "hirag-service"


def test_configure_logging_console_format(monkeypatch):
    # LOG_FORMAT=console exercises the ConsoleRenderer processor branch.
    monkeypatch.setenv("LOG_FORMAT", "console")
    kclog.configure_logging(service_name="svc-console")
    # First call wins the idempotency latch.
    assert kclog._configured is True


def test_add_trace_context_injects_ids_for_valid_span(monkeypatch):
    mock_ctx = MagicMock()
    mock_ctx.is_valid = True
    mock_ctx.trace_id = 0xABCDEF0123456789
    mock_ctx.span_id = 0x1234567890ABCDEF

    mock_span = MagicMock()
    mock_span.is_recording.return_value = True
    mock_span.get_span_context.return_value = mock_ctx

    mock_trace = MagicMock()
    mock_trace.get_current_span.return_value = mock_span

    monkeypatch.setattr(kclog, "OTEL_AVAILABLE", True)
    monkeypatch.setattr(kclog, "trace", mock_trace)

    result = kclog.add_trace_context(None, "info", {"event": "test"})
    assert result["trace_id"] == format(mock_ctx.trace_id, "032x")
    assert result["span_id"] == format(mock_ctx.span_id, "016x")


def test_add_trace_context_noop_when_otel_unavailable(monkeypatch):
    monkeypatch.setattr(kclog, "OTEL_AVAILABLE", False)
    result = kclog.add_trace_context(None, "info", {"event": "test"})
    assert "trace_id" not in result


# ── ProcessorFormatter: stdlib records must be queryable ────────────────────
# The whole point of moving the renderer off the structlog chain and onto the
# handler. Consumers use `logging.getLogger(__name__)` in the large majority of
# their modules (karma: 24 stdlib vs 2 structlog); before this those lines
# printed a bare message with no level, no timestamp and no service, invisible
# to both a JSON `"level":"error"` query and a literal `ERROR` grep.


def test_stdlib_record_is_json_and_carries_a_level(capsys):
    kclog.configure_logging(service_name="karma-service", suppress_loggers=())
    logging.getLogger("plain.module").warning("plain")

    (line,) = _emitted(capsys)
    assert line["event"] == "plain"
    assert line["level"] == "warning"


def test_stdlib_percent_style_args_are_interpolated(capsys):
    kclog.configure_logging(service_name="karma-service", suppress_loggers=())
    logging.getLogger("plain.module").error("job %s failed after %d tries", "abc", 3)

    (line,) = _emitted(capsys)
    assert line["event"] == "job abc failed after 3 tries"
    assert "%s" not in line["event"]
    assert "%d" not in line["event"]


def test_structlog_output_is_not_double_encoded(capsys):
    kclog.configure_logging(service_name="karma-service", suppress_loggers=())
    kclog.get_logger("structlog.module").info("hi", extra_key="v")

    (line,) = _emitted(capsys)
    # A renderer left on BOTH the structlog chain and the handler yields either
    # a nested JSON string here or (with JSONRenderer) no line at all.
    assert line["event"] == "hi"
    assert not line["event"].startswith("{")
    assert line["extra_key"] == "v"
    # ProcessorFormatter's bookkeeping keys must not reach the log stream.
    assert "_record" not in line
    assert "_from_structlog" not in line


def test_stdlib_and_structlog_share_the_same_field_set(capsys):
    kclog.configure_logging(service_name="karma-service", suppress_loggers=())
    logging.getLogger("plain.module").info("from stdlib")
    kclog.get_logger("structlog.module").info("from structlog")

    std_line, sl_line = _emitted(capsys)
    assert QUERYABLE_FIELDS <= set(std_line), sorted(set(std_line))
    assert QUERYABLE_FIELDS <= set(sl_line), sorted(set(sl_line))
    assert std_line["service"] == sl_line["service"] == "karma-service"
    assert std_line["logger"] == "plain.module"
    assert sl_line["logger"] == "structlog.module"
    assert std_line["level"] == sl_line["level"] == "info"


def test_configure_logging_replaces_preexisting_root_handlers(capsys):
    # basicConfig() is a silent no-op once root has a handler — which is exactly
    # the state uvicorn/gunicorn leave root in. This is the failure that passes
    # in CI (clean root) and ships plaintext to production.
    dummy = logging.StreamHandler()
    dummy.setFormatter(logging.Formatter("DUMMY-SENTINEL %(message)s"))
    root = logging.getLogger()
    root.addHandler(dummy)

    kclog.configure_logging(service_name="karma-service", suppress_loggers=())

    assert dummy not in root.handlers, (
        "the pre-existing handler survived — basicConfig() no-opped and every "
        "line still goes through the plaintext formatter uvicorn left behind"
    )
    assert len(root.handlers) == 1
    assert root.handlers == [kclog._installed_handler]

    logging.getLogger("plain.module").warning("after-uvicorn")
    captured = capsys.readouterr()
    assert "DUMMY-SENTINEL" not in captured.out + captured.err
    line = json.loads(captured.out.strip())
    assert line["level"] == "warning"
    assert line["event"] == "after-uvicorn"


def test_stdlib_exception_renders_its_traceback_exactly_once(capsys):
    kclog.configure_logging(service_name="karma-service", suppress_loggers=())
    try:
        raise ValueError("boom-sentinel")
    except ValueError:
        logging.getLogger("plain.module").exception("handler blew up")

    out = capsys.readouterr().out
    assert out.count("Traceback (most recent call last)") == 1
    (line,) = [json.loads(ln) for ln in out.strip().splitlines() if ln.strip()]
    assert line["level"] == "error"
    assert line["event"] == "handler blew up"
    # Rendered into a string field, not left as a repr'd (type, exc, tb) tuple.
    assert "exc_info" not in line
    assert isinstance(line["exception"], str)
    assert line["exception"].count("Traceback (most recent call last)") == 1
    assert "ValueError: boom-sentinel" in line["exception"]


def test_structlog_exception_renders_its_traceback_exactly_once(capsys):
    kclog.configure_logging(service_name="karma-service", suppress_loggers=())
    try:
        raise ValueError("sl-boom-sentinel")
    except ValueError:
        kclog.get_logger("structlog.module").exception("sl blew up")

    out = capsys.readouterr().out
    assert out.count("Traceback (most recent call last)") == 1
    (line,) = [json.loads(ln) for ln in out.strip().splitlines() if ln.strip()]
    assert line["level"] == "error"
    assert line["exception"].count("Traceback (most recent call last)") == 1


def test_renderer_is_on_the_handler_not_the_structlog_chain():
    kclog.configure_logging(service_name="karma-service", suppress_loggers=())

    chain = structlog.get_config()["processors"]
    assert chain[-1] is structlog.stdlib.ProcessorFormatter.wrap_for_formatter
    assert not any(
        isinstance(p, structlog.processors.JSONRenderer | structlog.dev.ConsoleRenderer)
        for p in chain
    ), "a renderer left on the structlog chain double-renders and drops every structlog line"

    formatter = kclog._installed_handler.formatter
    assert isinstance(formatter, structlog.stdlib.ProcessorFormatter)
    assert isinstance(formatter.processors[-1], structlog.processors.JSONRenderer)


def test_console_format_still_reaches_the_handler(monkeypatch, capsys):
    monkeypatch.setenv("LOG_FORMAT", "console")
    kclog.configure_logging(service_name="svc-console", suppress_loggers=())
    logging.getLogger("plain.module").warning("console-line")

    out = capsys.readouterr().out
    # ConsoleRenderer output is not JSON, but the level must still be present —
    # the LOG_FORMAT=console branch goes through the same foreign_pre_chain.
    assert "console-line" in out
    assert "warning" in out.lower()
    formatter = kclog._installed_handler.formatter
    assert isinstance(formatter.processors[-1], structlog.dev.ConsoleRenderer)
