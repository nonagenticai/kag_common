"""Structured logging with OpenTelemetry trace correlation.

Single source of truth for the structlog setup that every KAG backend used to
hand-roll. Each service used a near-identical ``configure_logging`` /
``get_logger`` pair; the small divergences (service-name default, which noisy
loggers to silence, whether to filter ``/health`` out of the uvicorn access
log) are surfaced here as parameters so each service keeps a one-line shim that
calls into this module with its own values.
"""

from __future__ import annotations

import logging
import os
import sys
import types
from collections.abc import MutableMapping, Sequence
from typing import Any

import structlog

# OpenTelemetry is an optional runtime dependency: trace correlation is added
# when it is importable, and silently skipped otherwise.
OTEL_AVAILABLE = False
trace: types.ModuleType | None = None
try:
    from opentelemetry import trace

    OTEL_AVAILABLE = True
except ImportError:
    pass

DEFAULT_SUPPRESS_LOGGERS: tuple[str, ...] = ("httpx", "httpcore", "uvicorn.access", "urllib3")

_default_service_name = "kag-service"
_configured = False
# The single root handler installed by ``configure_logging``. Tracked so
# ``_reset_for_tests`` can detach exactly what we attached instead of wiping
# root (which would take pytest's own capture handler with it).
_installed_handler: logging.Handler | None = None


def add_trace_context(
    logger: Any, method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Inject OpenTelemetry trace context into structured logs."""
    if OTEL_AVAILABLE and trace:
        span = trace.get_current_span()
        if span and span.is_recording():
            ctx = span.get_span_context()
            if ctx.is_valid:
                event_dict["trace_id"] = format(ctx.trace_id, "032x")
                event_dict["span_id"] = format(ctx.span_id, "016x")
    return event_dict


def add_service_context(
    logger: Any, method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Add service metadata to logs.

    ``OTEL_SERVICE_NAME`` always wins; the per-service default set via
    ``configure_logging(service_name=...)`` is only the dev/test fallback.
    """
    event_dict["service"] = os.getenv("OTEL_SERVICE_NAME", _default_service_name)
    event_dict["environment"] = os.getenv("ENVIRONMENT", "development")
    return event_dict


class _HealthFilter(logging.Filter):
    """Drop uvicorn access-log records for ``/health`` probes."""

    def filter(self, record: logging.LogRecord) -> bool:
        return "/health" not in record.getMessage()


def configure_logging(
    level: int | None = None,
    log_file: str | None = None,
    *,
    service_name: str = "kag-service",
    suppress_loggers: Sequence[str] = DEFAULT_SUPPRESS_LOGGERS,
    filter_health_access: bool = False,
) -> None:
    """Configure structured JSON logging with trace context (idempotent).

    Args:
        level: Logging level (defaults to INFO or the ``LOG_LEVEL`` env var).
        log_file: Accepted for call-site back-compat; ignored (structlog logs
            to stdout).
        service_name: Dev/test fallback for the ``service`` field when
            ``OTEL_SERVICE_NAME`` is unset.
        suppress_loggers: Logger names forced to WARNING to cut noise.
        filter_health_access: When True, attach a filter that drops
            ``/health`` lines from ``uvicorn.access`` (leave that logger out of
            ``suppress_loggers`` to keep request visibility).
    """
    global _configured, _default_service_name, _installed_handler

    if _configured:
        return

    _default_service_name = service_name

    log_format = os.getenv("LOG_FORMAT", "json").lower()
    log_level = level or getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper())

    # Context processors shared by BOTH entry points. They are what makes a
    # line queryable (`level`, `timestamp`, `service`, `logger`, trace ids), so
    # a stdlib record and a structlog event must run the same set.
    context_processors: list[Any] = [
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        add_service_context,
        add_trace_context,
        structlog.processors.StackInfoRenderer(),
        # format_exc_info belongs in BOTH chains, and in NEITHER renderer.
        # ProcessorFormatter does NOT render a foreign record's ``exc_info``
        # itself: it copies the raw ``(type, exc, tb)`` tuple into the event
        # dict and unsets ``record.exc_info`` (keep_exc_info=False), so the
        # base logging.Formatter never appends a traceback either. Drop this
        # processor and a `logger.exception()` traceback is not doubled — it is
        # LOST, replaced by a repr'd tuple. Verified empirically, not assumed.
        structlog.processors.format_exc_info,
    ]

    renderer: Any = (
        structlog.processors.JSONRenderer()
        if log_format == "json"
        else structlog.dev.ConsoleRenderer()  # human-readable dev format
    )

    # ── structlog chain ───────────────────────────────────────────────────
    # Ends at wrap_for_formatter, NOT at the renderer. Putting the renderer
    # here too does not merely double-encode: the stdlib record's ``msg``
    # becomes a str, ProcessorFormatter.format() raises
    # ``AttributeError: 'str' object has no attribute 'copy'``, and logging
    # swallows it via handleError — every structlog line silently disappears.
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            *context_processors,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.UnicodeDecoder(),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # ── handler chain ─────────────────────────────────────────────────────
    # ``foreign_pre_chain`` is the whole point of this module: it is the ONLY
    # thing that gives a plain ``logging.getLogger(__name__)`` record a level,
    # a timestamp and a service. Consumers use stdlib loggers in the large
    # majority of their modules; before this, those lines rendered as a bare
    # message and were invisible to both a JSON ``"level":"error"`` query and a
    # literal ``ERROR`` grep.
    #
    # PositionalArgumentsFormatter is deliberately absent here: ProcessorFormatter
    # already interpolates ``%``-style stdlib calls via ``record.getMessage()``.
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=context_processors,
        processor=renderer,  # structlog prepends remove_processors_meta for us
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    # NOT logging.basicConfig(): it is a silent no-op the moment root already
    # has ANY handler, and it would then leave every line on whatever plaintext
    # formatter got there first.
    #
    # Measured, so the claim is not larger than the evidence: bare uvicorn
    # 0.52.3 does NOT touch root (its LOGGING_CONFIG names only uvicorn.*), so
    # uvicorn alone is not the trigger. The reachable triggers are anything that
    # installs a root handler before this runs — a consumer's own
    # ``logging.basicConfig`` (nlp_service, kag_graph_service and
    # scientific_processor each still hand-roll one), a bare module-level
    # ``logging.warning()`` (which calls basicConfig implicitly), gunicorn,
    # Celery's logging setup, or pytest's capture plugin. Replacing
    # unconditionally makes this module's output independent of that ordering.
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(log_level)
    _installed_handler = handler

    for logger_name in suppress_loggers:
        logging.getLogger(logger_name).setLevel(logging.WARNING)

    if filter_health_access:
        logging.getLogger("uvicorn.access").addFilter(_HealthFilter())

    _configured = True


def get_logger(
    name: str | None = None, *, service_name: str = "kag-service"
) -> structlog.stdlib.BoundLogger:
    """Return a module-level structured logger, configuring logging on first use."""
    configure_logging(service_name=service_name)
    logger: Any = structlog.get_logger(name or service_name)
    return logger


def _reset_for_tests() -> None:
    """Reset the idempotency latch, structlog defaults and our root handler.

    For test use only. ``cache_logger_on_first_use=True`` means a bound logger
    fetched before a reconfigure keeps the old chain, so the structlog defaults
    have to be reset too — the latch alone is not enough isolation once the
    renderer lives on the handler.
    """
    global _configured, _installed_handler
    _configured = False
    if _installed_handler is not None:
        logging.getLogger().removeHandler(_installed_handler)
        _installed_handler = None
    structlog.reset_defaults()
