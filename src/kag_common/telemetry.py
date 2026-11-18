"""OpenTelemetry setup with graceful degradation.

Single source of truth for the OTEL tracing initialization every KAG backend
used to hand-roll. The structure is byte-identical across services; the only
divergences — which framework instrumentors to enable, and whether to fall back
to a default OTLP endpoint when the env var is unset — are surfaced as
parameters so each service keeps a one-line shim.

The framework instrumentation packages (FastAPI/HTTPX/Redis/SQLAlchemy) are
imported lazily, per requested instrumentor, so a consumer only needs the
instrumentation wheels it actually asks for.
"""

from __future__ import annotations

import logging
import os
import socket
from collections.abc import Sequence
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_INSTRUMENTORS: tuple[str, ...] = ("fastapi", "httpx")

_initialized: bool = False


def _test_connection(host: str, port: int, timeout: float = 2.0) -> bool:
    """Test if the OTLP endpoint is reachable."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except TimeoutError, ConnectionRefusedError, OSError:
        return False


def _apply_instrumentor(name: str, app: Any) -> None:
    """Enable a single framework instrumentor, guarded against import/runtime errors."""
    try:
        if name == "fastapi":
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

            FastAPIInstrumentor.instrument_app(app)
        elif name == "httpx":
            from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

            HTTPXClientInstrumentor().instrument()
        elif name == "redis":
            from opentelemetry.instrumentation.redis import RedisInstrumentor

            RedisInstrumentor().instrument()
        elif name == "sqlalchemy":
            from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

            SQLAlchemyInstrumentor().instrument()
        else:
            logger.warning(f"Unknown OTEL instrumentor requested: {name}")
            return
        logger.info(f"{name} instrumentation enabled")
    except (ImportError, RuntimeError) as e:
        logger.warning(f"{name} instrumentation failed: {e}")


def setup_telemetry(
    app: Any,
    service_name: str,
    *,
    instrumentors: Sequence[str] = DEFAULT_INSTRUMENTORS,
    otlp_endpoint_default: str | None = None,
) -> bool:
    """Initialize OpenTelemetry with graceful degradation (idempotent).

    Args:
        app: ASGI application instance (passed to the FastAPI instrumentor).
        service_name: Name to identify this service in traces.
        instrumentors: Framework instrumentors to enable. Valid names:
            ``fastapi``, ``httpx``, ``redis``, ``sqlalchemy``.
        otlp_endpoint_default: Fallback OTLP traces endpoint used when
            ``OTLP_TRACES_ENDPOINT`` is unset. ``None`` means "no fallback —
            disable the exporter when the env var is unset".

    Returns:
        True if OTEL was initialized, False if it was disabled/unavailable.
    """
    global _initialized

    if _initialized:
        return True

    if os.getenv("OTEL_SDK_DISABLED", "false").lower() == "true":
        logger.info("OTEL SDK disabled via environment variable")
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as e:
        logger.warning(f"OTEL packages not available: {e}")
        return False

    resource = Resource.create({SERVICE_NAME: service_name})
    provider = TracerProvider(resource=resource)

    otlp_endpoint = os.getenv("OTLP_TRACES_ENDPOINT", "") or (otlp_endpoint_default or "")
    if not otlp_endpoint:
        logger.info("OTLP_TRACES_ENDPOINT not set, OTEL exporter disabled")
        return False

    try:
        from urllib.parse import urlparse

        parsed = urlparse(otlp_endpoint.replace("/v1/traces", ""))
        host = parsed.hostname or "alloy"
        port = parsed.port or 4318

        if _test_connection(host, port):
            exporter = OTLPSpanExporter(endpoint=otlp_endpoint, timeout=5)
            processor = BatchSpanProcessor(
                exporter,
                max_queue_size=2048,
                schedule_delay_millis=5000,
                max_export_batch_size=512,
                export_timeout_millis=30000,
            )
            provider.add_span_processor(processor)
            logger.info(f"OTEL exporter configured: {otlp_endpoint}")
        else:
            logger.warning(f"OTLP endpoint not reachable: {host}:{port}, tracing disabled")
    except (ValueError, OSError) as e:
        logger.warning(f"Failed to configure OTEL exporter: {e}")

    trace.set_tracer_provider(provider)

    for name in instrumentors:
        _apply_instrumentor(name, app)

    _initialized = True
    return True


def _reset_for_tests() -> None:
    """Reset the module-level idempotency latch. For test use only."""
    global _initialized
    _initialized = False
