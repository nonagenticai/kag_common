"""Request/response logging middleware.

Logs each request/response with timing, skips health/probe paths to avoid log
spam, and stamps ``X-Request-ID`` + ``X-Processing-Time`` on the response. The
request id is taken from ``request.state.request_id`` (set by
``RequestIdMiddleware``, which runs first) and falls back to a fresh uuid7 only
if that middleware was not wired in.

Shared across the KAG backends; each service used a near-identical copy.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response

logger: logging.Logger = logging.getLogger(__name__)

_SKIP_LOG_PATHS = frozenset({"/health", "/healthz", "/ready", "/readyz"})


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log requests/responses with timing and request-tracking headers."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in _SKIP_LOG_PATHS:
            return await call_next(request)

        request_id: str = getattr(request.state, "request_id", "") or str(uuid.uuid7())
        request.state.request_id = request_id
        start_time: float = time.time()
        logger.info(f"Request started: {request.method} {request.url.path} [{request_id}]")

        response: Response = await call_next(request)

        process_time: float = (time.time() - start_time) * 1000
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Processing-Time"] = f"{process_time:.2f}ms"
        logger.info(
            f"Request completed: {request.method} {request.url.path} "
            f"[{request_id}] - Status: {response.status_code} - "
            f"Time: {process_time:.2f}ms"
        )
        return response
