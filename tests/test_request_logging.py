"""Tests for the shared RequestLoggingMiddleware."""

from __future__ import annotations

import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from kag_common.middleware import RequestIdMiddleware, RequestLoggingMiddleware


def _build_app(*, with_request_id: bool) -> Starlette:
    async def echo(request):
        return JSONResponse({"request_id": getattr(request.state, "request_id", None)})

    async def health(request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/echo", echo), Route("/health", health)])
    # RequestLoggingMiddleware added first runs *outer*; add RequestId after so
    # it runs before the logger and populates request.state.request_id.
    app.add_middleware(RequestLoggingMiddleware)
    if with_request_id:
        app.add_middleware(RequestIdMiddleware)
    return app


async def _client(app: Starlette) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_stamps_headers_and_reuses_request_id():
    async with await _client(_build_app(with_request_id=True)) as client:
        resp = await client.get("/echo", headers={"X-Request-ID": "caller-123"})
    assert resp.status_code == 200
    assert resp.headers["X-Request-ID"] == "caller-123"
    assert resp.json()["request_id"] == "caller-123"
    assert resp.headers["X-Processing-Time"].endswith("ms")


@pytest.mark.asyncio
async def test_mints_request_id_when_middleware_absent():
    async with await _client(_build_app(with_request_id=False)) as client:
        resp = await client.get("/echo")
    assert resp.status_code == 200
    minted = resp.headers["X-Request-ID"]
    assert minted
    assert resp.json()["request_id"] == minted


@pytest.mark.asyncio
async def test_skips_health_path():
    async with await _client(_build_app(with_request_id=True)) as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    # Skip paths bypass logging + header stamping entirely.
    assert "X-Processing-Time" not in resp.headers
