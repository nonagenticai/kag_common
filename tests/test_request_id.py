"""Tests for the shared RequestIdMiddleware."""

from __future__ import annotations

import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from kag_common.middleware import RequestIdMiddleware


def _build_app() -> Starlette:
    async def echo(request):
        return JSONResponse({"request_id": request.state.request_id})

    app = Starlette(routes=[Route("/echo", echo)])
    app.add_middleware(RequestIdMiddleware)
    return app


async def _client(app: Starlette) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_generates_request_id_when_absent():
    async with await _client(_build_app()) as client:
        resp = await client.get("/echo")
    assert resp.status_code == 200
    header_id = resp.headers["X-Request-ID"]
    assert header_id
    # Echoed header matches the id pinned to request.state.
    assert resp.json()["request_id"] == header_id


@pytest.mark.asyncio
async def test_preserves_incoming_request_id():
    async with await _client(_build_app()) as client:
        resp = await client.get("/echo", headers={"X-Request-ID": "caller-supplied-123"})
    assert resp.headers["X-Request-ID"] == "caller-supplied-123"
    assert resp.json()["request_id"] == "caller-supplied-123"


@pytest.mark.asyncio
async def test_blank_incoming_id_is_replaced():
    async with await _client(_build_app()) as client:
        resp = await client.get("/echo", headers={"X-Request-ID": "   "})
    # Whitespace-only header is stripped and a fresh id is minted.
    assert resp.headers["X-Request-ID"].strip()
    assert resp.headers["X-Request-ID"] != "   "
