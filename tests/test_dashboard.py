"""The live dashboard page is served without the API key (it holds no secrets), while the data endpoints it
calls (/status, /stats) stay behind the key. This is what lets a browser open /dashboard yet keeps the proxy
list from leaking to anyone who can reach the port without the key."""
from __future__ import annotations

import asyncio

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer


def _app(api, key):
    app = web.Application(middlewares=[api.cors_middleware, api.api_key_middleware])
    app["api_key"] = key
    app["cors_origin"] = "*"
    app.router.add_get("/dashboard", api.handle_dashboard)
    app.router.add_get("/health", lambda r: web.json_response({"ok": True}))

    async def status(request):
        return web.json_response({"ok": True, "active_proxies": 7})

    app.router.add_get("/status", status)
    return app


def _get(api, path, headers=None, key="secret123"):
    """Fresh app per call — an aiohttp Application can only be run once."""
    async def run():
        async with TestClient(TestServer(_app(api, key))) as client:
            response = await client.get(path, headers=headers or {})
            return response.status, response.headers.get("Content-Type", ""), await response.text()

    return asyncio.run(run())


def test_dashboard_page_is_served_without_the_api_key_and_is_html(api):
    status, ctype, body = _get(api, "/dashboard")
    assert status == 200 and "text/html" in ctype
    assert "<title>Proxy Pool" in body and "secret123" not in body, "the page must not embed the key"


def test_the_data_endpoints_the_dashboard_calls_still_require_the_key(api):
    assert _get(api, "/status")[0] == 401
    assert _get(api, "/status", {"X-API-Key": "secret123"})[0] == 200


def test_health_also_stays_exempt_so_the_exemption_list_was_not_broken(api):
    assert _get(api, "/health")[0] == 200
