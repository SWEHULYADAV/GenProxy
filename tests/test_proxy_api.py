"""Proxy-api.py: block detection, SSRF guard, tunnel credentials / country pinning, auth and CORS middleware.

The HTTP tests run an in-process aiohttp server on a random loopback port; nothing here uses the service's
real ports (1712 / 1909) or the network."""
from __future__ import annotations

import argparse
import asyncio
import base64
import socket

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer


def _basic(user: str, password: str) -> dict[str, str]:
    return {"Proxy-Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}


# ---- block detection ------------------------------------------------------------------------------
@pytest.mark.parametrize("status", [403, 407, 429, 503, 521, 522, 523, 524])
def test_block_statuses_are_blocks_whatever_the_body(api, status):
    assert api._is_blocked_response(status, b"<html>fine</html>")


@pytest.mark.parametrize("marker", [b"captcha", b"CAPTCHA", b"cf-challenge", b"Access Denied", b"Please verify you are a human",
                                    b"checking your browser", b"Too Many Requests", b"You have been blocked"])
def test_block_page_markers_in_a_200_are_blocks(api, marker):
    assert api._is_blocked_response(200, b"<html><body>" + marker + b"</body></html>")


@pytest.mark.parametrize("status", [200, 201, 301, 302, 404, 500])
def test_ordinary_responses_are_not_blocks(api, status):
    assert not api._is_blocked_response(status, b"<html><title>Mumbai Indians jersey</title></html>")


# ---- small helpers ----------------------------------------------------------------------------------
@pytest.mark.parametrize("raw, expected", [
    ("1.2.3.4:80", "http://1.2.3.4:80"),
    ("http://1.2.3.4:80", "http://1.2.3.4:80"),
    ("https://1.2.3.4:80", "http://1.2.3.4:80"),
    ("SOCKS5://u:p@1.2.3.4:1080", "socks5://u:p@1.2.3.4:1080"),
    ("  socks4://1.2.3.4:1080 ", "socks4://1.2.3.4:1080"),
])
def test_parse_proxy_url(api, raw, expected):
    assert api.parse_proxy_url(raw) == expected


def test_parse_proxy_url_refuses_an_empty_string(api):
    with pytest.raises(ValueError):
        api.parse_proxy_url("   ")


def test_header_lookup_is_case_insensitive_because_curl_cffi_lowercases_names(api):
    assert api._header_get({"content-type": "text/html"}, "Content-Type") == "text/html"
    assert api._header_get({"X-A": "1"}, "x-a") == "1"
    assert api._header_get({}, "x", "dflt") == "dflt" and api._header_get(None, "x") == ""


def test_hop_by_hop_headers_are_dropped_in_both_directions(api):
    headers = {"Connection": "close", "Host": "x", "Content-Length": "9", "Transfer-Encoding": "chunked",
               "Proxy-Authorization": "Basic secret", "Accept": "text/html", "X-Custom": "1"}
    assert api.sanitize_outbound_headers(headers) == {"Accept": "text/html", "X-Custom": "1"}
    assert api.sanitize_inbound_response_headers(headers) == {"Accept": "text/html", "X-Custom": "1"}


def test_url_host_strips_www_and_survives_garbage(api):
    assert api._url_host("https://WWW.Example.com/x?y=1") == "example.com"
    assert api._url_host("not a url") == "" and api._url_host("") == ""


# ---- SSRF guard ---------------------------------------------------------------------------------------
@pytest.mark.parametrize("value, public", [
    ("8.8.8.8", True), ("1.1.1.1", True), ("2606:4700:4700::1111", True),
    ("127.0.0.1", False), ("10.1.2.3", False), ("172.16.0.1", False), ("192.168.0.1", False),
    ("169.254.169.254", False), ("100.64.0.1", False), ("0.0.0.0", False), ("::1", False), ("fe80::1", False),
    ("::ffff:127.0.0.1", False), ("not-an-ip", False),
])
def test_public_ip_check(api, value, public):
    assert api._is_public_ip_address(value) is public


def _resolving_to(*addresses):
    """Make the running loop's DNS answer with `addresses` (or fail when none are given)."""
    async def fake(host, port, **kwargs):
        if not addresses:
            raise OSError("no such host")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in addresses]
    asyncio.get_running_loop().getaddrinfo = fake


@pytest.mark.parametrize("host, public", [
    ("localhost", False), ("LOCALHOST.", False), ("api.localhost", False), ("", False), ("  ", False),
    ("127.0.0.1", False), ("169.254.169.254", False), ("8.8.8.8", True),
])
def test_target_host_literals_never_need_dns(api, host, public):
    assert asyncio.run(api.is_public_target_host(host)) is public


def test_a_hostname_is_public_only_when_every_address_it_resolves_to_is_public(api):
    async def scenario():
        _resolving_to("93.184.216.34")
        assert await api.is_public_target_host("shop.example") is True
        _resolving_to("93.184.216.34", "10.0.0.7")  # DNS rebinding style: one internal answer is enough to refuse
        assert await api.is_public_target_host("shop.example") is False
        _resolving_to("127.0.0.1")
        assert await api.is_public_target_host("shop.example") is False
        _resolving_to()  # does not resolve
        assert await api.is_public_target_host("shop.example") is False

    asyncio.run(scenario())


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://8.8.8.8/x", "javascript:alert(1)", "gopher://8.8.8.8/",
                                 "http:///nohost", "//8.8.8.8/x", "", "http://127.0.0.1:1712/status",
                                 "http://169.254.169.254/latest/meta-data/", "http://localhost/"])
def test_only_public_http_urls_are_valid_fetch_targets(api, url):
    assert asyncio.run(api.is_valid_target_url(url)) is False


def test_public_http_and_https_urls_are_valid_fetch_targets(api):
    assert asyncio.run(api.is_valid_target_url("https://8.8.8.8/x?y=1")) is True
    assert asyncio.run(api.is_valid_target_url("http://1.1.1.1/")) is True


# ---- tunnel credentials and country pinning ------------------------------------------------------------
@pytest.fixture()
def tunnel(api):
    return api.ProxyTunnel(service=None, auth_user="proxy", auth_key="s3cret")


@pytest.mark.parametrize("user, expected", [
    ("proxy", ("proxy", None)),
    ("PROXY", ("PROXY", None)),
    ("proxy-sg", ("proxy-sg", "SG")),
    ("Proxy-Sg", ("Proxy-Sg", "SG")),
    ("proxy-country-de", ("proxy-country-de", "DE")),
])
def test_tunnel_accepts_the_plain_user_and_country_pinned_users(tunnel, user, expected):
    assert tunnel._parse_credentials(_basic(user, "s3cret")) == expected


@pytest.mark.parametrize("user", ["proxy-", "proxy-s", "proxy-sgp", "proxy-s1", "proxy-country-", "proxy-country-d3",
                                  "other-sg", "proxysg", "sg", ""])
def test_tunnel_refuses_unknown_users_and_malformed_country_pins(tunnel, user):
    assert tunnel._parse_credentials(_basic(user, "s3cret")) is None


def test_tunnel_refuses_wrong_missing_and_malformed_credentials(tunnel):
    assert tunnel._parse_credentials(_basic("proxy", "wrong")) is None
    assert tunnel._parse_credentials(_basic("proxy", "")) is None
    assert tunnel._parse_credentials({}) is None
    assert tunnel._parse_credentials({"Proxy-Authorization": "Bearer abc"}) is None
    assert tunnel._parse_credentials({"Proxy-Authorization": "Basic !!!notbase64"}) is None
    assert tunnel._parse_credentials({"Proxy-Authorization": "Basic " + base64.b64encode(b"nocolon").decode()}) is None


def test_tunnel_header_name_is_case_insensitive_and_a_password_may_contain_colons(api):
    tunnel = api.ProxyTunnel(service=None, auth_user="proxy", auth_key="a:b:c")
    headers = {"proxy-authorization": _basic("proxy-in", "a:b:c")["Proxy-Authorization"]}
    assert tunnel._parse_credentials(headers) == ("proxy-in", "IN")


def test_a_tunnel_without_a_key_lets_everyone_in_without_a_pin(api):
    open_tunnel = api.ProxyTunnel(service=None, auth_user="proxy", auth_key="")
    assert open_tunnel._parse_credentials({}) == ("proxy", None)


# ---- startup safety ------------------------------------------------------------------------------------
def test_the_service_refuses_to_start_without_an_api_key(api):
    with pytest.raises(SystemExit):
        api.ensure_secure_runtime_args(argparse.Namespace(api_key="  ", tunnel_port=0, tunnel_api_key=""))


def test_an_enabled_tunnel_needs_its_own_key(api):
    with pytest.raises(SystemExit):
        api.ensure_secure_runtime_args(argparse.Namespace(api_key="k", tunnel_port=1909, tunnel_api_key=""))
    args = api.ensure_secure_runtime_args(argparse.Namespace(api_key=" k ", tunnel_port=1909, tunnel_api_key=" t "))
    assert (args.api_key, args.tunnel_api_key) == ("k", "t")
    api.ensure_secure_runtime_args(argparse.Namespace(api_key="k", tunnel_port=0, tunnel_api_key=""))


# ---- middleware over real (loopback) HTTP -----------------------------------------------------------------
def _app(api, api_key="topsecret", cors_origin=None):
    app = web.Application(middlewares=[api.cors_middleware, api.api_key_middleware])
    app["api_key"] = api_key
    if cors_origin:
        app["cors_origin"] = cors_origin

    async def ok(request):
        return web.json_response({"ok": True})

    app.router.add_get("/health", ok)
    app.router.add_get("/status", ok)
    return app


def _with_client(app, scenario):
    async def run():
        async with TestClient(TestServer(app)) as client:
            return await scenario(client)

    return asyncio.run(run())


def test_every_endpoint_but_health_needs_the_api_key_in_the_header(api):
    async def scenario(client):
        assert (await client.get("/health")).status == 200
        assert (await client.get("/status")).status == 401
        assert (await client.get("/status", headers={"X-API-Key": "wrong"})).status == 401
        assert (await client.get("/status?api_key=topsecret")).status == 401, "a key in the URL would leak into logs"
        assert (await client.get("/status", headers={"X-API-Key": "topsecret"})).status == 200

    _with_client(_app(api), scenario)


def test_cors_preflight_and_credentials_follow_the_configured_origin(api):
    async def scenario(client):
        preflight = await client.options("/status")
        assert preflight.status == 204 and preflight.headers["Access-Control-Allow-Origin"] == "https://app.example"
        reply = await client.get("/status", headers={"X-API-Key": "topsecret"})
        assert reply.headers["Access-Control-Allow-Credentials"] == "true"

    _with_client(_app(api, cors_origin="https://app.example"), scenario)

    async def wildcard(client):
        reply = await client.get("/status", headers={"X-API-Key": "topsecret"})
        assert reply.headers["Access-Control-Allow-Origin"] == "*"
        assert "Access-Control-Allow-Credentials" not in reply.headers

    _with_client(_app(api), wildcard)


def test_json_error_shape(api):
    response = api.json_error("nope", status=418, hint="h")
    assert response.status == 418 and b'"ok": false' in response.body and b'"hint": "h"' in response.body


# ---- browser header profiles ---------------------------------------------------------------------------
def test_generated_headers_are_complete_strings_and_vary(api):
    samples = [api.get_random_browser_headers() for _ in range(200)]
    assert all(h["User-Agent"] and all(isinstance(k, str) and isinstance(v, str) for k, v in h.items()) for h in samples)
    assert len({h["User-Agent"] for h in samples}) > 20


def test_client_hint_mobile_flag_matches_the_user_agent(api):
    for _ in range(1000):
        headers = api.get_random_browser_headers()
        flag = headers.get("Sec-CH-UA-Mobile")
        if flag is not None:
            ua = headers["User-Agent"]
            assert (flag == "?1") == any(token in ua for token in ("Mobile", "iPhone", "Android")), ua


def test_client_hint_platform_matches_the_user_agent_for_mainstream_platforms(api):
    expected = {"Windows": "Windows", "macOS": "Macintosh", "Android": "Android", "iOS": "iPhone"}
    for _ in range(1000):
        headers = api.get_random_browser_headers()
        platform = headers.get("Sec-CH-UA-Platform", "").strip('"')
        if platform in expected:
            assert expected[platform] in headers["User-Agent"], headers["User-Agent"]


@pytest.mark.xfail(strict=True, reason=(
    "Known gap: the ChromeOS profile (UA 'X11; CrOS') sends Sec-CH-UA-Platform \"Linux\"; real ChromeOS sends "
    "\"Chrome OS\". About 1% of generated header sets are self-contradictory. Remove this marker when fixed."))
def test_chromeos_user_agents_send_the_chromeos_client_hint_platform(api):
    seen = 0
    for _ in range(3000):
        headers = api.get_random_browser_headers()
        if "CrOS" in headers["User-Agent"] and "Sec-CH-UA-Platform" in headers:
            seen += 1
            assert headers["Sec-CH-UA-Platform"].strip('"') == "Chrome OS"
    assert seen, "no ChromeOS header set was generated in 3000 draws"
