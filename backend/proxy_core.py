#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import re
import signal
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    Any,
    Callable,
    DefaultDict,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Set,
)

import aiohttp

try:
    import aiohttp_socks
    _SOCKS_OK = True
except ImportError:
    _SOCKS_OK = False

DEFAULT_OUTPUT_FILE = "active_proxies.json"
DEFAULT_USER_AGENT = "ProxyGenerator/2.0 (+local pool manager)"
DEFAULT_TEST_URLS = (
    "https://api.ipify.org?format=json",
    "https://httpbin.org/ip",
    "https://example.com/",
)
DEFAULT_SOURCES = (
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/theriturajps/proxy-list/main/proxies.txt",
    "https://raw.githubusercontent.com/komutan234/Proxy-List-Free/main/proxies/http.txt",
    "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/http.txt",
    "https://cdn.jsdelivr.net/gh/databay-labs/free-proxy-list/http.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/https.txt",
    "https://raw.githubusercontent.com/gitrecon1455/fresh-proxy-list/main/all.txt",
    "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/https.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/http.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "https://api.proxyscrape.com/v2/?request=get&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",
    "https://www.proxy-list.download/api/v1/get?type=http",
    "https://api.openproxylist.xyz/http.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/mertguvencli/http-proxy-list/main/proxy-list/data.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/shiftytr/proxy-list/master/proxy.txt",
    "https://raw.githubusercontent.com/Thordata/awesome-free-proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/http.txt",
    # --- Additional HTTP sources ---
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt",
    "https://raw.githubusercontent.com/elliottophellia/yakumo/master/results/http/global/http_checked.txt",
    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt",
    "https://raw.githubusercontent.com/casals-ar/proxy-list/main/http",
    "https://raw.githubusercontent.com/rxvl-d/ProxyList/main/results.txt",
    "https://raw.githubusercontent.com/UptimerBot/proxy-list/main/proxies/http.txt",
    # --- Fresh/high-update sources (every 5-30 min) ---
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/https.txt",
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt",
    "https://raw.githubusercontent.com/rx443/proxy-list/online/online/http.txt",
    "https://raw.githubusercontent.com/TuanMinPay/live-proxy/master/http.txt",
    "https://raw.githubusercontent.com/HyperBeats/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt",
    "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/http.txt",
    "https://raw.githubusercontent.com/proxylist-to/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies_anonymous/http.txt",
    "https://raw.githubusercontent.com/ObcbO/getproxy/master/file/http.txt",
    "https://raw.githubusercontent.com/hanwayTech/free-proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/hanwayTech/free-proxy-list/main/https.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/http.txt",
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/https.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/https.txt",
    # --- ProxyScrape API (multiple protocols) ---
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&timeout=10000&country=all&anonymity=all",
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks5&timeout=10000",
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks4&timeout=10000",
    # --- SOCKS5 sources ---
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt",
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/ObcbO/getproxy/master/file/socks5.txt",
    # --- SOCKS4 sources ---
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks4.txt",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks4.txt",
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks4.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks4.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks4.txt",
    # --- APIs that return JSON (regex still extracts IP:port) ---
    "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&filterUpTime=90&protocols=http",
    "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&filterUpTime=90&protocols=socks5",
    # --- Curated fresh high-yield feeds (2026 update) ---
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks5_proxies.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks4_proxies.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/http_proxies.txt",
    "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/HTTP.txt",
    "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS5.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks4.txt",
    "https://raw.githubusercontent.com/yemixzy/proxy-list/main/proxies/unchecked.txt",
    "https://raw.githubusercontent.com/andigwandi/free-proxy/main/proxy_list.txt",
    "https://raw.githubusercontent.com/im-razvan/proxy_list/main/http.txt",
    "https://raw.githubusercontent.com/im-razvan/proxy_list/main/socks5.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks4.txt",
    "https://raw.githubusercontent.com/elliottophellia/yakumo/master/results/socks5/global/socks5_checked.txt",
    "https://raw.githubusercontent.com/elliottophellia/yakumo/master/results/socks4/global/socks4_checked.txt",
    "https://raw.githubusercontent.com/ProxyList-to/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/ProxyList-to/proxy-list/main/socks4.txt",
    "https://raw.githubusercontent.com/caliphdev/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/caliphdev/Proxy-List/master/socks5.txt",
)

# ---------------------------------------------------------------------------
# Country-targeted free proxy lists ({cc} = lower ISO-2, {CC} = upper ISO-2).
# Every fetched record from these sources is pre-tagged with the list country,
# so per-country coverage grows even before geo enrichment has seen it.
# ---------------------------------------------------------------------------
COUNTRY_SOURCE_TEMPLATES = (
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&country={cc}&proxy_format=protocolipport&format=text",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/countries/{CC}/data.txt",
)

# Countries queried by default (ISO-2, lowercase).
DEFAULT_COUNTRY_SOURCE_CODES = (
    "ae af al am ao ar at au az ba bd be bf bg bh bi bj bn bo br bt bw by bz "
    "ca cd cf cg ch ci cl cm cn co cr cu cv cy cz de dj dk do dz ec ee eg es et "
    "fi fj fr ga ge gh gi gm gn gr gt gw gy hk hn hr ht hu id ie il in iq ir is "
    "it jm jo jp ke kg kh ki km kn kr kw kz la lb lc lk lr ls lt lu lv ly ma md "
    "me mg mk ml mm mn mo mt mu mv mw mx my mz na ne ng ni nl no np om pa pe pg "
    "ph pk pl pr ps pt py qa ro rs ru rw sa sb sc sd se sg si sk sl sn so sr st "
    "sv sy sz td tg th tj tl tm tn to tr tt tw tz ua ug us uy uz vc ve vn ye za "
    "zm zw"
)

PROXY_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b")
PROXY_WITH_SCHEME_PATTERN = re.compile(
    r"\b(?:https?|socks5h?|socks4a?)://(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b"
)
PROXY_WITH_AUTH_PATTERN = re.compile(
    r"(?:(?:http|socks4|socks5)://)?"
    r"[A-Za-z0-9_.\-%!$]+:[A-Za-z0-9_.\-%!$]+@(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}"
)

# Enrichment endpoints
ANONYMITY_CHECK_URL = "http://httpbin.org/headers"
ANONYMITY_CHECK_URLS = [
    "http://httpbin.org/headers",
    "https://httpbin.io/headers",
    "https://ifconfig.me/all.json",
]
TRANSPARENT_LEAK_HEADERS = {
    "x-forwarded-for", "x-real-ip", "forwarded", "client-ip",
    "x-client-ip", "cf-connecting-ip", "true-client-ip", "x-originating-ip",
}
ANONYMOUS_LEAK_HEADERS = {
    "via", "proxy-connection", "x-proxy-id", "x-forwarded-host", "x-forwarded-server",
}
GEO_API_URL = (
    "http://ip-api.com/json/{ip}?fields=status,countryCode,hosting,mobile,isp"
)
_GEO_ENRICH_CONCURRENCY = 1
_GEO_DELAY_SECONDS = 1.4  # ~42 req/min to stay below ip-api.com free limits
_GEO_FAST_URL = "https://get.geojs.io/v1/ip/geo/{ip}.json"  # free, no key, no cap
_GEO_FAST_CONCURRENCY = 32
_TYPE_ENRICH_PER_CYCLE = 45  # ip-api.com budget per cycle (45 req/min free tier)
_ANONYMITY_ENRICH_CONCURRENCY = 24
_ENRICH_BATCH_SIZE = 120
PLATFORM_PROBE_URLS = {
    "telegram": "https://api.telegram.org/",
    "google": "https://www.google.com/generate_204",
    "cloudflare": "https://www.cloudflare.com/cdn-cgi/trace",
    "amazon": "https://www.amazon.com/robots.txt",
    "github": "https://github.com/robots.txt",
    "instagram": "https://www.instagram.com/robots.txt",
    "whatsapp": "https://www.whatsapp.com/robots.txt",
}
_PLATFORM_PROBE_CONCURRENCY = 24
_PLATFORM_REPROBE_SECONDS = 900.0


def normalize_proxy(candidate: str) -> Optional[str]:
    value = candidate.strip()
    if not value:
        return None

    protocol = "http"
    if "://" in value:
        scheme, rest = value.split("://", 1)
        scheme = scheme.lower()
        if scheme in ("http", "https"):
            protocol = scheme
        elif scheme in ("socks4", "socks4a"):
            protocol = "socks4"
        elif scheme in ("socks5", "socks5h"):
            protocol = "socks5"
        value = rest

    # Keep credentials (user:pass@) — required for paid/residential proxies.
    auth = ""
    if "@" in value:
        auth, value = value.rsplit("@", 1)
        auth = auth.strip()
        if not auth or any(char.isspace() for char in auth):
            return None

    if ":" not in value:
        return None

    host, port_text = value.rsplit(":", 1)
    octets = host.split(".")
    if len(octets) != 4:
        return None

    try:
        if any(int(part) < 0 or int(part) > 255 for part in octets):
            return None
        port = int(port_text)
    except ValueError:
        return None

    if not 1 <= port <= 65535:
        return None

    if auth:
        return f"{protocol}://{auth}@{host}:{port}"
    return f"{protocol}://{host}:{port}"


_IPV4_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_HOSTNAME_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9\-\.]{0,251}[A-Za-z0-9])?$")


def normalize_manual_proxy(candidate: str) -> Optional[str]:
    """Like normalize_proxy, but for user-supplied entries.

    Additionally accepts hostnames (e.g. gate.provider.com:8080) so paid
    residential providers that do not publish raw IPs can be used.
    """
    value = candidate.strip()
    if not value:
        return None

    protocol = "http"
    if "://" in value:
        scheme, rest = value.split("://", 1)
        scheme = scheme.lower()
        if scheme in ("http", "https"):
            protocol = scheme
        elif scheme in ("socks4", "socks4a"):
            protocol = "socks4"
        elif scheme in ("socks5", "socks5h"):
            protocol = "socks5"
        value = rest

    if protocol == "https":
        # Upstream proxies are spoken to over plain HTTP in this project.
        protocol = "http"

    auth = ""
    if "@" in value:
        auth, value = value.rsplit("@", 1)
        auth = auth.strip()
        if not auth or ":" not in auth or any(c.isspace() for c in auth):
            return None

    if ":" not in value:
        return None

    host, port_text = value.rsplit(":", 1)
    host = host.strip()
    if not host:
        return None
    if not (_IPV4_PATTERN.match(host) or _HOSTNAME_PATTERN.match(host)):
        return None

    try:
        port = int(port_text)
    except ValueError:
        return None

    if not 1 <= port <= 65535:
        return None

    if auth:
        return f"{protocol}://{auth}@{host}:{port}"
    return f"{protocol}://{host}:{port}"


def _ignore_known_windows_asyncio_noise(
    loop: asyncio.AbstractEventLoop, context: Dict[str, Any]
) -> None:
    if sys.platform != "win32":
        loop.default_exception_handler(context)
        return

    exc = context.get("exception")
    handle_text = repr(context.get("handle", ""))
    message = str(context.get("message", ""))

    if isinstance(exc, ConnectionResetError) and (
        "_ProactorBasePipeTransport._call_connection_lost" in handle_text
        or "_ProactorBasePipeTransport" in message
    ):
        return

    loop.default_exception_handler(context)


def run_async_entrypoint(coro):
    loop_factory = asyncio.SelectorEventLoop if sys.platform == "win32" else None
    with asyncio.Runner(loop_factory=loop_factory) as runner:
        runner.get_loop().set_exception_handler(_ignore_known_windows_asyncio_noise)
        return runner.run(coro)


def run_async_with_cleanup(coro, cleanup_callback=None):
    loop_factory = asyncio.SelectorEventLoop if sys.platform == "win32" else None

    async def run_with_signal_handling():
        interrupt_event = asyncio.Event()
        loop = asyncio.get_running_loop()

        def signal_handler():
            print("\nShutdown signal received, cleaning up...")
            interrupt_event.set()

        if sys.platform != "win32":
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, signal_handler)

        async def run_coro():
            try:
                await coro
            finally:
                if cleanup_callback:
                    await cleanup_callback()

        try:
            async with asyncio.TaskGroup() as tg:
                tg.create_task(run_coro())
                tg.create_task(interrupt_event.wait())
        except (asyncio.CancelledError, KeyboardInterrupt):
            pass

    with asyncio.Runner(loop_factory=loop_factory) as runner:
        runner.get_loop().set_exception_handler(_ignore_known_windows_asyncio_noise)
        return runner.run(run_with_signal_handling())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_datetime(value: str | None) -> datetime:
    if not value:
        return utc_now()
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def extract_proxies(text: str) -> Set[str]:
    proxies: Set[str] = set()
    auth_hosts: Set[str] = set()
    scheme_hosts: Set[str] = set()

    # Scheme-aware pass first: keeps socks5/socks4 protocol info that would
    # otherwise be lost (a socks5 endpoint probed as http always fails).
    for raw_proxy in PROXY_WITH_SCHEME_PATTERN.findall(text):
        normalized = normalize_proxy(raw_proxy)
        if normalized:
            proxies.add(normalized)
            if "://" in normalized:
                scheme_hosts.add(normalized.rsplit("://", 1)[1])

    for raw_proxy in PROXY_WITH_AUTH_PATTERN.findall(text):
        normalized = normalize_proxy(raw_proxy)
        if normalized:
            proxies.add(normalized)
            auth_hosts.add(normalized.rsplit("@", 1)[1])

    for raw_proxy in PROXY_PATTERN.findall(text):
        if raw_proxy in auth_hosts or raw_proxy in scheme_hosts:
            # Same endpoint already extracted with credentials / scheme — skip
            # the duplicate (it would just fail verification).
            continue
        normalized = normalize_proxy(raw_proxy)
        if normalized:
            proxies.add(normalized)

    return proxies


def read_source_file(path: str | None) -> List[str]:
    if not path:
        return []
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"source file not found: {file_path}")
    urls = []
    for line in file_path.read_text(encoding="utf-8").splitlines():
        cleaned = line.strip()
        if cleaned and not cleaned.startswith("#"):
            urls.append(cleaned)
    return urls


def _extract_origin(body: str) -> str:
    stripped = body.strip()
    if not stripped:
        return ""
    try:
        payload = json.loads(stripped)
        if isinstance(payload, dict):
            for key in ("origin", "ip", "query"):
                value = payload.get(key)
                if value:
                    return str(value)
    except json.JSONDecodeError:
        pass

    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", stripped)
    if ip_match:
        return ip_match.group(0)
    return ""


def _extract_ip(proxy_url: str) -> str:
    """Extract bare IP from a proxy URL like http://1.2.3.4:8080."""
    try:
        clean = proxy_url.split("://", 1)[-1].split("@")[-1]
        return clean.split(":")[0]
    except Exception:
        return ""


def _evaluate_anonymity(data: Any) -> str:
    if not isinstance(data, dict):
        return ""
    headers = data.get("headers", {})
    if not isinstance(headers, dict):
        headers = {}
    combined = {str(k).lower(): str(v) for k, v in headers.items()}
    for k, v in data.items():
        if k != "headers" and v:
            combined[str(k).lower()] = str(v)
    for h in TRANSPARENT_LEAK_HEADERS:
        if h in combined and combined[h]:
            return "transparent"
    for h in ANONYMOUS_LEAK_HEADERS:
        if h in combined and combined[h]:
            return "anonymous"
    return "elite"


async def _check_anonymity_via_socks(proxy_url: str, timeout_seconds: float) -> str:
    if not _SOCKS_OK:
        return ""
    target_url = proxy_url
    if target_url.startswith("socks5://"):
        target_url = "socks5h://" + target_url[len("socks5://"):]
    per_mirror = max(2.5, timeout_seconds / len(ANONYMITY_CHECK_URLS))
    for check_url in ANONYMITY_CHECK_URLS:
        try:
            connector = aiohttp_socks.ProxyConnector.from_url(target_url, ssl=False)
            timeout = aiohttp.ClientTimeout(total=per_mirror)
            async with aiohttp.ClientSession(connector=connector, trust_env=False) as s:
                async with s.get(
                    check_url,
                    timeout=timeout,
                    headers={"User-Agent": DEFAULT_USER_AGENT},
                ) as response:
                    if response.status == 200:
                        data = await response.json(content_type=None)
                        res = _evaluate_anonymity(data)
                        if res:
                            return res
        except Exception:
            continue
    return ""


async def check_proxy_anonymity(
    session: aiohttp.ClientSession,
    proxy_url: str,
    timeout_seconds: float = 8.0,
) -> str:
    """Return 'elite', 'anonymous', 'transparent', or '' on failure."""
    if proxy_url.startswith("socks"):
        return await _check_anonymity_via_socks(proxy_url, timeout_seconds)
    per_mirror = max(2.5, timeout_seconds / len(ANONYMITY_CHECK_URLS))
    for check_url in ANONYMITY_CHECK_URLS:
        try:
            timeout = aiohttp.ClientTimeout(total=per_mirror)
            async with session.get(
                check_url,
                proxy=proxy_url,
                timeout=timeout,
                headers={"User-Agent": DEFAULT_USER_AGENT},
            ) as response:
                if response.status == 200:
                    data = await response.json(content_type=None)
                    res = _evaluate_anonymity(data)
                    if res:
                        return res
        except Exception:
            continue
    return ""


def _classify_proxy_type(geo: Dict[str, Any]) -> str:
    """Map ip-api.com geo data to a proxy type label."""
    if geo.get("mobile"):
        return "mobile"
    if geo.get("hosting"):
        return "datacenter"
    return "residential"


async def lookup_proxy_geo(
    session: aiohttp.ClientSession,
    ip: str,
    timeout_seconds: float = 5.0,
) -> Dict[str, Any]:
    """Return {"country", "proxy_type"} for *ip* via ip-api.com, or {} on failure."""
    if not ip:
        return {}
    try:
        timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        async with session.get(
            GEO_API_URL.format(ip=ip),
            timeout=timeout,
        ) as response:
            if response.status != 200:
                return {}
            data = await response.json(content_type=None)
            if data.get("status") != "success":
                return {}
            return {
                "country": str(data.get("countryCode", "")),
                "proxy_type": _classify_proxy_type(data),
            }
    except Exception:
        return {}


async def lookup_proxy_geo_batch(
    session: aiohttp.ClientSession,
    ips: List[str],
    timeout_seconds: float = 8.0,
) -> Dict[str, Dict[str, Any]]:
    """Return {ip: {"country": ..., "proxy_type": ...}} using ip-api.com/batch (up to 100 IPs per request)."""
    if not ips:
        return {}
    results: Dict[str, Dict[str, Any]] = {}
    batch_url = "http://ip-api.com/batch?fields=status,countryCode,hosting,mobile,isp,query"
    # Process unique IPs in chunks of 100
    unique_ips = list(dict.fromkeys(ip.strip() for ip in ips if ip.strip()))
    for i in range(0, len(unique_ips), 100):
        chunk = unique_ips[i : i + 100]
        try:
            timeout = aiohttp.ClientTimeout(total=timeout_seconds)
            async with session.post(
                batch_url,
                json=chunk,
                timeout=timeout,
            ) as response:
                if response.status == 200:
                    data = await response.json(content_type=None)
                    if isinstance(data, list):
                        for item in data:
                            if item.get("status") == "success":
                                q = item.get("query", "")
                                if q:
                                    results[q] = {
                                        "country": str(item.get("countryCode", "")),
                                        "proxy_type": _classify_proxy_type(item),
                                        "isp": str(item.get("isp", "")),
                                    }
        except Exception:
            pass
        if i + 100 < len(unique_ips):
            await asyncio.sleep(0.5)
    return results


async def lookup_proxy_country(
    session: aiohttp.ClientSession,
    ip: str,
    timeout_seconds: float = 5.0,
) -> str:
    """Return ISO-2 country code for *ip* using ip-api.com, or '' on failure."""
    geo = await lookup_proxy_geo(session, ip, timeout_seconds)
    return str(geo.get("country", ""))


async def lookup_country_fast(
    session: aiohttp.ClientSession,
    ip: str,
    timeout_seconds: float = 5.0,
) -> str:
    """Return ISO-2 country code for *ip* via geojs.io, or '' on failure.

    geojs.io is free, needs no key and has no practical rate cap, so country
    fill runs fully parallel (concurrency 32) instead of the ip-api.com
    sequential path that stays reserved for proxy-type classification.
    """
    if not ip:
        return ""
    try:
        timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        async with session.get(
            _GEO_FAST_URL.format(ip=ip),
            timeout=timeout,
        ) as response:
            if response.status != 200:
                return ""
            data = await response.json(content_type=None)
            return str(data.get("country_code") or "").upper()
    except Exception:
        return ""


@dataclass
class HarvesterConfig:
    max_concurrent: int = 200
    fetch_timeout: float = 10.0
    verify_timeout: float = 10.0
    update_interval: float = 120.0
    verify_interval: float = 60.0
    auto_save_interval: float = 15.0
    max_candidates: int = 3000
    verify_batch_size: int = 200
    min_success_rate: float = 0.35
    max_consecutive_failures: int = 3
    max_stored_records: int = 5000
    stale_after_seconds: float = 1800.0
    max_response_time: float = 12.0
    output_file: str = DEFAULT_OUTPUT_FILE
    user_agent: str = DEFAULT_USER_AGENT
    residential_file: str = "residential-proxies.txt"
    tor_file: str = "tor-proxies.txt"
    country_source_codes: str = "default"
    platform_probes: str = ""  # e.g. "telegram,instagram,whatsapp" ("" = disabled)
    test_urls: List[str] = field(default_factory=lambda: list(DEFAULT_TEST_URLS))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_concurrent": self.max_concurrent,
            "fetch_timeout": self.fetch_timeout,
            "verify_timeout": self.verify_timeout,
            "update_interval": self.update_interval,
            "verify_interval": self.verify_interval,
            "auto_save_interval": self.auto_save_interval,
            "max_candidates": self.max_candidates,
            "verify_batch_size": self.verify_batch_size,
            "platform_probes": self.platform_probes,
            "min_success_rate": self.min_success_rate,
            "max_consecutive_failures": self.max_consecutive_failures,
            "stale_after_seconds": self.stale_after_seconds,
            "max_response_time": self.max_response_time,
            "output_file": self.output_file,
            "user_agent": self.user_agent,
            "residential_file": self.residential_file,
            "tor_file": self.tor_file,
            "test_urls": list(self.test_urls),
        }


def _safe_int_map(value: Any) -> Dict[str, int]:
    """Parse a JSON payload into {str: int}, ignoring malformed entries."""
    if not isinstance(value, dict):
        return {}
    result: Dict[str, int] = {}
    for key, item in value.items():
        try:
            result[str(key)] = int(item)
        except (TypeError, ValueError):
            continue
    return result


@dataclass
class ProxyRecord:
    proxy: str
    first_seen: datetime = field(default_factory=utc_now)
    last_seen_success: datetime = field(default_factory=utc_now)
    last_checked: datetime = field(default_factory=utc_now)
    total_checks: int = 0
    successful_checks: int = 0
    consecutive_failures: int = 0
    response_times: List[float] = field(default_factory=list)
    source_urls: List[str] = field(default_factory=list)
    last_error: str = ""
    last_probe_url: str = ""
    last_origin: str = ""
    anonymity: str = ""   # "elite" | "anonymous" | "transparent" | ""
    country: str = ""     # ISO-2 country code or ""
    proxy_type: str = ""  # "residential" | "mobile" | "datacenter" | ""
    speed_tier: str = ""  # "fast" (<1.5s) | "medium" (1.5-3.5s) | "slow" (>3.5s)
    platforms: Dict[str, bool] = field(default_factory=dict)  # {"telegram": True, ...}
    platforms_checked_at: float = 0.0  # time.monotonic() of last platform probe
    manual: bool = False  # user-supplied entry (from residential-proxies.txt)
    domain_ok: Dict[str, int] = field(default_factory=dict)    # per-host success memory
    domain_fail: Dict[str, int] = field(default_factory=dict)  # per-host failure memory
    success_rate: float = 0.0
    avg_response_time: float = 0.0
    score: float = 0.0
    _last_used_at: float = field(default=0.0, init=False, compare=False, repr=False)

    @property
    def protocol(self) -> str:
        if "://" in self.proxy:
            return self.proxy.split("://", 1)[0].lower()
        return "http"

    def mark_used(self) -> None:
        self._last_used_at = time.monotonic()

    def on_cooldown(self, min_interval_seconds: float = 0.0) -> bool:
        if min_interval_seconds <= 0:
            return False
        return (time.monotonic() - self._last_used_at) < min_interval_seconds

    def add_sources(self, urls: Iterable[str]) -> None:
        merged = set(self.source_urls)
        merged.update(urls)
        self.source_urls = sorted(merged)[:10]

    # --- per-domain (target host) memory ---------------------------------
    _MAX_DOMAIN_KEYS = 16

    def note_domain_result(self, domain: str, success: bool) -> None:
        """Remember how this proxy behaved for one target host.

        Real fetch outcomes are recorded here so future requests to the same
        host prefer proxies already proven to work for it (and skip ones that
        failed before).
        """
        key = (domain or "").strip().lower()
        if not key:
            return
        bucket = self.domain_ok if success else self.domain_fail
        bucket[key] = bucket.get(key, 0) + 1
        if len(self.domain_ok) + len(self.domain_fail) > self._MAX_DOMAIN_KEYS:
            self._prune_domain_stats()

    def domain_net(self, domain: str) -> int:
        """Net score (successes - failures) recorded for a target host."""
        key = (domain or "").strip().lower()
        if not key:
            return 0
        return self.domain_ok.get(key, 0) - self.domain_fail.get(key, 0)

    def _prune_domain_stats(self) -> None:
        keys = sorted(
            set(self.domain_ok) | set(self.domain_fail),
            key=lambda item: self.domain_ok.get(item, 0) + self.domain_fail.get(item, 0),
            reverse=True,
        )
        for key in keys[self._MAX_DOMAIN_KEYS:]:
            self.domain_ok.pop(key, None)
            self.domain_fail.pop(key, None)

    def record_success(
        self,
        response_time: float,
        probe_url: str,
        origin: str,
        max_response_time: float,
    ) -> None:
        self.total_checks += 1
        self.successful_checks += 1
        self.consecutive_failures = 0
        self.last_checked = utc_now()
        self.last_seen_success = self.last_checked
        self.last_error = ""
        self.last_probe_url = probe_url
        self.last_origin = origin
        self.response_times.append(round(response_time, 4))
        if len(self.response_times) > 20:
            self.response_times = self.response_times[-20:]
        self.recalculate(max_response_time)

    def record_failure(
        self, error: str, probe_url: str, max_response_time: float
    ) -> None:
        self.total_checks += 1
        self.consecutive_failures += 1
        self.last_checked = utc_now()
        self.last_error = error
        self.last_probe_url = probe_url
        self.recalculate(max_response_time)

    def recalculate(
        self, max_response_time: float, freshness_window_seconds: float = 3600.0
    ) -> None:
        self.success_rate = (
            (self.successful_checks / self.total_checks) if self.total_checks else 0.0
        )
        self.avg_response_time = (
            sum(self.response_times) / len(self.response_times)
            if self.response_times
            else 0.0
        )
        freshness = (
            0.0
            if self.successful_checks == 0
            else max(
                0.0,
                1.0
                - min(
                    (utc_now() - self.last_seen_success).total_seconds(),
                    freshness_window_seconds,
                )
                / freshness_window_seconds,
            )
        )
        speed = (
            0.0
            if self.avg_response_time <= 0
            else max(
                0.0,
                1.0
                - min(self.avg_response_time, max_response_time) / max_response_time,
            )
        )
        stability = max(0.0, 1.0 - min(self.consecutive_failures, 5) / 5.0)
        self.score = round(
            (self.success_rate * 0.50)
            + (speed * 0.25)
            + (freshness * 0.15)
            + (stability * 0.10),
            6,
        )
        if self.avg_response_time > 0:
            if self.avg_response_time <= 1.5:
                self.speed_tier = "fast"
            elif self.avg_response_time <= 3.5:
                self.speed_tier = "medium"
            else:
                self.speed_tier = "slow"
        else:
            self.speed_tier = ""

    def is_active(self, config: HarvesterConfig) -> bool:
        if self.successful_checks == 0:
            return False
        if self.consecutive_failures >= config.max_consecutive_failures:
            return False
        if self.total_checks >= 3 and self.success_rate < config.min_success_rate:
            return False
        if self.avg_response_time and self.avg_response_time > config.max_response_time:
            return False
        return (
            utc_now() - self.last_seen_success
        ).total_seconds() <= config.stale_after_seconds

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proxy": self.proxy,
            "protocol": self.protocol,
            "first_seen": to_iso(self.first_seen),
            "last_seen_success": to_iso(self.last_seen_success),
            "last_seen": to_iso(self.last_seen_success),
            "last_checked": to_iso(self.last_checked),
            "total_checks": self.total_checks,
            "successful_checks": self.successful_checks,
            "consecutive_failures": self.consecutive_failures,
            "response_times": self.response_times,
            "source_urls": self.source_urls,
            "last_error": self.last_error,
            "last_probe_url": self.last_probe_url,
            "last_origin": self.last_origin,
            "anonymity": self.anonymity,
            "country": self.country,
            "proxy_type": self.proxy_type,
            "speed_tier": self.speed_tier,
            "platforms": dict(self.platforms),
            "manual": self.manual,
            "success_rate": round(self.success_rate, 6),
            "avg_response_time": round(self.avg_response_time, 4),
            "score": round(self.score, 6),
            "domain_ok": dict(self.domain_ok),
            "domain_fail": dict(self.domain_fail),
        }

    @classmethod
    def from_dict(
        cls, payload: Dict[str, Any], max_response_time: float = 12.0
    ) -> "ProxyRecord":
        record = cls(
            proxy=payload["proxy"],
            first_seen=parse_datetime(
                payload.get("first_seen") or payload.get("last_seen")
            ),
            last_seen_success=parse_datetime(
                payload.get("last_seen_success") or payload.get("last_seen")
            ),
            last_checked=parse_datetime(
                payload.get("last_checked") or payload.get("last_seen")
            ),
            total_checks=int(payload.get("total_checks", 0)),
            successful_checks=int(payload.get("successful_checks", 0)),
            consecutive_failures=int(payload.get("consecutive_failures", 0)),
            response_times=[
                float(value) for value in payload.get("response_times", [])
            ],
            source_urls=list(payload.get("source_urls", [])),
            last_error=str(payload.get("last_error", "")),
            last_probe_url=str(payload.get("last_probe_url", "")),
            last_origin=str(payload.get("last_origin", "")),
            anonymity=str(payload.get("anonymity", "")),
            country=str(payload.get("country", "")),
            proxy_type=str(payload.get("proxy_type", "")),
            speed_tier=str(payload.get("speed_tier", "")),
            platforms={
                str(name): bool(ok)
                for name, ok in (payload.get("platforms") or {}).items()
            },
            manual=bool(payload.get("manual", False)),
            success_rate=float(payload.get("success_rate", 0.0)),
            avg_response_time=float(payload.get("avg_response_time", 0.0)),
            score=float(payload.get("score", 0.0)),
            domain_ok=_safe_int_map(payload.get("domain_ok")),
            domain_fail=_safe_int_map(payload.get("domain_fail")),
        )
        record.recalculate(max_response_time)
        return record


def load_proxy_records(
    path: str | Path, max_response_time: float = 12.0
) -> Dict[str, ProxyRecord]:
    file_path = Path(path)
    if not file_path.exists():
        return {}
    raw = json.loads(file_path.read_text(encoding="utf-8"))
    items = raw.get("proxies", []) if isinstance(raw, dict) else raw
    records: Dict[str, ProxyRecord] = {}
    for item in items:
        try:
            record = ProxyRecord.from_dict(item, max_response_time)
            records[record.proxy] = record
        except Exception:
            continue
    return records


def load_ranked_records(
    path: str | Path,
    limit: int | None = None,
    min_score: float = 0.0,
    max_response_time: float = 12.0,
) -> List[ProxyRecord]:
    records = [
        record
        for record in load_proxy_records(path, max_response_time).values()
        if record.score >= min_score
    ]
    records.sort(
        key=lambda item: (
            -item.score,
            -item.success_rate,
            item.avg_response_time or 9999.0,
            item.proxy,
        )
    )
    return records if limit is None else records[:limit]


@dataclass
class ProbeOutcome:
    proxy: str
    working: bool
    response_time: float = 0.0
    probe_url: str = ""
    error: str = ""
    origin: str = ""
    status_code: int = 0


async def _probe_socks_proxy(
    proxy: str,
    proxy_url: str,
    test_urls: Sequence[str],
    timeout_seconds: float,
    user_agent: str,
) -> ProbeOutcome:
    if not _SOCKS_OK:
        return ProbeOutcome(proxy=proxy, working=False, error="aiohttp_socks not installed")
    headers = {"User-Agent": user_agent, "Accept": "application/json,text/plain,*/*"}
    errors: List[str] = []
    try:
        connector = aiohttp_socks.ProxyConnector.from_url(proxy_url, ssl=False)
        async with aiohttp.ClientSession(connector=connector, trust_env=False) as socks_session:
            for test_url in test_urls:
                started = time.perf_counter()
                try:
                    timeout = aiohttp.ClientTimeout(total=timeout_seconds)
                    async with socks_session.get(
                        test_url, headers=headers, timeout=timeout, allow_redirects=True,
                    ) as response:
                        body = await response.text()
                        if response.status != 200:
                            errors.append(f"{response.status} from {test_url}")
                            continue
                        origin = _extract_origin(body)
                        if not origin:
                            errors.append(f"no origin from {test_url}")
                            continue
                        return ProbeOutcome(
                            proxy=proxy, working=True,
                            response_time=time.perf_counter() - started,
                            probe_url=test_url, origin=origin, status_code=response.status,
                        )
                except asyncio.TimeoutError:
                    errors.append(f"timeout from {test_url}")
                except Exception as exc:
                    errors.append(f"{exc.__class__.__name__} from {test_url}")
    except Exception as exc:
        errors.append(f"connector: {exc.__class__.__name__}")
    return ProbeOutcome(
        proxy=proxy, working=False,
        error="; ".join(errors[:3]) if errors else "unknown error",
    )


async def tcp_preflight_check(host: str, port: int, timeout: float = 1.8) -> bool:
    """Pre-flight check: ensure remote TCP port responds with SYN-ACK within timeout."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def probe_proxy(
    session: aiohttp.ClientSession,
    proxy: str,
    test_urls: Sequence[str],
    timeout_seconds: float,
    user_agent: str = DEFAULT_USER_AGENT,
) -> ProbeOutcome:
    headers = {"User-Agent": user_agent, "Accept": "application/json,text/plain,*/*"}
    proxy_url = proxy if "://" in proxy else f"http://{proxy}"
    errors: List[str] = []
    clean_addr = proxy.split("://", 1)[-1].split("@", 1)[-1]
    if ":" in clean_addr:
        h, p_str = clean_addr.rsplit(":", 1)
        try:
            p_val = int(p_str)
            if h not in ("127.0.0.1", "localhost", "0.0.0.0"):
                alive = await tcp_preflight_check(h, p_val, timeout=min(1.8, timeout_seconds))
                if not alive:
                    return ProbeOutcome(
                        proxy=proxy,
                        working=False,
                        error="TCP port unreachable / SYN-ACK timeout",
                    )
        except ValueError:
            pass

    if proxy_url.startswith(("socks4://", "socks5://")):
        return await _probe_socks_proxy(proxy, proxy_url, test_urls, timeout_seconds, user_agent)

    for test_url in test_urls:
        started = time.perf_counter()
        try:
            timeout = aiohttp.ClientTimeout(total=timeout_seconds)
            async with session.get(
                test_url,
                headers=headers,
                proxy=proxy_url,
                timeout=timeout,
                allow_redirects=True,
            ) as response:
                body = await response.text()
                if response.status != 200:
                    errors.append(f"{response.status} from {test_url}")
                    continue
                origin = _extract_origin(body)
                if not origin:
                    errors.append(f"unexpected response from {test_url}")
                    continue
                return ProbeOutcome(
                    proxy=proxy,
                    working=True,
                    response_time=time.perf_counter() - started,
                    probe_url=test_url,
                    origin=origin,
                    status_code=response.status,
                )
        except asyncio.TimeoutError:
            errors.append(f"timeout from {test_url}")
        except aiohttp.ClientError as exc:
            errors.append(f"{exc.__class__.__name__} from {test_url}")
        except Exception as exc:
            errors.append(f"{exc.__class__.__name__} from {test_url}")

    # Auto-detection fallback: if HTTP probe failed, test whether candidate is a SOCKS5 proxy
    if _SOCKS_OK and not proxy_url.startswith(("socks4://", "socks5://")):
        socks_candidate = f"socks5://{clean_addr}"
        try:
            socks_res = await _probe_socks_proxy(
                proxy=socks_candidate,
                proxy_url=socks_candidate,
                test_urls=test_urls[:1],
                timeout_seconds=min(timeout_seconds, 6.0),
                user_agent=user_agent,
            )
            if socks_res.working:
                return socks_res
        except Exception:
            pass

    return ProbeOutcome(
        proxy=proxy,
        working=False,
        error="; ".join(errors[:3]) if errors else "unknown error",
    )


def _write_json_atomic(output_path: str, tmp_path: str, payload: dict) -> None:
    """Write JSON to a temp file then atomically replace the target. Thread-safe."""
    from pathlib import Path as _Path
    t = _Path(tmp_path)
    t.parent.mkdir(parents=True, exist_ok=True)
    t.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    t.replace(_Path(output_path))


class ProxyHarvester:
    def __init__(
        self,
        config: HarvesterConfig,
        sources: Optional[Sequence[str]] = None,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.config = config
        self.sources = list(sources or DEFAULT_SOURCES)
        self.source_country: Dict[str, str] = {}
        self._apply_country_sources()
        self.progress_callback = progress_callback
        self.records: Dict[str, ProxyRecord] = {}
        self.active_proxies: Set[str] = set()
        self.source_counts: Dict[str, int] = {}
        self.source_errors: Dict[str, str] = {}
        self.session: Optional[aiohttp.ClientSession] = None
        self._last_collect = 0.0
        self._last_verify = 0.0
        self._last_save = 0.0
        self._round_robin_index: int = 0

    def _emit_progress(self, **payload: Any) -> None:
        if not self.progress_callback:
            return
        self.progress_callback(payload)

    def _apply_country_sources(self) -> None:
        """Append country-targeted list URLs and remember url -> ISO-2 code."""
        raw = (self.config.country_source_codes or "").strip()
        if not raw or raw.lower() in {"off", "none", "0", "false", "disabled"}:
            return
        if raw.lower() == "default":
            raw = DEFAULT_COUNTRY_SOURCE_CODES
        codes = [code for code in re.split(r"[\s,;]+", raw) if code]
        for code in codes:
            country_code = code.strip().upper()
            if len(country_code) != 2 or not country_code.isalpha():
                continue
            for template in COUNTRY_SOURCE_TEMPLATES:
                url = template.format(cc=country_code.lower(), CC=country_code)
                if url not in self.sources:
                    self.sources.append(url)
                self.source_country[url] = country_code

    async def __aenter__(self) -> "ProxyHarvester":
        connector = aiohttp.TCPConnector(limit=self.config.max_concurrent, ssl=True)
        self.session = aiohttp.ClientSession(
            connector=connector,
            headers={"User-Agent": self.config.user_agent},
            trust_env=False,
        )
        self.records = load_proxy_records(
            self.config.output_file, self.config.max_response_time
        )
        self._rebuild_active_proxies()
        self._last_collect = time.monotonic() - self.config.update_interval
        self._last_verify = time.monotonic() - self.config.verify_interval
        self._last_save = 0.0
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self.session:
            await self.session.close()

    def _rebuild_active_proxies(self) -> None:
        self.active_proxies = {
            proxy
            for proxy, record in self.records.items()
            if record.is_active(self.config)
        }

    def ranked_active_records(self, limit: int | None = None) -> List[ProxyRecord]:
        records = [
            self.records[proxy]
            for proxy in self.active_proxies
            if proxy in self.records
        ]
        records.sort(
            key=lambda item: (
                -item.score,
                -item.success_rate,
                item.avg_response_time or 9999.0,
                item.proxy,
            )
        )
        return records if limit is None else records[:limit]

    def best_proxy(self) -> Optional[ProxyRecord]:
        ranked = self.ranked_active_records(limit=1)
        return ranked[0] if ranked else None

    def _filtered_records(
        self,
        protocol: Optional[str] = None,
        country: Optional[str] = None,
        anonymity: Optional[str] = None,
        proxy_type: Optional[str] = None,
        platform: Optional[str] = None,
        speed_tier: Optional[str] = None,
        min_score: float = 0.0,
        limit: Optional[int] = None,
    ) -> List[ProxyRecord]:
        """Return ranked active records matching all non-None filter criteria."""
        records = self.ranked_active_records()
        if min_score > 0:
            records = [r for r in records if r.score >= min_score]
        if protocol:
            records = [r for r in records if r.protocol == protocol.lower()]
        if country:
            records = [r for r in records if r.country.upper() == country.upper()]
        if anonymity:
            records = [r for r in records if r.anonymity == anonymity.lower()]
        if proxy_type:
            value = proxy_type.lower()
            records = [r for r in records if r.proxy_type == value]
        if platform:
            platform_key = platform.lower()
            records = [r for r in records if r.platforms.get(platform_key)]
        if speed_tier:
            st = speed_tier.strip().lower()
            records = [r for r in records if r.speed_tier == st]
        return records if limit is None else records[:limit]

    def next_proxy(
        self,
        protocol: Optional[str] = None,
        country: Optional[str] = None,
        anonymity: Optional[str] = None,
        proxy_type: Optional[str] = None,
        platform: Optional[str] = None,
        speed_tier: Optional[str] = None,
        min_score: float = 0.0,
        skip_cooldown: float = 0.0,
    ) -> Optional[ProxyRecord]:
        """Round-robin: return next proxy matching criteria and advance the index."""
        records = self._filtered_records(
            protocol=protocol,
            country=country,
            anonymity=anonymity,
            proxy_type=proxy_type,
            platform=platform,
            speed_tier=speed_tier,
            min_score=min_score,
        )
        if skip_cooldown > 0:
            records = [r for r in records if not r.on_cooldown(skip_cooldown)]
        if not records:
            return None
        if self._round_robin_index >= len(records):
            self._round_robin_index = 0
        record = records[self._round_robin_index]
        self._round_robin_index = (self._round_robin_index + 1) % len(records)
        return record

    async def _enrich_pool(self) -> None:
        """Detect anonymity level, country and proxy type for active proxies in fast batches."""
        if not self.session:
            return
        candidates = [
            record
            for proxy, record in self.records.items()
            if proxy in self.active_proxies
            and (not record.anonymity or not record.country or not record.proxy_type)
        ]
        if not candidates:
            return
        # Process up to 300 candidates per cycle
        candidates = candidates[:300]

        sem_anon = asyncio.Semaphore(_ANONYMITY_ENRICH_CONCURRENCY)
        sem_geo_fast = asyncio.Semaphore(_GEO_FAST_CONCURRENCY)

        async def enrich_anon_and_fast_country(record: ProxyRecord) -> None:
            proxy_url = record.proxy if "://" in record.proxy else f"http://{record.proxy}"
            ip = _extract_ip(proxy_url)
            try:
                if not record.country and ip:
                    async with sem_geo_fast:
                        country = await lookup_country_fast(
                            self.session,  # type: ignore[arg-type]
                            ip,
                            5.0,
                        )
                    if country:
                        record.country = country
                if not record.anonymity:
                    async with sem_anon:
                        anon = await check_proxy_anonymity(
                            self.session,  # type: ignore[arg-type]
                            proxy_url,
                            self.config.verify_timeout,
                        )
                        if anon:
                            record.anonymity = anon
            except Exception:
                pass

        # 1. Parallel anonymity + fast country resolution
        await asyncio.gather(*(enrich_anon_and_fast_country(record) for record in candidates))

        # 2. Ultra-fast bulk proxy_type (Residential vs Datacenter) resolution via ip-api.com/batch (100 IPs/req)
        needed_ips = [
            _extract_ip(r.proxy)
            for r in candidates
            if not r.proxy_type and _extract_ip(r.proxy)
        ]
        if needed_ips:
            try:
                batch_geo = await lookup_proxy_geo_batch(
                    self.session,
                    needed_ips[:300],
                    timeout_seconds=8.0,
                )
                for record in candidates:
                    ip = _extract_ip(record.proxy)
                    if ip in batch_geo:
                        g = batch_geo[ip]
                        if not record.country and g.get("country"):
                            record.country = str(g["country"])
                        if not record.proxy_type and g.get("proxy_type"):
                            record.proxy_type = str(g["proxy_type"])
            except Exception:
                pass

    async def _probe_platforms(self) -> None:
        """Tag active proxies with the platforms they can actually reach.

        Opt-in via ``config.platform_probes`` (e.g. "telegram,instagram,whatsapp").
        Only proxies that passed basic verification are probed, through cheap
        GET requests to tiny public endpoints (API root / robots.txt). Results
        land in ``record.platforms`` and feed /proxies?platform=... .
        """
        wanted = [
            name.strip().lower()
            for name in (self.config.platform_probes or "").split(",")
            if name.strip()
        ]
        wanted = [name for name in wanted if name in PLATFORM_PROBE_URLS]
        if not wanted or not self.session:
            return
        now = time.monotonic()
        candidates = [
            record
            for proxy, record in self.records.items()
            if proxy in self.active_proxies
            and (
                not record.platforms
                or (now - record.platforms_checked_at) >= _PLATFORM_REPROBE_SECONDS
                or any(name not in record.platforms for name in wanted)
            )
        ]
        if not candidates:
            return
        candidates = candidates[:_ENRICH_BATCH_SIZE]
        sem = asyncio.Semaphore(_PLATFORM_PROBE_CONCURRENCY)
        timeout = aiohttp.ClientTimeout(total=max(6.0, self.config.verify_timeout))

        async def probe(record: ProxyRecord) -> None:
            proxy_url = record.proxy if "://" in record.proxy else f"http://{record.proxy}"
            stale = (now - record.platforms_checked_at) >= _PLATFORM_REPROBE_SECONDS
            names = (
                wanted
                if stale or not record.platforms
                else [name for name in wanted if name not in record.platforms]
            )
            results: Dict[str, bool] = {}
            for name in names:
                ok = False
                try:
                    async with sem:
                        async with self.session.get(  # type: ignore[union-attr]
                            PLATFORM_PROBE_URLS[name],
                            proxy=proxy_url,
                            timeout=timeout,
                            headers={"User-Agent": DEFAULT_USER_AGENT},
                            allow_redirects=True,
                        ) as response:
                            ok = 200 <= response.status < 400
                except Exception:
                    ok = False
                results[name] = ok
            if results:
                record.platforms.update(results)
                record.platforms_checked_at = time.monotonic()

        await asyncio.gather(*(probe(record) for record in candidates))
        tally = {n: sum(1 for r in candidates if r.platforms.get(n)) for n in wanted}
        print(f"[platform-probe] candidates={len(candidates)} tally={tally}", flush=True)
    async def save_pool(self, force: bool = False) -> None:
        """Persist the active proxy pool to disk without blocking the event loop."""
        now = time.monotonic()
        if not force and (now - self._last_save) < self.config.auto_save_interval:
            return

        payload = {
            "updated_at": to_iso(utc_now()),
            "count": len(self.active_proxies),
            "summary": {
                "known_records": len(self.records),
                "active_records": len(self.active_proxies),
                "sources": len(self.sources),
            },
            "config": self.config.to_dict(),
            "sources": [
                {
                    "url": url,
                    "last_count": self.source_counts.get(url, 0),
                    "last_error": self.source_errors.get(url, ""),
                }
                for url in self.sources
            ],
            "proxies": [record.to_dict() for record in self.ranked_active_records()],
        }
        output_path = Path(self.config.output_file)
        tmp_path = output_path.with_suffix(f"{output_path.suffix}.tmp")
        # H-1: Use asyncio.to_thread so disk I/O never blocks the event loop.
        await asyncio.to_thread(
            _write_json_atomic, str(output_path), str(tmp_path), payload
        )
        self._last_save = now

    async def _fetch_source(self, url: str, retries: int = 2) -> Set[str]:
        if not self.session:
            raise RuntimeError("harvester session is not ready")

        last_error = ""
        for attempt in range(retries + 1):
            try:
                timeout = aiohttp.ClientTimeout(total=self.config.fetch_timeout)
                async with self.session.get(
                    url, timeout=timeout, allow_redirects=True
                ) as response:
                    if response.status == 429:
                        self.source_counts[url] = 0
                        self.source_errors[url] = "rate_limited"
                        return set()
                    if response.status != 200:
                        last_error = f"http {response.status}"
                        if attempt < retries:
                            await asyncio.sleep(1.0 * (attempt + 1))
                            continue
                        self.source_counts[url] = 0
                        self.source_errors[url] = last_error
                        return set()
                    proxies = extract_proxies(await response.text())
                    self.source_counts[url] = len(proxies)
                    self.source_errors[url] = ""
                    return proxies
            except (asyncio.TimeoutError, aiohttp.ClientError) as exc:
                last_error = exc.__class__.__name__
                if attempt < retries:
                    await asyncio.sleep(0.5 * (attempt + 1))
            except Exception as exc:
                self.source_counts[url] = 0
                self.source_errors[url] = exc.__class__.__name__
                return set()

        self.source_counts[url] = 0
        self.source_errors[url] = last_error
        return set()

    def load_manual_proxies(self) -> Dict[str, Set[str]]:
        """Read user-supplied proxies (e.g. paid residential) from a text file.

        One entry per line: host:port, user:pass@host:port,
        http://user:pass@host:port or socks5://user:pass@host:port.
        An optional '|CC' suffix pins the ISO-2 exit country, e.g.
        gate.provider.com:8080|SG — important for provider gateway hostnames
        whose exit country geo lookup cannot guess (ip-api sees the gateway
        IP, not the rotating exit). Lines starting with '#' are ignored;
        inline '#' comments are stripped. These entries are always kept in the
        pool, re-verified each cycle and tagged as residential.
        """
        entries: Dict[str, Set[str]] = {}
        path = Path(self.config.residential_file)
        if not path.exists():
            return entries
        label = f"manual:{path.name}"
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return entries
        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            country = ""
            if "|" in line:
                line, _, suffix = line.partition("|")
                suffix = suffix.strip().upper()
                if len(suffix) == 2 and suffix.isalpha():
                    country = suffix
                line = line.strip()
            for chunk in re.split(r"[,\s;]+", line):
                if not chunk:
                    continue
                normalized = normalize_manual_proxy(chunk)
                if not normalized:
                    continue
                entries.setdefault(normalized, set()).add(label)
                record = self.records.setdefault(
                    normalized, ProxyRecord(proxy=normalized)
                )
                record.manual = True
                if not record.proxy_type:
                    record.proxy_type = "residential"
                if country:
                    record.country = country
        return entries

    def load_tor_proxies(self) -> Dict[str, Set[str]]:
        """Read Tor SOCKS endpoints (written by Tor-manager.py) from a text file.

        One entry per line: socks5://127.0.0.1:9701|US (the optional pipe +
        ISO-2 suffix is the exit country that the Tor instance was started with
        via ExitNodes {cc} + StrictNodes 1, so the record keeps that country
        instead of relying on geo lookup). These endpoints are always kept,
        re-verified every cycle and tagged proxy_type=tor.
        """
        entries: Dict[str, Set[str]] = {}
        path = Path(self.config.tor_file)
        if not path.exists():
            return entries
        label = f"tor:{path.name}"
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return entries
        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            country = ""
            if "|" in line:
                line, _, suffix = line.partition("|")
                suffix = suffix.strip().upper()
                if len(suffix) == 2 and suffix.isalpha():
                    country = suffix
                line = line.strip()
            normalized = normalize_manual_proxy(line)
            if not normalized:
                continue
            entries.setdefault(normalized, set()).add(label)
            record = self.records.setdefault(normalized, ProxyRecord(proxy=normalized))
            record.manual = True  # locally managed: always kept, verified first
            record.proxy_type = "tor"
            if country:
                record.country = country
        return entries

    async def collect_candidates(self) -> Dict[str, Set[str]]:
        candidate_sources: DefaultDict[str, Set[str]] = defaultdict(set)
        total_sources = len(self.sources)
        completed_sources = 0

        self._emit_progress(
            phase="collecting_sources",
            total_sources=total_sources,
            completed_sources=0,
            collected_candidates=0,
        )

        # M-2: Limit concurrent source fetches to avoid port exhaustion on
        # slow connections. Reuse the same max_concurrent cap as verification.
        source_sem = asyncio.Semaphore(self.config.max_concurrent)

        async def worker(url: str) -> None:
            nonlocal completed_sources
            async with source_sem:
                try:
                    result = await self._fetch_source(url)
                except Exception as exc:
                    self.source_counts[url] = 0
                    self.source_errors[url] = exc.__class__.__name__
                    result = set()

            for proxy in result:
                candidate_sources[proxy].add(url)

            completed_sources += 1
            self._emit_progress(
                phase="collecting_sources",
                current_source=url,
                current_source_count=len(result),
                total_sources=total_sources,
                completed_sources=completed_sources,
                collected_candidates=len(candidate_sources),
            )

        await asyncio.gather(*(worker(url) for url in self.sources))

        # Merge user-supplied proxies (paid residential etc.) and local Tor
        # endpoints (Tor-manager.py) — always kept and verified first.
        pinned: Dict[str, Set[str]] = {}
        for mapping in (self.load_manual_proxies(), self.load_tor_proxies()):
            for proxy, tags in mapping.items():
                pinned.setdefault(proxy, set()).update(tags)
                candidate_sources[proxy].update(tags)

        ranked = sorted(
            candidate_sources,
            key=lambda proxy: (
                0 if self.records.get(proxy) and self.records[proxy].manual else 1,
                -len(candidate_sources[proxy]),
                -(
                    self.records[proxy].successful_checks
                    if proxy in self.records
                    else 0
                ),
                self.records[proxy].consecutive_failures
                if proxy in self.records
                else 0,
                proxy,
            ),
        )[: self.config.max_candidates]

        trimmed: Dict[str, Set[str]] = {}
        for proxy in ranked:
            trimmed[proxy] = candidate_sources[proxy]
            record = self.records.setdefault(proxy, ProxyRecord(proxy=proxy))
            record.add_sources(candidate_sources[proxy])

        # Never let the candidate cap drop user-supplied / managed proxies.
        for proxy, tags in pinned.items():
            if proxy not in trimmed:
                trimmed[proxy] = tags
                record = self.records.setdefault(proxy, ProxyRecord(proxy=proxy))
                record.add_sources(tags)

        # Country-targeted sources: pre-tag records with the list's country so
        # per-country coverage grows immediately (geo enrichment only fills
        # gaps for records from non-country sources).
        if self.source_country:
            for proxy, tags in trimmed.items():
                record = self.records.get(proxy)
                if record is None or record.country:
                    continue
                for url in tags:
                    country_code = self.source_country.get(url)
                    if country_code:
                        record.country = country_code
                        break

        self._emit_progress(
            phase="collect_complete",
            total_sources=total_sources,
            completed_sources=completed_sources,
            collected_candidates=len(trimmed),
        )
        return trimmed

    def _needs_recheck(self, record: ProxyRecord) -> bool:
        return (
            utc_now() - record.last_checked
        ).total_seconds() >= self.config.verify_interval

    def _select_collect_batch(
        self, candidate_sources: Dict[str, Set[str]]
    ) -> List[str]:
        batch: List[str] = []
        for proxy in candidate_sources:
            record = self.records.get(proxy)
            if (
                record is None
                or proxy not in self.active_proxies
                or self._needs_recheck(record)
            ):
                batch.append(proxy)
        # User-supplied proxies are verified first so they join the pool ASAP.
        batch.sort(
            key=lambda proxy: (
                0 if self.records.get(proxy) and self.records[proxy].manual else 1
            )
        )
        return batch[: self.config.max_candidates]

    def _select_reverify_batch(self, exclude: Optional[Set[str]] = None) -> List[str]:
        excluded = exclude or set()
        records = [
            self.records[proxy]
            for proxy in self.active_proxies
            if proxy in self.records and proxy not in excluded
        ]
        records.sort(
            key=lambda item: (item.last_checked.timestamp(), -item.score, item.proxy)
        )
        return [record.proxy for record in records[: self.config.verify_batch_size]]

    async def verify_proxies(self, proxies: Sequence[str]) -> List[ProbeOutcome]:
        if not self.session:
            raise RuntimeError("harvester session is not ready")

        semaphore = asyncio.Semaphore(self.config.max_concurrent)
        outcomes: List[ProbeOutcome] = []
        total = len(proxies)
        verified = 0
        working = 0

        self._emit_progress(
            phase="verifying_proxies",
            total_verify=total,
            verified_count=0,
            working_count=0,
        )

        async def worker(proxy: str) -> None:
            nonlocal verified, working
            async with semaphore:
                if self.session is None:
                    return
                outcome = await probe_proxy(
                    session=self.session,  # type: ignore[arg-type]
                    proxy=proxy,
                    test_urls=self.config.test_urls,
                    timeout_seconds=self.config.verify_timeout,
                    user_agent=self.config.user_agent,
                )
                record = self.records.setdefault(proxy, ProxyRecord(proxy=proxy))
                if outcome.working:
                    record.record_success(
                        outcome.response_time,
                        outcome.probe_url,
                        outcome.origin,
                        self.config.max_response_time,
                    )
                    working += 1
                else:
                    record.record_failure(
                        outcome.error, outcome.probe_url, self.config.max_response_time
                    )
                outcomes.append(outcome)
                verified += 1
                self._emit_progress(
                    phase="verifying_proxies",
                    current_proxy=proxy,
                    total_verify=total,
                    verified_count=verified,
                    working_count=working,
                    active_now=len(self.active_proxies),
                )

        await asyncio.gather(*(worker(proxy) for proxy in proxies))
        self._rebuild_active_proxies()
        self._emit_progress(
            phase="verify_complete",
            total_verify=total,
            verified_count=verified,
            working_count=working,
            active_now=len(self.active_proxies),
        )
        return outcomes

    def _prune_records(self) -> None:
        stale_seconds = max(self.config.stale_after_seconds * 2.0, 3600.0)
        remove: List[str] = []

        for proxy, record in self.records.items():
            if proxy in self.active_proxies or record.manual:
                continue
            age = (utc_now() - record.last_checked).total_seconds()
            # M-1: Require at least 5 checks before permanently pruning a proxy.
            # Free proxies are unstable — 2 failures is too aggressive a threshold.
            if record.successful_checks == 0 and record.total_checks >= 5:
                remove.append(proxy)
            elif (
                age >= stale_seconds
                and record.consecutive_failures >= self.config.max_consecutive_failures
            ):
                remove.append(proxy)

        for proxy in remove:
            self.records.pop(proxy, None)

        if len(self.records) > self.config.max_stored_records:
            inactive = [
                (proxy, record)
                for proxy, record in self.records.items()
                if proxy not in self.active_proxies and not record.manual
            ]
            inactive.sort(
                key=lambda x: (
                    x[1].score,
                    x[1].last_checked.timestamp(),
                )
            )
            excess = len(self.records) - self.config.max_stored_records
            for proxy, _ in inactive[:excess]:
                self.records.pop(proxy, None)

    async def run_cycle(
        self, force_collect: bool = False, force_verify: bool = False
    ) -> Dict[str, Any]:
        summary: Dict[str, Any] = {
            "did_collect": False,
            "did_verify": False,
            "collected_candidates": 0,
            "verified_proxies": 0,
            "active_proxies": len(self.active_proxies),
            "added_active": 0,
            "removed_active": 0,
        }
        previous_active = set(self.active_proxies)
        verified_now: Set[str] = set()
        now = time.monotonic()

        self._emit_progress(
            phase="cycle_start",
            active_now=len(self.active_proxies),
        )

        if force_collect or (now - self._last_collect) >= self.config.update_interval:
            candidates = await self.collect_candidates()
            summary["did_collect"] = True
            summary["collected_candidates"] = len(candidates)
            batch = self._select_collect_batch(candidates)
            if batch:
                # Verify in chunks and publish the pool after every chunk so a
                # fresh start becomes usable within minutes instead of waiting
                # for the whole (up to max_candidates) initial verification.
                chunk_size = max(1, self.config.verify_batch_size)
                outcomes: List[ProbeOutcome] = []
                for start in range(0, len(batch), chunk_size):
                    chunk = batch[start : start + chunk_size]
                    outcomes.extend(await self.verify_proxies(chunk))
                    self._prune_records()
                    self._rebuild_active_proxies()
                    await self.save_pool()
                summary["verified_proxies"] += len(outcomes)
                verified_now.update(outcome.proxy for outcome in outcomes)
            self._last_collect = time.monotonic()

        now = time.monotonic()
        if force_verify or (now - self._last_verify) >= self.config.verify_interval:
            batch = self._select_reverify_batch(exclude=verified_now)
            if batch:
                outcomes = await self.verify_proxies(batch)
                summary["verified_proxies"] += len(outcomes)
            summary["did_verify"] = True
            self._last_verify = time.monotonic()

        self._prune_records()
        self._rebuild_active_proxies()
        await self._enrich_pool()
        await self._probe_platforms()
        summary["active_proxies"] = len(self.active_proxies)
        summary["added_active"] = len(self.active_proxies - previous_active)
        summary["removed_active"] = len(previous_active - self.active_proxies)

        best = self.best_proxy()
        if best:
            summary["best_proxy"] = best.proxy
            summary["best_score"] = best.score
            summary["best_response_time"] = best.avg_response_time

        await self.save_pool()
        self._emit_progress(
            phase="cycle_complete",
            active_now=summary["active_proxies"],
            collected_candidates=summary["collected_candidates"],
            verified_count=summary["verified_proxies"],
            added_active=summary["added_active"],
            removed_active=summary["removed_active"],
            best_proxy=summary.get("best_proxy", ""),
        )
        return summary
