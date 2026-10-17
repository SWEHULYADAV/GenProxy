#!/usr/bin/env python3
"""
proxy_mcp.py — MCP (Model Context Protocol) server for the local Proxy Generator.

Lets any MCP-capable AI host (OpenCode, Claude Desktop, Cursor, ...) operate
this project: start/stop the local service, inspect the active proxy pool,
and fetch URLs through the rotating proxies.

It is a thin, local-only wrapper around the running Proxy API (REST, default
http://127.0.0.1:1712) plus a small amount of process control for start/stop.

Connection settings resolve in this priority order:
  1. Environment variables: PROXY_MCP_BASE_URL / PROXY_MCP_API_KEY / PROXY_MCP_TUNNEL_KEY
  2. proxy-service-config.env in this folder (written by
     Setup-Authenticated-Proxy-Service.bat)

Run directly (stdio transport):
    venv\\Scripts\\python.exe proxy_mcp.py

Install deps first:
    venv\\Scripts\\pip install -r requirements-mcp.txt
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

import aiohttp
from mcp.server import MCPServer

PROJECT_DIR = Path(__file__).resolve().parent
CONFIG_FILE = PROJECT_DIR / "proxy-service-config.env"
OUTPUT_DIR = PROJECT_DIR / "output"
PID_FILE = OUTPUT_DIR / ".proxy_service.pid"
SERVICE_LOG = OUTPUT_DIR / "proxy_service_mcp.log"

logger = logging.getLogger("proxy_mcp")

mcp = MCPServer(
    "Proxy Generator",
    instructions=(
        "Operate the local Proxy Generator service (free-proxy harvesting + local "
        "HTTP proxy tunnel on this machine). Typical flow: 1) call proxy_service_status "
        "to check whether the service is running; 2) proxy_service_start if it is down; "
        "3) use proxy_fetch to download a public URL through rotating proxies, or "
        "proxy_list / proxy_next / proxy_random to inspect and hand out pool entries. "
        "proxy_reload forces a pool refresh (server rate-limits to once per 60 s and it "
        "takes 30-90 s to finish). Keys are read from proxy-service-config.env or the "
        "PROXY_MCP_* environment variables; never ask the user for keys. All targets "
        "must resolve to public IP addresses (localhost/LAN targets are rejected). "
        "Use proxy_type=\"residential\" on proxy_list/proxy_next/proxy_random/proxy_fetch "
        "to route through the user's own residential proxies (residential-proxies.txt), "
        "which accept an optional '|CC' country tag (gate.provider.com:8080|SG). "
        "The local tunnel pins the exit country via the username: "
        "http://proxy-sg:<tunnel_key>@127.0.0.1:1909 (or proxy-country-sg; plain "
        "'proxy' stays any-country). proxy_fetch also accepts route=\"direct\" "
        "(own IP, no proxy; best for Myntra/Nykaa/Flipkart-class sites) and "
        "route=\"unlock\" (external anti-block API), plus http_client=\"curl_cffi\"."
    ),
)


# ---------------------------------------------------------------------------
#  Config + HTTP helpers
# ---------------------------------------------------------------------------

def _read_env_file(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return values
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _resolve_config() -> Dict[str, Any]:
    file_cfg = _read_env_file(CONFIG_FILE)
    host = os.environ.get("PROXY_MCP_HOST") or file_cfg.get("PROXY_SERVICE_HOST", "127.0.0.1")
    port = os.environ.get("PROXY_MCP_PORT") or file_cfg.get("PROXY_SERVICE_API_PORT", "1712")
    base_url = (os.environ.get("PROXY_MCP_BASE_URL") or f"http://{host}:{port}").rstrip("/")
    api_key = os.environ.get("PROXY_MCP_API_KEY") or file_cfg.get("PROXY_SERVICE_API_KEY", "")
    tunnel_key = (
        os.environ.get("PROXY_MCP_TUNNEL_KEY")
        or os.environ.get("PROXY_SERVICE_TUNNEL_KEY")
        or file_cfg.get("PROXY_SERVICE_TUNNEL_KEY", "")
    )
    return {
        "base_url": base_url,
        "api_key": api_key,
        "tunnel_key": tunnel_key,
        "tunnel_user": file_cfg.get("PROXY_SERVICE_TUNNEL_USER", "proxy"),
        "tunnel_port": file_cfg.get("PROXY_SERVICE_TUNNEL_PORT", "1909"),
        "config_file": str(CONFIG_FILE),
        "config_exists": CONFIG_FILE.exists(),
    }


def _dump(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, default=str)


async def _http_json(
    method: str,
    path: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    body: Optional[Dict[str, Any]] = None,
    timeout: float = 60.0,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    cfg = _resolve_config()
    url = cfg["base_url"] + path
    headers: Dict[str, str] = {}
    key = cfg["api_key"] if api_key is None else api_key
    if key:
        headers["X-API-Key"] = key
    query = {k: str(v) for k, v in (params or {}).items() if v is not None}
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    try:
        async with aiohttp.ClientSession(timeout=client_timeout, trust_env=False) as session:
            async with session.request(
                method, url, params=query or None, json=body, headers=headers
            ) as response:
                text = await response.text()
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError:
                    payload = {"raw": text[:4000]}
                if not isinstance(payload, dict):
                    payload = {"data": payload}
                payload.setdefault("http_status", response.status)
                if response.status == 401:
                    payload.setdefault(
                        "hint",
                        "Service rejected the API key. Set PROXY_MCP_API_KEY or run "
                        "Setup-Authenticated-Proxy-Service.bat so both sides use the same key.",
                    )
                return payload
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
        return {
            "ok": False,
            "error": "service_unreachable",
            "detail": f"{exc.__class__.__name__}: {exc}",
            "base_url": cfg["base_url"],
            "hint": (
                "The local proxy service is not reachable. Start it with "
                "proxy_service_start (or run Start-Live-Proxies.bat) and retry."
            ),
        }


async def _probe_health(timeout: float = 4.0) -> Dict[str, Any]:
    return await _http_json("GET", "/health", timeout=timeout, api_key="")


def _read_pid() -> Optional[int]:
    try:
        return int(PID_FILE.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _find_venv_python() -> Optional[Path]:
    for rel in ("venv/Scripts/python.exe", "venv/bin/python"):
        candidate = PROJECT_DIR / rel
        if candidate.exists():
            return candidate
    return None


# ---------------------------------------------------------------------------
#  Read-only tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def proxy_service_status() -> str:
    """Check whether the local proxy service is running (health + PID + config summary)."""
    cfg = _resolve_config()
    health = await _probe_health()
    running = health.get("http_status") == 200 and health.get("ok", True)
    pid = _read_pid()
    return _dump({
        "ok": True,
        "service_running": running,
        "pid": pid,
        "started_by_mcp": pid is not None,
        "base_url": cfg["base_url"],
        "config_file": cfg["config_file"],
        "config_file_exists": cfg["config_exists"],
        "api_key_configured": bool(cfg["api_key"]),
        "tunnel_key_configured": bool(cfg["tunnel_key"]),
        "health": health if running else None,
        "hint": None if running else (
            "Service is down. Call proxy_service_start, or run Start-Live-Proxies.bat, "
            "or run Setup-Authenticated-Proxy-Service.bat first if no config exists."
        ),
    })


@mcp.tool()
async def proxy_status() -> str:
    """Full service status: active pool size, known records, best proxy, refresh progress, output files."""
    return _dump(await _http_json("GET", "/status"))


@mcp.tool()
async def proxy_stats() -> str:
    """Active pool analytics: breakdown by protocol, country and anonymity + average score/response time."""
    return _dump(await _http_json("GET", "/stats"))


@mcp.tool()
async def proxy_coverage() -> str:
    """Country coverage report: active proxies per country vs all ISO-3166 countries, plus the missing list.

    Use this to see which countries your pool can currently serve — handy for
    scrapers that need per-country proxies. Shows covered_countries,
    coverage_percent, by_country counts and the missing ISO-2 codes.
    """
    return _dump(await _http_json("GET", "/coverage"))


@mcp.tool()
async def proxy_tunnel_status() -> str:
    """Proxy tunnel info and live usage counters (total requests, connect/http split, successful, failed)."""
    return _dump(await _http_json("GET", "/tunnel-status"))


@mcp.tool()
async def proxy_list(
    protocol: Optional[str] = None,
    country: Optional[str] = None,
    anonymity: Optional[str] = None,
    proxy_type: Optional[str] = None,
    min_score: float = 0.0,
    limit: int = 50,
) -> str:
    """List active (verified working) proxies ranked by score.

    Filters (all optional): protocol = http | socks4 | socks5,
    country = ISO-2 code e.g. US, anonymity = elite | anonymous | transparent,
    proxy_type = residential | mobile | datacenter | tor (residential = your own paid
    proxies from residential-proxies.txt, or free ones that look non-datacenter),
    min_score = 0.0-1.0 quality floor.
    """
    params: Dict[str, Any] = {"limit": limit, "min_score": min_score}
    if protocol:
        params["protocol"] = protocol
    if country:
        params["country"] = country
    if anonymity:
        params["anonymity"] = anonymity
    if proxy_type:
        params["proxy_type"] = proxy_type
    return _dump(await _http_json("GET", "/proxies", params=params))


@mcp.tool()
async def proxy_next(
    protocol: Optional[str] = None,
    country: Optional[str] = None,
    anonymity: Optional[str] = None,
    proxy_type: Optional[str] = None,
    min_score: float = 0.0,
    skip_cooldown: float = 0.0,
) -> str:
    """Return the next proxy in round-robin rotation (one proxy per call, advanced each time).

    Same filters as proxy_list. skip_cooldown>0 skips proxies used in the last N seconds.
    """
    params: Dict[str, Any] = {"min_score": min_score, "skip_cooldown": skip_cooldown}
    if protocol:
        params["protocol"] = protocol
    if country:
        params["country"] = country
    if anonymity:
        params["anonymity"] = anonymity
    if proxy_type:
        params["proxy_type"] = proxy_type
    return _dump(await _http_json("GET", "/next", params=params))


@mcp.tool()
async def proxy_random(
    protocol: Optional[str] = None,
    country: Optional[str] = None,
    anonymity: Optional[str] = None,
    proxy_type: Optional[str] = None,
    min_score: float = 0.0,
) -> str:
    """Return one random active proxy matching the filters (protocol/country/anonymity/proxy_type/min_score)."""
    params: Dict[str, Any] = {"min_score": min_score}
    if protocol:
        params["protocol"] = protocol
    if country:
        params["country"] = country
    if anonymity:
        params["anonymity"] = anonymity
    if proxy_type:
        params["proxy_type"] = proxy_type
    return _dump(await _http_json("GET", "/random", params=params))


# ---------------------------------------------------------------------------
#  Action tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def proxy_fetch(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    timeout: Optional[float] = None,
    max_attempts: int = 10,
    expected_status: Optional[int] = None,
    min_score: float = 0.0,
    allow_redirects: bool = True,
    session_id: Optional[str] = None,
    country: Optional[str] = None,
    proxy_type: Optional[str] = None,
    detect_block_pages: bool = True,
    route: str = "auto",
    http_client: str = "auto",
    max_body_chars: int = 20000,
) -> str:
    """Fetch a public http/https URL through the rotating proxy pool; returns JSON + response body.

    This is the main workhorse (smart curl). The service retries on other proxies
    automatically when one fails or returns a block/captcha page. Response includes
    which proxy was used, status_code, final_url, headers, body text and attempt log.
    Binary bodies are omitted and reported via body_base64_omitted/body_bytes_estimate.
    Large text bodies are truncated to max_body_chars (default 20000).
    session_id pins the same proxy for a logical user flow (sticky session).
    country (ISO-2, e.g. "DE") restricts routing to proxies from that country.
    proxy_type (e.g. "residential") restricts routing to that proxy class.
    route: "auto" (default) | "pool" | "direct" | "unlock".
      "direct" fetches from this machine's own IP with a real Chrome TLS
      fingerprint (rate-limited server-side) — full pages on Akamai-fronted
      Indian stores (Myntra, Nykaa, Flipkart...) that 403 datacenter proxies.
      "unlock" routes through the external anti-block API (needs service-side
      --unlock-url-template / --unlock-api-key configuration).
    http_client: "auto" | "aiohttp" | "curl_cffi" — per-request client override
      (curl_cffi = JA3-correct Chrome TLS fingerprint).
    """
    request_body: Dict[str, Any] = {
        "url": url,
        "method": method.upper(),
        "max_attempts": max_attempts,
        "min_score": min_score,
        "allow_redirects": allow_redirects,
        "detect_block_pages": detect_block_pages,
    }
    if headers:
        request_body["headers"] = headers
    if body is not None:
        request_body["body"] = body
    if timeout:
        request_body["timeout"] = timeout
    if expected_status is not None:
        request_body["expected_status"] = expected_status
    if session_id:
        request_body["session_id"] = session_id
    if country:
        request_body["country"] = country
    if proxy_type:
        request_body["proxy_type"] = proxy_type
    if route and route != "auto":
        request_body["route"] = route
    if http_client and http_client != "auto":
        request_body["http_client"] = http_client

    payload = await _http_json(
        "POST", "/fetch", body=request_body, timeout=(timeout or 30.0) * 3 + 120.0
    )

    if isinstance(payload.get("body"), str) and len(payload["body"]) > max_body_chars:
        full_len = len(payload["body"])
        payload["body"] = payload["body"][:max_body_chars]
        payload["body_truncated"] = True
        payload["body_full_chars"] = full_len
    if payload.get("body_base64"):
        b64 = payload.pop("body_base64")
        payload["body_base64_omitted"] = True
        payload["body_bytes_estimate"] = len(b64) * 3 // 4
    return _dump(payload)


@mcp.tool()
async def proxy_reload() -> str:
    """Force an immediate pool refresh cycle (collect + verify).

    The server rate-limits this to once per 60 seconds and a full cycle takes
    roughly 30-90 seconds to complete.
    """
    return _dump(await _http_json("POST", "/reload", timeout=180.0))


@mcp.tool()
async def proxy_service_start(warmup: bool = False, wait_seconds: float = 60.0) -> str:
    """Start the local proxy service (Proxy-api.py) in the background if it is not running.

    warmup=True makes the service build one full pool before answering traffic
    (slower start, better first results). Requires proxy-service-config.env or
    PROXY_MCP_API_KEY / PROXY_MCP_TUNNEL_KEY env vars.
    """
    cfg = _resolve_config()
    health = await _probe_health()
    if health.get("http_status") == 200:
        return _dump({"ok": True, "already_running": True, "pid": _read_pid(), "health": health})

    if not cfg["api_key"] or not cfg["tunnel_key"]:
        return _dump({
            "ok": False,
            "error": "missing_keys",
            "hint": (
                "Run Setup-Authenticated-Proxy-Service.bat once (creates "
                "proxy-service-config.env), or set PROXY_MCP_API_KEY and "
                "PROXY_MCP_TUNNEL_KEY environment variables for this MCP server."
            ),
        })

    python = _find_venv_python() or Path(sys.executable)
    cmd = [str(python), str(PROJECT_DIR / "Proxy-api.py")]
    if warmup:
        cmd.append("--warmup")

    env = os.environ.copy()
    env["PROXY_SERVICE_API_KEY"] = cfg["api_key"]
    env["PROXY_SERVICE_TUNNEL_KEY"] = cfg["tunnel_key"]
    # Forward pool-tuning knobs from proxy-service-config.env so the service
    # grows a bigger verified pool for heavy scraping jobs.
    file_cfg = _read_env_file(CONFIG_FILE)
    for name in (
        "PROXY_SERVICE_MAX_CANDIDATES",
        "PROXY_SERVICE_VERIFY_BATCH_SIZE",
        "PROXY_SERVICE_COUNTRY_SOURCES",
        "PROXY_SERVICE_RESIDENTIAL_FILE",
        "PROXY_SERVICE_TOR_FILE",
        "PROXY_SERVICE_FETCH_CLIENT",
        "PROXY_SERVICE_CURL_WORKERS",
        "PROXY_SERVICE_CURL_IMPERSONATE",
        "PROXY_SERVICE_DIRECT_CLIENT",
        "PROXY_SERVICE_DIRECT_CONCURRENCY",
        "PROXY_SERVICE_DIRECT_MIN_INTERVAL",
        "PROXY_SERVICE_UNLOCK_URL_TEMPLATE",
        "PROXY_SERVICE_UNLOCK_API_KEY",
        "PROXY_SERVICE_UNLOCK_TIMEOUT",
        "PROXY_SERVICE_UNLOCK_HOSTS",
    ):
        value = file_cfg.get(name)
        if value:
            env[name] = value

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    popen_kwargs: Dict[str, Any] = {}
    if os.name == "nt":
        popen_kwargs["creationflags"] = (
            subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        )
    else:
        popen_kwargs["start_new_session"] = True

    with open(SERVICE_LOG, "ab") as log_file:
        process = subprocess.Popen(
            cmd,
            cwd=str(PROJECT_DIR),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            **popen_kwargs,
        )
    PID_FILE.write_text(str(process.pid), encoding="utf-8")
    logger.info("started proxy service pid=%s warmup=%s", process.pid, warmup)

    confirmed = False
    exited = False
    deadline = time.monotonic() + max(wait_seconds, 5.0)
    while time.monotonic() < deadline:
        await asyncio.sleep(1.0)
        if process.poll() is not None:
            exited = True
            break
        health = await _probe_health()
        if health.get("http_status") == 200:
            confirmed = True
            break

    if exited:
        return _dump({
            "ok": False,
            "error": "service_exited_immediately",
            "exit_code": process.returncode,
            "log_file": str(SERVICE_LOG),
            "hint": "Check the log file; likely a port conflict or Python error.",
        })

    return _dump({
        "ok": True,
        "started": True,
        "pid": process.pid,
        "warmup": warmup,
        "health_confirmed": confirmed,
        "log_file": str(SERVICE_LOG),
        "health": health if confirmed else None,
        "hint": None if confirmed else (
            "Service has not answered /health yet; it may still be starting. "
            "Check again with proxy_service_status."
        ),
    })


@mcp.tool()
async def proxy_service_stop(wait_seconds: float = 25.0) -> str:
    """Stop the proxy service if it was started by proxy_service_start (via the PID file).

    A service started elsewhere (e.g. by Start-Live-Proxies.bat) is NOT killed;
    the tool tells you to stop it in its own window instead.
    """
    pid = _read_pid()
    health = await _probe_health()
    running = health.get("http_status") == 200

    if pid is None:
        if running:
            return _dump({
                "ok": False,
                "error": "not_started_by_mcp",
                "hint": (
                    "The service is running but was not started by the MCP server. "
                    "Stop it in its own console window (or Task Manager)."
                ),
            })
        return _dump({"ok": True, "already_stopped": True})

    killed = False
    if os.name == "nt":
        result = subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            text=True,
        )
        killed = result.returncode == 0
    else:
        try:
            os.kill(pid, signal.SIGTERM)
            killed = True
        except ProcessLookupError:
            killed = False
        except OSError:
            killed = False

    still_running = False
    deadline = time.monotonic() + max(wait_seconds, 3.0)
    while time.monotonic() < deadline:
        await asyncio.sleep(1.0)
        health = await _probe_health()
        if health.get("http_status") != 200:
            still_running = False
            break
        still_running = True

    try:
        PID_FILE.unlink()
    except OSError:
        pass
    logger.info("stopped proxy service pid=%s killed=%s", pid, killed)

    return _dump({
        "ok": not still_running,
        "stopped": not still_running,
        "pid": pid,
        "kill_command_succeeded": killed,
        "still_responding": still_running,
        "hint": None if not still_running else "Service still answers /health; stop it manually.",
    })


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
