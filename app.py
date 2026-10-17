#!/usr/bin/env python3
"""
app.py — Unified Pure-Python Entry Point for Proxy Generation & Multi-Route Service.

Replaces legacy .bat scripts with a modern, cross-platform CLI:
    python app.py                         # Start Proxy API service (auto-reads proxy-service-config.env)
    python app.py setup                   # Initialize or regenerate proxy-service-config.env with secure keys
    python app.py live                    # Run terminal live monitor window
    python app.py both                    # Start both Live Monitor and Proxy API service concurrently
    python app.py harvest                 # Run standalone proxy harvester
    python app.py sources                 # Check backend/proxy_sources.py for dead / empty lists
    python app.py mcp                     # Run Model Context Protocol server (for AI agents)
    python app.py tor                     # Run local country-pinned Tor manager
    python app.py direct [url]            # Direct fetch with real Chrome TLS fingerprint
    python app.py warm [url]              # Akamai sensor cookie warmer & replay helper
    python app.py browser [url]           # Stealth browser automation runner
    python app.py test                    # Run proxy verification test suite
"""
from __future__ import annotations

import os
import runpy
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Dict

ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
CONFIG_FILE = ROOT_DIR / "proxy-service-config.env"
EXAMPLE_CONFIG_FILE = ROOT_DIR / "proxy-service-config.example.env"

# Ensure backend and root directories are in sys.path
for path in (str(BACKEND_DIR), str(ROOT_DIR)):
    if path not in sys.path:
        sys.path.insert(0, path)

SUBCOMMANDS = {
    "api": "Proxy-api.py",
    "live": "Live-proxies.py",
    "harvest": "Proxy-harvester.py",
    "harvester": "Proxy-harvester.py",
    "mcp": "proxy_mcp.py",
    "test": "Test-proxy.py",
    "tor": "Tor-manager.py",
    "direct": "direct_fetch.py",
    "warm": "akamai_warm.py",
    "browser": "stealth_browser.py",
}


def load_env_file(filepath: Path) -> Dict[str, str]:
    """Parse a simple key=value .env file and export to os.environ if not already set."""
    values: Dict[str, str] = {}
    if not filepath.exists():
        return values
    for line in filepath.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key, val = key.strip(), val.strip()
        values[key] = val
        if key not in os.environ:
            os.environ[key] = val
    return values


def run_setup() -> None:
    """Pure-Python interactive or automatic setup for proxy-service-config.env."""
    print("=" * 60)
    print(" Proxy Generator — Pure Python Environment Setup")
    print("=" * 60)

    if CONFIG_FILE.exists():
        print(f"Existing config file found at: {CONFIG_FILE}")
        resp = input("Do you want to regenerate API and tunnel keys? (y/N): ").strip().lower()
        if resp != "y":
            print("Setup cancelled. Existing config kept unchanged.")
            return

    api_key = secrets.token_hex(16)
    tunnel_key = secrets.token_hex(16)

    config_content = f"""# Proxy Service Configuration — Local Runtime
PROXY_SERVICE_HOST=127.0.0.1
PROXY_SERVICE_API_PORT=1712
PROXY_SERVICE_TUNNEL_PORT=1909
PROXY_SERVICE_TUNNEL_USER=proxy
PROXY_SERVICE_API_KEY={api_key}
PROXY_SERVICE_TUNNEL_KEY={tunnel_key}
PROXY_SERVICE_WARMUP=1
PROXY_SERVICE_LOG_REQUESTS=1
PROXY_SERVICE_OUTPUT_ROOT=output

# Pool tuning
PROXY_SERVICE_MAX_CANDIDATES=3000
PROXY_SERVICE_VERIFY_BATCH_SIZE=200
PROXY_SERVICE_FETCH_CLIENT=curl_cffi
"""
    CONFIG_FILE.write_text(config_content.strip() + "\n", encoding="utf-8")
    print("\n[OK] Generated configuration file:")
    print(f"  REST API  : http://127.0.0.1:1712")
    print(f"  Tunnel    : http://127.0.0.1:1909")
    print(f"  API Key   : {api_key[:4]}****************************")
    print(f"  Tunnel Key: {tunnel_key[:4]}****************************")
    print(f"  Saved to  : {CONFIG_FILE}\n")
    print("You can now start the service simply by running:")
    print("  python app.py\n")


def run_both() -> None:
    """Launch both Live Monitor and API Service concurrently."""
    load_env_file(CONFIG_FILE)
    python_exe = sys.executable

    print("[Launcher] Starting Live Proxy Monitor & API Service...")
    api_cmd = [python_exe, str(ROOT_DIR / "app.py"), "api"]
    live_cmd = [python_exe, str(ROOT_DIR / "app.py"), "live"]

    p_api = subprocess.Popen(api_cmd, cwd=str(ROOT_DIR))
    p_live = subprocess.Popen(live_cmd, cwd=str(ROOT_DIR))

    try:
        p_api.wait()
    except KeyboardInterrupt:
        print("\n[Launcher] Stopping services...")
        p_api.terminate()
        p_live.terminate()
        p_api.wait()
        p_live.wait()


def run_export() -> None:
    """Export active proxies or threat intelligence evidence directly from session storage."""
    import argparse
    import csv
    import io
    import json
    from datetime import datetime

    parser = argparse.ArgumentParser(description="Export proxies or threat intelligence evidence.")
    parser.add_argument("--format", choices=["txt", "csv", "json"], default="txt", help="Export format (default: txt)")
    parser.add_argument("--output", "-o", help="Output file path (default: print to stdout)")
    parser.add_argument("--country", "-c", help="Filter by ISO-2 country code (e.g. US, DE, IN)")
    parser.add_argument("--protocol", "-p", help="Filter by protocol (http, socks5, socks4)")
    parser.add_argument("--anonymity", "-a", help="Filter by anonymity (elite, anonymous, transparent)")
    parser.add_argument("--speed-tier", "-s", help="Filter by speed tier (fast, medium, slow)")
    parser.add_argument("--proxy-type", "-t", help="Filter by proxy type (residential, datacenter, mobile)")
    parser.add_argument("--min-score", type=float, default=0.0, help="Minimum quality score")
    parser.add_argument("--with-scheme", action="store_true", help="Include scheme prefix in txt export")
    parser.add_argument("--input-file", help="Path to pool JSON file (default: latest in output/ directory)")

    export_args = parser.parse_args(sys.argv[2:])

    pool_file = None
    if export_args.input_file:
        pool_file = Path(export_args.input_file)
    else:
        output_root = ROOT_DIR / os.environ.get("PROXY_SERVICE_OUTPUT_ROOT", "output")
        candidates = list(output_root.glob("**/active-proxies.json")) + list(output_root.glob("**/active_proxies.json"))
        if candidates:
            candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            pool_file = candidates[0]

    if not pool_file or not pool_file.exists():
        print(f"Error: No active proxy pool JSON found. Start the service first (python app.py) or run: python app.py harvest", file=sys.stderr)
        sys.exit(1)

    try:
        data = json.loads(pool_file.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"Error reading pool file {pool_file}: {e}", file=sys.stderr)
        sys.exit(1)

    raw_proxies = data if isinstance(data, list) else data.get("proxies", [])

    filtered = []
    for p in raw_proxies:
        if export_args.country and p.get("country", "").upper() != export_args.country.upper():
            continue
        if export_args.protocol and p.get("protocol", "").lower() != export_args.protocol.lower():
            continue
        if export_args.anonymity and p.get("anonymity", "").lower() != export_args.anonymity.lower():
            continue
        if export_args.speed_tier and p.get("speed_tier", "").lower() != export_args.speed_tier.lower():
            continue
        if export_args.proxy_type and p.get("proxy_type", "").lower() != export_args.proxy_type.lower():
            continue
        if p.get("score", 0.0) < export_args.min_score:
            continue
        filtered.append(p)

    def _safe_endpoint(proxy_str: str):
        raw = proxy_str.split("://", 1)[-1] if "://" in proxy_str else proxy_str
        scheme = proxy_str.split("://", 1)[0] if "://" in proxy_str else "http"
        if "@" in raw:
            auth, host_port = raw.rsplit("@", 1)
            user = auth.split(":", 1)[0]
            sanitized_url = f"{scheme}://{user}:***@{host_port}"
        else:
            host_port = raw
            sanitized_url = f"{scheme}://{host_port}"
        if ":" in host_port:
            ip_part, port_part = host_port.rsplit(":", 1)
        else:
            ip_part, port_part = host_port, ""
        return ip_part, port_part, sanitized_url

    out_text = ""
    if export_args.format == "txt":
        lines = []
        for p in filtered:
            ip_part, port_part, sanitized_url = _safe_endpoint(p.get("proxy", ""))
            if export_args.with_scheme:
                lines.append(sanitized_url)
            else:
                lines.append(f"{ip_part}:{port_part}" if port_part else ip_part)
        out_text = "\n".join(lines) + ("\n" if lines else "")
    elif export_args.format == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "ip", "port", "protocol", "country", "anonymity", "speed_tier",
            "avg_response_time_ms", "success_rate", "total_checks",
            "successful_checks", "consecutive_failures", "proxy_type", "score"
        ])
        for p in filtered:
            ip_part, port_part, _ = _safe_endpoint(p.get("proxy", ""))
            writer.writerow([
                ip_part, port_part, p.get("protocol", ""), p.get("country", ""),
                p.get("anonymity", ""), p.get("speed_tier", ""),
                round(p.get("avg_response_time", 0.0) * 1000, 1),
                p.get("success_rate", 0.0), p.get("total_checks", 0),
                p.get("successful_checks", 0), p.get("consecutive_failures", 0),
                p.get("proxy_type", ""), p.get("score", 0.0)
            ])
        out_text = buf.getvalue()
    elif export_args.format == "json":
        sanitized_filtered = []
        for p in filtered:
            p_copy = dict(p)
            _, _, sanitized_url = _safe_endpoint(p.get("proxy", ""))
            p_copy["proxy"] = sanitized_url
            sanitized_filtered.append(p_copy)
        bundle = {
            "ok": True,
            "format": "threat-intelligence-evidence",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "source_pool": str(pool_file),
            "total_records": len(sanitized_filtered),
            "evidence": sanitized_filtered,
        }
        out_text = json.dumps(bundle, indent=2)

    if export_args.output:
        out_path = Path(export_args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(out_text, encoding="utf-8")
        print(f"[OK] Exported {len(filtered)} proxies to {out_path} ({export_args.format.upper()} format)")
    else:
        sys.stdout.write(out_text)


def run_sources_check() -> None:
    """Fetch every list in backend/proxy_sources.py once and report the dead or empty ones."""
    import argparse
    import asyncio
    from urllib.parse import urlsplit

    import aiohttp
    from proxy_core import HarvesterConfig, ProxyHarvester, default_sources_path, run_async_entrypoint

    parser = argparse.ArgumentParser(
        prog="app.py sources",
        description="Check every proxy list URL in backend/proxy_sources.py and show which are dead or empty.",
    )
    parser.add_argument(
        "--countries", default="off",
        help="Also check country templates for these ISO-2 codes, e.g. 'us,in,sg' or 'default' (default: off)",
    )
    opts = parser.parse_args(sys.argv[2:])

    async def check():
        harvester = ProxyHarvester(HarvesterConfig(country_source_codes=opts.countries))
        host_sems: Dict[str, asyncio.Semaphore] = {}
        async with aiohttp.ClientSession(
            headers={"User-Agent": harvester.config.user_agent}, trust_env=False
        ) as session:
            harvester.session = session

            async def one(url: str):
                host = (urlsplit(url).hostname or "").lower()
                sem = host_sems.setdefault(host, asyncio.Semaphore(
                    harvester._HOST_FETCH_LIMITS.get(host, harvester._DEFAULT_HOST_FETCH_LIMIT)))
                async with sem:
                    found = await harvester._fetch_source(url, retries=1)
                return url, len(found), harvester.source_errors.get(url, "")

            return await asyncio.gather(*(one(url) for url in harvester.sources))

    print(f"Checking lists in {default_sources_path()} ...")
    results = run_async_entrypoint(check())
    status_order = {"DEAD": 0, "ERROR": 1, "EMPTY": 2, "OK": 3}
    rows = []
    for url, count, error in results:
        if count:
            status = "OK"
        elif error.startswith("http 404") or error.startswith("http 410"):
            status = "DEAD"
        elif error:
            status = "ERROR"
        else:
            status = "EMPTY"
        rows.append((status, count, error, url))
    rows.sort(key=lambda row: (status_order[row[0]], -row[1], row[3]))
    for status, count, error, url in rows:
        print(f"{status:<6}{count:>8}  {error[:28]:<28}  {url}")
    tally = {name: sum(1 for row in rows if row[0] == name) for name in status_order}
    total = sum(row[1] for row in rows)
    print(
        f"\n{len(rows)} lists: {tally['OK']} ok ({total} entries), {tally['EMPTY']} empty, "
        f"{tally['ERROR']} erroring, {tally['DEAD']} dead."
    )
    if tally["DEAD"] or tally["ERROR"]:
        print(f"Move dead URLs to DEAD_SOURCES (or replace them) in {default_sources_path()}")


def main() -> None:
    # Always load proxy-service-config.env if present
    load_env_file(CONFIG_FILE)

    args = sys.argv[1:]

    # Handle special setup, both, and export commands
    if args and args[0].lower() in ("setup", "--setup"):
        run_setup()
        return

    if args and args[0].lower() in ("both", "--both", "start-all"):
        run_both()
        return

    if args and args[0].lower() in ("export", "--export"):
        run_export()
        return

    if args and args[0].lower() in ("sources", "--sources"):
        run_sources_check()
        return

    target_script = "Proxy-api.py"

    if args and args[0].lower() in SUBCOMMANDS:
        cmd = args[0].lower()
        target_script = SUBCOMMANDS[cmd]
        sys.argv = [sys.argv[0]] + args[1:]
    else:
        # Default behavior: run API service with warmup
        if not any(arg.startswith("--warmup") for arg in sys.argv):
            if os.environ.get("PROXY_SERVICE_WARMUP", "1") != "0":
                sys.argv.append("--warmup")

    script_path = BACKEND_DIR / target_script
    if not script_path.exists():
        print(f"Error: Target script {script_path} does not exist.", file=sys.stderr)
        sys.exit(1)

    runpy.run_path(str(script_path), run_name="__main__")


if __name__ == "__main__":
    main()
