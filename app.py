#!/usr/bin/env python3
"""
app.py — Unified Pure-Python Entry Point for Proxy Generation & Multi-Route Service.

Replaces legacy .bat scripts with a modern, cross-platform CLI:
    python app.py                         # Start Proxy API service (auto-reads proxy-service-config.env)
    python app.py setup                   # Initialize or regenerate proxy-service-config.env with secure keys
    python app.py live                    # Run terminal live monitor window
    python app.py both                    # Start both Live Monitor and Proxy API service concurrently
    python app.py harvest                 # Run standalone proxy harvester
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


def main() -> None:
    # Always load proxy-service-config.env if present
    load_env_file(CONFIG_FILE)

    args = sys.argv[1:]

    # Handle special setup and both commands
    if args and args[0].lower() in ("setup", "--setup"):
        run_setup()
        return

    if args and args[0].lower() in ("both", "--both", "start-all"):
        run_both()
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
