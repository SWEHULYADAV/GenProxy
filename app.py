#!/usr/bin/env python3
"""
app.py — Root application entry point for Proxy Generation & Multi-Route Service.

Usage:
    python app.py                         # Start Proxy API service (default on 127.0.0.1:1712)
    python app.py --port 1712 --warmup    # Start Proxy API service with custom arguments
    python app.py api [args]              # Run backend/Proxy-api.py
    python app.py live [args]             # Run backend/Live-proxies.py (terminal monitor window)
    python app.py harvest [args]          # Run backend/Proxy-harvester.py
    python app.py mcp [args]              # Run backend/proxy_mcp.py (AI MCP server)
    python app.py test [args]             # Run backend/Test-proxy.py
    python app.py tor [args]              # Run backend/Tor-manager.py
    python app.py direct [args]           # Run backend/direct_fetch.py
    python app.py warm [args]             # Run backend/akamai_warm.py
    python app.py browser [args]          # Run backend/stealth_browser.py
"""
from __future__ import annotations

import os
import runpy
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"

# Ensure backend and root directories are in sys.path
for path in (str(BACKEND_DIR), str(ROOT_DIR)):
    if path not in sys.path:
        sys.path.insert(0, path)

# Subcommand dispatch table
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


def main() -> None:
    args = sys.argv[1:]
    target_script = "Proxy-api.py"

    if args and args[0].lower() in SUBCOMMANDS:
        cmd = args[0].lower()
        target_script = SUBCOMMANDS[cmd]
        sys.argv = [sys.argv[0]] + args[1:]

    script_path = BACKEND_DIR / target_script
    if not script_path.exists():
        print(f"Error: Target script {script_path} does not exist.", file=sys.stderr)
        sys.exit(1)

    # Execute target script in __main__ namespace
    runpy.run_path(str(script_path), run_name="__main__")


if __name__ == "__main__":
    main()
