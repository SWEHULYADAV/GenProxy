#!/usr/bin/env python3
"""direct_fetch.py — fetch pages from THIS machine's own IP with a real
Chrome TLS fingerprint (curl_cffi), no proxy.

Why this exists
---------------
The 403s we see through free datacenter proxies are mostly IP-reputation
blocks (Akamai / DataDome / AWS WAF). The very same URLs often answer 200
from an ordinary ISP/residential IP *when the TLS fingerprint looks like
real Chrome*. Live-tested on 2026-10-17 from this machine (own IP):

  works direct: myntra.com (+category), nykaa.com (+category),
                flipkart.com (+search), jiomart.com, croma.com,
                reliancedigital.in, snapdeal.com, pinterest.com,
                etsy.com/in-en, shopsy.in (when its edge allows)
  challenge:    ajio.com, meesho.com (Akamai JS sensor — use the browser
                helper or residential), amazon.in (AWS WAF), tatacliq.com

Use this helper for own-IP work at human-ish rates and keep the proxy
service for rotation / geo / scaling.

Safety
------
* Public https targets only, no logins, no personal data.
* Courteous default pacing (`--delay 1.0`); raise it if a site complains.
* Respect each site's robots/ToS and local law.

Examples
--------
  venv\\Scripts\\python direct_fetch.py https://www.myntra.com/shoes --output shoes.html
  venv\\Scripts\\python direct_fetch.py --urls-file urls.txt --json results.json --delay 1.5
  venv\\Scripts\\python direct_fetch.py https://example.com --proxy http://user:pass@host:port

Exit codes: 0 = at least one success, 2 = all failed, 1 = usage/install error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional

try:
    from curl_cffi import requests as creq
except ImportError:  # pragma: no cover
    print("curl_cffi is not installed. Run:  venv\\Scripts\\pip install curl_cffi")
    raise SystemExit(1)

DEFAULT_IMPERSONATE = "chrome"
DEFAULT_TIMEOUT = 45.0
DEFAULT_DELAY = 1.0


def _title_of(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:80]


def _safe_filename(url: str) -> str:
    import hashlib

    host = re.sub(r"[^A-Za-z0-9._-]+", "_", url.split("://", 1)[-1].split("/", 1)[0])
    digest = hashlib.sha1(url.encode("utf-8")).hexdigest()[:8]
    return f"{host}_{digest}.html"


def _normalize(url: str) -> str:
    url = url.strip()
    if not url:
        return url
    if "://" not in url:
        url = "https://" + url
    return url


def fetch_one(
    url: str,
    impersonate: str = DEFAULT_IMPERSONATE,
    timeout: float = DEFAULT_TIMEOUT,
    proxy: Optional[str] = None,
    output: Optional[Path] = None,
) -> Dict[str, object]:
    """Fetch a single URL with the curl_cffi Chrome fingerprint client."""
    started = time.monotonic()
    result: Dict[str, object] = {"url": url, "ok": False, "status": None, "error": None}
    opts = {"impersonate": impersonate, "timeout": timeout, "allow_redirects": True}
    if proxy:
        opts["proxies"] = {"http": proxy, "https": proxy}
    try:
        response = creq.get(url, **opts)
        body = response.text
        result.update(
            {
                "status": response.status_code,
                "ok": response.status_code == 200,
                "length": len(body),
                "title": _title_of(body),
                "seconds": round(time.monotonic() - started, 2),
            }
        )
        if output is not None:
            output.write_text(body, encoding="utf-8", errors="replace")
            result["saved"] = str(output)
    except Exception as exc:  # noqa: BLE001 — report any transport failure
        result["error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
        result["seconds"] = round(time.monotonic() - started, 2)
    return result


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="direct_fetch.py",
        description=(
            "Fetch public https pages from this machine's own IP with a real "
            "Chrome TLS fingerprint (curl_cffi), no proxy by default."
        ),
    )
    parser.add_argument("urls", nargs="*", help="One or more URLs")
    parser.add_argument("--urls-file", help="Text file with one URL per line (# = comment)")
    parser.add_argument("--output", help="Save single-URL body to this file")
    parser.add_argument("--save-dir", help="Save every body into this folder")
    parser.add_argument("--json", dest="json_out", help="Write full results as JSON here")
    parser.add_argument("--proxy", help="Optional proxy URL (http://user:pass@host:port)")
    parser.add_argument("--impersonate", default=DEFAULT_IMPERSONATE,
                        help=f"curl_cffi impersonation profile (default: {DEFAULT_IMPERSONATE})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"Per-request timeout seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                        help=f"Seconds between requests in sequential mode (default: {DEFAULT_DELAY})")
    parser.add_argument("--concurrency", type=int, default=1,
                        help="Parallel workers (default 1 = sequential + --delay pacing)")
    return parser


def main() -> int:
    args = _build_parser().parse_args()

    targets: List[str] = [_normalize(u) for u in args.urls if u.strip()]
    if args.urls_file:
        for line in Path(args.urls_file).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(_normalize(line))
    if not targets:
        print("No URLs given. Pass URLs or --urls-file. See --help.")
        return 1

    save_dir = Path(args.save_dir) if args.save_dir else None
    if save_dir:
        save_dir.mkdir(parents=True, exist_ok=True)

    print(f"direct_fetch: {len(targets)} URL(s) | impersonate={args.impersonate} "
          f"| proxy={'yes' if args.proxy else 'no (own IP)'} | concurrency={args.concurrency}")
    results: List[Dict[str, object]] = []

    if args.concurrency > 1:
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futures = {
                pool.submit(
                    fetch_one,
                    url,
                    args.impersonate,
                    args.timeout,
                    args.proxy,
                    (save_dir / _safe_filename(url)) if save_dir else
                    (Path(args.output) if args.output and len(targets) == 1 else None),
                ): url
                for url in targets
            }
            for future in as_completed(futures):
                results.append(future.result())
        results.sort(key=lambda r: targets.index(str(r["url"])))
    else:
        for index, url in enumerate(targets):
            if index:
                time.sleep(max(args.delay, 0.0))
            output = None
            if save_dir:
                output = save_dir / _safe_filename(url)
            elif args.output and len(targets) == 1:
                output = Path(args.output)
            results.append(fetch_one(url, args.impersonate, args.timeout, args.proxy, output))

    successes = 0
    for result in results:
        if result.get("ok"):
            successes += 1
            saved = f" saved={result['saved']}" if result.get("saved") else ""
            print(f"[OK ] {result['url']}")
            print(f"      status={result['status']} len={result['length']} "
                  f"title='{result['title']}' {result['seconds']}s{saved}")
        else:
            print(f"[FAIL] {result['url']}")
            print(f"      status={result.get('status')} "
                  f"error={result.get('error') or 'non-200'} {result.get('seconds')}s")

    print(f"-> {successes}/{len(results)} succeeded")
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"results JSON -> {args.json_out}")
    return 0 if successes else 2


if __name__ == "__main__":
    sys.exit(main())
