#!/usr/bin/env python3
"""
akamai_warm.py - Akamai Bot Manager cookie mint -> replay prototype.

Why: Akamai-protected sites (myntra, nykaa, ajio, jiomart, meesho, pinterest,
... — see RESEARCH-2026-10-17.md) issue `_abck` / `bm_sz` / `ak_bmsc` cookies
only after their sensor JavaScript runs inside a real browser and passes
silently. Once `_abck` is validated (contains the `~-1~` marker), a plain HTTP
client can often keep fetching pages for a while IF it presents:

  - the same exit IP    (the cookie set is scored against the IP), and
  - the same User-Agent (mismatch => sensor retest), and
  - a real Chrome TLS fingerprint (curl_cffi impersonate chrome).

This script does exactly that:
  1. mint   - real Chrome (nodriver) visits the URL on this machine's own IP,
              waits for the Akamai sensor to validate `_abck`, harvests every
              cookie + the exact UA, and saves them to akamai-cookies.json.
  2. replay - fetches the URL with curl_cffi (Chrome TLS) + stored cookies/UA.
  3. test   - mint then immediately replay (the honest end-to-end check).

Usage:
    python akamai_warm.py test https://www.ajio.com/
    python akamai_warm.py mint https://www.meesho.com/
    python akamai_warm.py replay https://www.meesho.com/ --output page.html
    python akamai_warm.py list

Honest limitations (read before trusting it):
  - `_abck` validation is behavioural and IP-scored; a replay can still get a
    403 (Akamai re-challenges and issues a new `_abck` marked ~0~).
  - Cookies die with an IP/UA change and expire (minutes to ~1 hour typical).
  - This is a direct / own-IP tool. Through datacenter proxies it will not
    work; through residential proxies you must mint through the SAME exit IP.
  - Re-mint when replays start failing: `akamai_warm.py mint <url>`.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

try:
    import nodriver as uc
    _NODRIVER_OK = True
except ImportError:
    _NODRIVER_OK = False

try:
    from curl_cffi import requests as curl_requests
    _CURL_OK = True
except ImportError:
    _CURL_OK = False

COOKIE_FILE = Path(__file__).resolve().parent / "akamai-cookies.json"
FALLBACK_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
_CHALLENGE_TITLE_HINTS = ("just a moment", "please wait", "attention required", "checking your browser")


# ---------------------------------------------------------------------------
#  Store helpers
# ---------------------------------------------------------------------------
def _host_key(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def _load_store() -> Dict[str, Any]:
    if not COOKIE_FILE.exists():
        return {}
    try:
        return json.loads(COOKIE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_store(store: Dict[str, Any]) -> None:
    COOKIE_FILE.write_text(json.dumps(store, indent=2), encoding="utf-8")


def _cookie_header(entry: Dict[str, Any]) -> str:
    parts: List[str] = []
    for cookie in entry.get("cookies", []):
        name = str(cookie.get("name", "")).strip()
        if name:
            parts.append(f"{name}={cookie.get('value', '')}")
    return "; ".join(parts)


def _abck_state(value: str) -> str:
    if "~-1~" in value:
        return "validated(~-1~)"
    if "~0~" in value:
        return "unvalidated(~0~)"
    return "no-marker"


# ---------------------------------------------------------------------------
#  Mint - real Chrome (nodriver), own IP, harvest cookies + UA
# ---------------------------------------------------------------------------
async def mint(
    url: str,
    *,
    headless: bool = True,
    wait_seconds: float = 6.0,
    max_wait: float = 25.0,
) -> Dict[str, Any]:
    """Open *url* in real Chrome, wait for the Akamai sensor, save cookies."""
    if not _NODRIVER_OK:
        raise SystemExit(
            "nodriver not installed — run: venv\\Scripts\\pip install nodriver"
        )

    from stealth_browser import _find_chrome_executable

    chrome = _find_chrome_executable()
    browser = await asyncio.wait_for(
        uc.start(
            headless=headless,
            sandbox=False,
            browser_executable_path=chrome,
            lang="en-US",
            browser_args=[
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                "--lang=en-US",
            ],
        ),
        timeout=60,
    )
    page = None
    try:
        page = await asyncio.wait_for(
            browser.get(url), timeout=max(30.0, wait_seconds + 20.0)
        )
        await asyncio.sleep(max(0.0, wait_seconds))

        # Poll until `_abck` shows the validated marker (bounded by max_wait).
        abck_value = ""
        no_abck_checks = 0
        deadline = time.monotonic() + max(0.0, max_wait - wait_seconds)
        while time.monotonic() < deadline:
            try:
                jar = await browser.cookies.get_all()
            except Exception:
                break
            abck_value = next(
                (str(c.value or "") for c in jar if getattr(c, "name", "") == "_abck"),
                "",
            )
            if "~-1~" in abck_value:
                break
            if not abck_value:
                # Not an Akamai site (or cookie not issued): stop early once the
                # page looks settled instead of burning the whole deadline.
                no_abck_checks += 1
                try:
                    title = str(await page.evaluate("document.title") or "").lower()
                except Exception:
                    title = ""
                if no_abck_checks >= 3 and not any(
                    hint in title for hint in _CHALLENGE_TITLE_HINTS
                ):
                    break
            await asyncio.sleep(1.5)

        try:
            ua = str(await page.evaluate("navigator.userAgent") or FALLBACK_UA)
        except Exception:
            ua = FALLBACK_UA

        cookies: List[Dict[str, str]] = []
        try:
            jar = await browser.cookies.get_all()
            for c in jar:
                cookies.append(
                    {
                        "name": str(getattr(c, "name", "") or ""),
                        "value": str(getattr(c, "value", "") or ""),
                        "domain": str(getattr(c, "domain", "") or ""),
                        "path": str(getattr(c, "path", "/") or "/"),
                    }
                )
        except Exception:
            raw = str(await page.evaluate("document.cookie") or "")
            for part in raw.split(";"):
                if "=" in part:
                    key, value = part.strip().split("=", 1)
                    cookies.append({"name": key, "value": value, "domain": "", "path": "/"})

        try:
            title = str(await page.evaluate("document.title") or "")
        except Exception:
            title = ""
        try:
            html_len = len(await page.get_content() or "")
        except Exception:
            html_len = 0
        final_url = url
        try:
            final_url = page.target.url or url
        except Exception:
            pass

        entry = {
            "url": final_url,
            "ua": ua,
            "minted_at": time.time(),
            "abck_state": _abck_state(abck_value),
            "cookies": cookies,
        }
        store = _load_store()
        store[_host_key(url)] = entry
        _save_store(store)

        return {
            "ok": True,
            "host": _host_key(url),
            "final_url": final_url,
            "title": title,
            "html_len": html_len,
            "cookie_count": len(cookies),
            "cookie_names": sorted({c["name"] for c in cookies if c["name"]}),
            "abck_state": entry["abck_state"],
            "saved_to": str(COOKIE_FILE),
        }
    finally:
        # Explicit awaited teardown (same reasoning as
        # stealth_browser._scrape_nodriver): stop() alone can leave nodriver's
        # websocket listener dangling when the event loop closes right after,
        # producing an endless "cannot call get() concurrently" error flood.
        for conn in (page, browser):
            if conn is not None:
                try:
                    await conn.aclose()
                except Exception:
                    pass
        try:
            browser.stop()
        except Exception:
            pass
        try:
            await asyncio.sleep(0.05)
        except Exception:
            pass


# ---------------------------------------------------------------------------
#  Replay - curl_cffi (Chrome TLS) + stored cookies/UA
# ---------------------------------------------------------------------------
def replay(
    url: str,
    *,
    output: Optional[str] = None,
    timeout: float = 30.0,
    impersonate: str = "chrome",
) -> Dict[str, Any]:
    """Fetch *url* with the stored cookies via curl_cffi (Chrome TLS print)."""
    if not _CURL_OK:
        raise SystemExit(
            "curl_cffi not installed — run: venv\\Scripts\\pip install curl_cffi"
        )
    key = _host_key(url)
    store = _load_store()
    entry = store.get(key)
    if not entry:
        return {
            "ok": False,
            "error": (
                f"no minted cookies for {key!r} — run: "
                f"python akamai_warm.py mint {url}"
            ),
        }

    headers = {
        "User-Agent": entry.get("ua") or FALLBACK_UA,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Cookie": _cookie_header(entry),
    }
    response = curl_requests.get(
        url,
        headers=headers,
        impersonate=impersonate,
        timeout=timeout,
        allow_redirects=True,
    )
    body = response.content or b""
    if output:
        Path(output).write_bytes(body)

    age = max(0.0, time.time() - float(entry.get("minted_at") or 0))
    return {
        "ok": response.status_code == 200,
        "status_code": response.status_code,
        "final_url": str(response.url),
        "content_length": len(body),
        "age_seconds": round(age),
        "cookies_used": len(entry.get("cookies", [])),
        "abck_state_at_mint": entry.get("abck_state"),
        "body_snippet": body[:300].decode("utf-8", "replace"),
        "saved_output": output,
    }


# ---------------------------------------------------------------------------
#  CLI
# ---------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Akamai cookie mint -> replay prototype (direct / own IP). "
            "See module docstring for honest limitations."
        )
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_mint = sub.add_parser("mint", help="Harvest Akamai cookies with real Chrome (nodriver)")
    p_mint.add_argument("url")
    p_mint.add_argument("--headful", action="store_true", help="Show the browser window")
    p_mint.add_argument("--wait", type=float, default=6.0, help="Initial settle seconds (default 6)")
    p_mint.add_argument("--max-wait", type=float, default=25.0, help="Total seconds waiting for _abck validation")

    p_replay = sub.add_parser("replay", help="Fetch the URL with saved cookies via curl_cffi")
    p_replay.add_argument("url")
    p_replay.add_argument("--output", help="Save response body to this file")
    p_replay.add_argument("--timeout", type=float, default=30.0)

    p_test = sub.add_parser("test", help="mint then replay immediately (end-to-end check)")
    p_test.add_argument("url")
    p_test.add_argument("--headful", action="store_true")
    p_test.add_argument("--wait", type=float, default=6.0)
    p_test.add_argument("--max-wait", type=float, default=25.0)
    p_test.add_argument("--output", help="Save replay body to this file")

    sub.add_parser("list", help="Show stored cookie entries")
    return parser


def main() -> None:
    args = _build_parser().parse_args()

    if args.cmd == "mint":
        from stealth_browser import _run_async, _hard_exit

        result = _run_async(
            mint(
                args.url,
                headless=not args.headful,
                wait_seconds=args.wait,
                max_wait=args.max_wait,
            )
        )
        print(json.dumps(result, indent=2))
        _hard_exit(0 if result.get("ok") else 2)

    if args.cmd == "replay":
        result = replay(args.url, output=args.output, timeout=args.timeout)
        print(json.dumps(result, indent=2))
        sys.exit(0 if result.get("ok") else 2)

    if args.cmd == "test":
        from stealth_browser import _run_async, _hard_exit

        print(f"[1/2] minting Akamai cookies for {args.url} ...")
        mint_result = _run_async(
            mint(
                args.url,
                headless=not args.headful,
                wait_seconds=args.wait,
                max_wait=args.max_wait,
            )
        )
        print(json.dumps(mint_result, indent=2))
        print("[2/2] replaying with curl_cffi ...")
        replay_result = replay(args.url, output=args.output)
        print(json.dumps(replay_result, indent=2))
        verdict = "REPLAY OK" if replay_result.get("ok") else "REPLAY FAILED"
        print(
            f"verdict: abck_at_mint={mint_result.get('abck_state')} "
            f"{verdict} (status={replay_result.get('status_code')})"
        )
        _hard_exit(0 if replay_result.get("ok") else 2)

    if args.cmd == "list":
        store = _load_store()
        if not store:
            print("(no entries)")
            return
        for host, entry in sorted(store.items()):
            age = round(max(0.0, time.time() - float(entry.get("minted_at") or 0)))
            print(
                f"{host}: cookies={len(entry.get('cookies', []))} "
                f"abck={entry.get('abck_state')} age={age}s url={entry.get('url')}"
            )


if __name__ == "__main__":
    main()
