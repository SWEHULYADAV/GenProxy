#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path

DEFAULT_USER_AGENT = "ProxyGenerator/2.0 (+local pool manager)"
DEFAULT_TEST_URLS = (
    "https://api.ipify.org?format=json",
    "https://httpbin.org/ip",
    "http://api.ipify.org?format=json",
)


def _detect_default_input() -> str:
    """M-9: Auto-detect the active_proxies.json from the most recent session.
    Falls back to 'active_proxies.json' in the working directory.
    """
    for marker in ("output/latest_session.txt", "output/latest_api_session.txt"):
        p = Path(marker)
        if p.exists():
            session_dir = p.read_text(encoding="utf-8").strip()
            candidate = Path(session_dir) / "active_proxies.json"
            if candidate.exists():
                return str(candidate)
    return "active_proxies.json"


def format_proxy_url(value: str) -> str:
    return value if "://" in value else f"http://{value}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Re-test saved proxies or fetch a target URL through the best saved proxies."
    )
    parser.add_argument(
        "--input",
        default=None,
        help="Proxy pool JSON file (default: auto-detect from latest session)",
    )
    parser.add_argument(
        "--limit", type=int, default=50, help="How many ranked proxies to load"
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        help="Minimum score required from the saved pool",
    )
    parser.add_argument(
        "--concurrency", type=int, default=50, help="Concurrent checks in verify mode"
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0, help="Timeout for verify/fetch requests"
    )
    parser.add_argument(
        "--probe-url",
        action="append",
        dest="probe_urls",
        help="Override/add verification probe URL",
    )
    parser.add_argument(
        "--save-working", help="Optional JSON file for currently working proxies"
    )
    parser.add_argument(
        "--target-url", help="Optional target URL to fetch via rotating proxies"
    )
    parser.add_argument(
        "--output-body", help="Write successful target response body to this file"
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=15,
        help="Maximum proxies to try in target fetch mode",
    )
    parser.add_argument(
        "--delay", type=float, default=1.0, help="Delay between target fetch attempts"
    )
    parser.add_argument(
        "--status",
        type=int,
        default=200,
        help="Expected HTTP status for target fetch mode",
    )
    parser.add_argument(
        "--user-agent", default=DEFAULT_USER_AGENT, help="User-Agent header"
    )
    return parser


async def verify_pool(args: argparse.Namespace) -> int:
    import aiohttp

    from proxy_core import load_ranked_records, probe_proxy

    records = load_ranked_records(
        args.input or _detect_default_input(),
        limit=args.limit,
        min_score=args.min_score,
        max_response_time=args.timeout,
    )
    if not records:
        print("No proxies available in the selected score range.")
        return 1

    probe_urls = args.probe_urls or list(DEFAULT_TEST_URLS)
    connector = aiohttp.TCPConnector(limit=args.concurrency, ssl=True)
    semaphore = asyncio.Semaphore(args.concurrency)
    results = []

    async with aiohttp.ClientSession(connector=connector, trust_env=False) as session:

        async def worker(record):
            async with semaphore:
                outcome = await probe_proxy(
                    session=session,
                    proxy=record.proxy,
                    test_urls=probe_urls,
                    timeout_seconds=args.timeout,
                    user_agent=args.user_agent,
                )
                results.append((record, outcome))

        await asyncio.gather(*(worker(record) for record in records))

    results.sort(key=lambda item: item[0].score, reverse=True)
    working = [(record, outcome) for record, outcome in results if outcome.working]

    print(f"Checked {len(results)} proxies from {args.input}.")
    print(f"Working now: {len(working)} | Failed now: {len(results) - len(working)}")

    for record, outcome in working[:10]:
        print(
            f"OK  {record.proxy} | saved_score={record.score:.3f} | "
            f"rtt={outcome.response_time:.2f}s | origin={outcome.origin or 'unknown'}"
        )

    for record, outcome in [item for item in results if not item[1].working][:5]:
        print(f"BAD {record.proxy} | reason={outcome.error}")

    if args.save_working:
        payload = {
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "count": len(working),
            "proxies": [
                {
                    "proxy": record.proxy,
                    "saved_score": record.score,
                    "saved_success_rate": record.success_rate,
                    "saved_avg_response_time": record.avg_response_time,
                    "probe_response_time": round(outcome.response_time, 4),
                    "origin": outcome.origin,
                    "probe_url": outcome.probe_url,
                }
                for record, outcome in working
            ],
        }
        Path(args.save_working).write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )
        print(f"Saved currently working proxies to {args.save_working}")

    return 0 if working else 1


def fetch_target(args: argparse.Namespace) -> int:
    import aiohttp

    from proxy_core import load_ranked_records

    input_file = args.input or _detect_default_input()
    records = load_ranked_records(
        input_file,
        limit=args.limit,
        min_score=args.min_score,
        max_response_time=args.timeout,
    )
    if not records:
        print("No proxies available in the selected score range.")
        return 1

    async def try_fetch() -> int:
        timeout = aiohttp.ClientTimeout(total=args.timeout)
        max_attempts = min(args.max_attempts, len(records))

        for index, record in enumerate(records[:max_attempts], start=1):
            proxy_url = format_proxy_url(record.proxy)
            # H-3: SOCKS proxies require a special connector —
            # aiohttp's proxy= kwarg only works for HTTP/HTTPS proxies.
            is_socks = proxy_url.startswith(("socks4://", "socks5://", "socks4a://"))
            try:
                if is_socks:
                    from aiohttp_socks import ProxyConnector
                    connector = ProxyConnector.from_url(proxy_url, ssl=True)
                    extra_kwargs: dict = {}
                else:
                    connector = aiohttp.TCPConnector(limit=1, ssl=True)
                    extra_kwargs = {"proxy": proxy_url}

                async with aiohttp.ClientSession(
                    connector=connector, timeout=timeout, trust_env=False
                ) as session:
                    async with session.get(
                        args.target_url,
                        headers={"User-Agent": args.user_agent, "Accept": "*/*"},
                        allow_redirects=True,
                        **extra_kwargs,
                    ) as response:
                        if response.status != args.status:
                            print(
                                f"[{index}/{max_attempts}] {record.proxy} returned "
                                f"{response.status}, expected {args.status}"
                            )
                            await asyncio.sleep(args.delay)
                            continue

                        body = await response.text()
                        print(
                            f"[{index}/{max_attempts}] success via {record.proxy} | "
                            f"saved_score={record.score:.3f} | body={len(body)} bytes"
                        )
                        if args.output_body:
                            Path(args.output_body).write_text(body, encoding="utf-8")
                            print(f"Saved response body to {args.output_body}")
                        else:
                            snippet = body[:300].replace("\n", " ").strip()
                            print(f"Snippet: {snippet}")
                        return 0
            except Exception as exc:
                print(
                    f"[{index}/{max_attempts}] failed via {record.proxy} "
                    f"({exc.__class__.__name__})"
                )
                await asyncio.sleep(args.delay)

        print("Could not fetch the target URL with the selected proxies.")
        return 1

    from proxy_core import run_async_entrypoint
    return run_async_entrypoint(try_fetch)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    # M-9: resolve --input default at runtime after arg parsing
    if args.input is None:
        args.input = _detect_default_input()
    try:
        if args.target_url:
            return fetch_target(args)
        from proxy_core import run_async_entrypoint
        return run_async_entrypoint(verify_pool(args))
    except ModuleNotFoundError as exc:
        print(f"Missing dependency: {exc.name}. Run: pip install -r requirements.txt")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
