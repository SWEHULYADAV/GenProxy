#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
from typing import Iterable, List

try:
    from rich import box
    from rich.console import Console
    from rich.table import Table

    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False

    class SimpleConsole:
        def print(self, *args, **kwargs):
            print(*args)

    console = SimpleConsole()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect, validate, and continuously rank active free HTTP proxies."
    )
    parser.add_argument(
        "--output", default="active_proxies.json", help="JSON file for active proxies"
    )
    parser.add_argument(
        "--max-concurrent",
        type=int,
        default=200,
        help="Concurrent source fetches and proxy checks",
    )
    parser.add_argument(
        "--fetch-timeout", type=float, default=10.0, help="Timeout for source downloads"
    )
    parser.add_argument(
        "--verify-timeout",
        type=float,
        default=10.0,
        help="Timeout for proxy validation",
    )
    parser.add_argument(
        "--update-interval",
        type=float,
        default=120.0,
        help="Seconds between source refresh cycles",
    )
    parser.add_argument(
        "--verify-interval",
        type=float,
        default=60.0,
        help="Seconds between active proxy re-checks",
    )
    parser.add_argument(
        "--auto-save-interval",
        type=float,
        default=15.0,
        help="Minimum seconds between JSON writes",
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        default=3000,
        help="Maximum candidates retained per source cycle",
    )
    parser.add_argument(
        "--verify-batch-size",
        type=int,
        default=200,
        help="How many active proxies to re-check per cycle",
    )
    parser.add_argument(
        "--min-success-rate",
        type=float,
        default=0.35,
        help="Drop slow/failing proxies below this success rate",
    )
    parser.add_argument(
        "--max-failures",
        type=int,
        default=3,
        help="Max consecutive failures before proxy removal",
    )
    parser.add_argument(
        "--stale-after",
        type=float,
        default=1800.0,
        help="Remove proxies with no success for this many seconds",
    )
    parser.add_argument(
        "--max-response-time",
        type=float,
        default=12.0,
        help="Exclude proxies slower than this average",
    )
    parser.add_argument(
        "--probe-url",
        action="append",
        dest="probe_urls",
        help="Override/add probe URL",
    )
    parser.add_argument(
        "--source-file", help="Optional file with extra source URLs, one per line"
    )
    parser.add_argument("--once", action="store_true", help="Run one cycle and exit")
    return parser


def build_config(args: argparse.Namespace):
    from proxy_core import DEFAULT_TEST_URLS, HarvesterConfig

    return HarvesterConfig(
        max_concurrent=args.max_concurrent,
        fetch_timeout=args.fetch_timeout,
        verify_timeout=args.verify_timeout,
        update_interval=args.update_interval,
        verify_interval=args.verify_interval,
        auto_save_interval=args.auto_save_interval,
        max_candidates=args.max_candidates,
        verify_batch_size=args.verify_batch_size,
        min_success_rate=args.min_success_rate,
        max_consecutive_failures=args.max_failures,
        stale_after_seconds=args.stale_after,
        max_response_time=args.max_response_time,
        output_file=args.output,
        test_urls=list(args.probe_urls or DEFAULT_TEST_URLS),
        max_stored_records=args.max_candidates * 2,
    )


def build_sources(extra_source_file: str | None) -> List[str]:
    from proxy_core import DEFAULT_SOURCES, read_source_file

    sources = list(DEFAULT_SOURCES)
    for source in read_source_file(extra_source_file):
        if source not in sources:
            sources.append(source)
    return sources


def render_top_table(records: Iterable, title: str) -> None:
    records = list(records)
    if not records:
        console.print("No active proxies yet.")
        return

    if RICH_AVAILABLE:
        table = Table(title=title, box=box.SIMPLE_HEAVY)
        table.add_column("Rank", justify="right", style="cyan")
        table.add_column("Proxy", style="green")
        table.add_column("Score", justify="right", style="yellow")
        table.add_column("Success %", justify="right", style="bright_green")
        table.add_column("Avg RTT", justify="right", style="blue")
        table.add_column("Sources", justify="right", style="magenta")
        for index, record in enumerate(records, start=1):
            table.add_row(
                str(index),
                record.proxy,
                f"{record.score:.3f}",
                f"{record.success_rate * 100:.1f}",
                f"{record.avg_response_time:.2f}s",
                str(len(record.source_urls)),
            )
        console.print(table)
        return

    console.print(title)
    for index, record in enumerate(records, start=1):
        console.print(
            f"{index:>2}. {record.proxy} | score={record.score:.3f} | "
            f"success={record.success_rate * 100:.1f}% | avg={record.avg_response_time:.2f}s | "
            f"sources={len(record.source_urls)}"
        )


def print_cycle_summary(summary: dict, harvester) -> None:
    console.print(
        "Cycle summary: "
        f"collected={summary['collected_candidates']} "
        f"verified={summary['verified_proxies']} "
        f"active={summary['active_proxies']} "
        f"added={summary['added_active']} "
        f"removed={summary['removed_active']}"
    )
    best = harvester.best_proxy()
    if best:
        console.print(
            f"Best proxy: {best.proxy} | score={best.score:.3f} | "
            f"success={best.success_rate * 100:.1f}% | avg={best.avg_response_time:.2f}s"
        )
    render_top_table(harvester.ranked_active_records(limit=10), "Top active proxies")


async def run_harvester(args: argparse.Namespace) -> None:
    from proxy_core import ProxyHarvester

    config = build_config(args)
    sources = build_sources(args.source_file)
    console.print(f"Using {len(sources)} source URLs.")

    async with ProxyHarvester(config=config, sources=sources) as harvester:
        console.print(
            f"Loaded {len(harvester.active_proxies)} active proxies from {config.output_file}."
        )

        if args.once:
            summary = await harvester.run_cycle(force_collect=True, force_verify=True)
            await harvester.save_pool(force=True)
            print_cycle_summary(summary, harvester)
            return

        while True:
            summary = await harvester.run_cycle()
            if summary["did_collect"] or summary["did_verify"]:
                print_cycle_summary(summary, harvester)
            await asyncio.sleep(5)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        from proxy_core import run_async_entrypoint

        run_async_entrypoint(run_harvester(args))
    except ModuleNotFoundError as exc:
        console.print(
            f"Missing dependency: {exc.name}. Run: pip install -r requirements.txt"
        )
    except KeyboardInterrupt:
        console.print("Stopped by user.")


if __name__ == "__main__":
    main()
