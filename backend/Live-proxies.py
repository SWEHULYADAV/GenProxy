#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import argparse
import ctypes
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List

from proxy_core import (
    DEFAULT_SOURCES,
    DEFAULT_TEST_URLS,
    HarvesterConfig,
    ProxyHarvester,
    read_source_file,
    run_async_entrypoint,
    to_iso,
    utc_now,
)

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

        def clear(self):
            os.system("cls")

    console = SimpleConsole()

LEGACY_ROOT_FILES = (
    "active_proxies.json",
    "working_proxies.txt",
    "working_proxies.json",
)

STD_INPUT_HANDLE = -10
ENABLE_QUICK_EDIT_MODE = 0x0040
ENABLE_EXTENDED_FLAGS = 0x0080


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Single live window for only updated and currently working proxies."
    )
    parser.add_argument(
        "--output-root",
        default="output",
        help="Root folder where each run gets its own timestamped directory",
    )
    parser.add_argument(
        "--session-prefix",
        default="proxies",
        help="Per-run folder prefix before the timestamp",
    )
    parser.add_argument(
        "--output",
        default="active_proxies.json",
        help="Full ranked active proxy pool JSON filename inside the run folder",
    )
    parser.add_argument(
        "--txt-output",
        default="working_proxies.txt",
        help="Plain text filename with one working proxy per line inside the run folder",
    )
    parser.add_argument(
        "--json-output",
        default="working_proxies.json",
        help="Filtered live working proxies JSON filename inside the run folder",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="How many working proxies to show in the live window",
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        help="Only show proxies above this saved score",
    )
    parser.add_argument(
        "--plain", action="store_true", help="Show plain list instead of rich table"
    )
    parser.add_argument(
        "--refresh-delay",
        type=float,
        default=5.0,
        help="Seconds between screen refreshes",
    )
    parser.add_argument(
        "--max-concurrent",
        type=int,
        default=120,
        help="Concurrent source fetches and proxy checks",
    )
    parser.add_argument(
        "--fetch-timeout", type=float, default=8.0, help="Timeout for source downloads"
    )
    parser.add_argument(
        "--verify-timeout", type=float, default=8.0, help="Timeout for proxy validation"
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
        default=1000,
        help="Maximum candidates retained per source cycle",
    )
    parser.add_argument(
        "--verify-batch-size",
        type=int,
        default=120,
        help="How many active proxies to re-check per cycle",
    )
    parser.add_argument(
        "--min-success-rate",
        type=float,
        default=0.35,
        help="Drop proxies below this success rate",
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
    parser.add_argument(
        "--once", action="store_true", help="Run one live refresh cycle and exit"
    )
    return parser


def _resolve_session_file(session_dir: Path, value: str) -> Path:
    target = Path(value)
    if target.is_absolute():
        target.parent.mkdir(parents=True, exist_ok=True)
        return target
    resolved = session_dir / target
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def prepare_session(args: argparse.Namespace) -> Path:
    timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    root = Path(args.output_root)
    root.mkdir(parents=True, exist_ok=True)

    session_dir = root / f"{args.session_prefix}_{timestamp}"
    counter = 1
    while session_dir.exists():
        session_dir = root / f"{args.session_prefix}_{timestamp}_{counter}"
        counter += 1
    session_dir.mkdir(parents=True, exist_ok=False)

    args.output = str(_resolve_session_file(session_dir, args.output))
    args.txt_output = str(_resolve_session_file(session_dir, args.txt_output))
    args.json_output = str(_resolve_session_file(session_dir, args.json_output))
    args.session_dir = str(session_dir.resolve())
    args.session_info = str((session_dir / "session_info.json").resolve())
    (root / "latest_session.txt").write_text(args.session_dir, encoding="utf-8")
    return session_dir


def cleanup_legacy_root_outputs() -> None:
    cwd = Path.cwd()
    for name in LEGACY_ROOT_FILES:
        target = cwd / name
        if target.exists() and target.is_file():
            target.unlink()


def configure_windows_console() -> None:
    if os.name != "nt":
        return
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(STD_INPUT_HANDLE)
        mode = ctypes.c_uint()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            new_mode = (mode.value | ENABLE_EXTENDED_FLAGS) & ~ENABLE_QUICK_EDIT_MODE
            kernel32.SetConsoleMode(handle, new_mode)
    except Exception:
        pass


def clear_screen() -> None:
    # M-8: ANSI escape for flicker-free in-place update.
    # Works on Windows 10+ Terminal, ConEmu, VS Code terminal.
    # Falls back to cls only when ANSI is not supported.
    if os.name == "nt":
        print("\033[H\033[J", end="", flush=True)
    else:
        console.clear()


def flush_console() -> None:
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass


def build_config(args: argparse.Namespace) -> HarvesterConfig:
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
    sources = list(DEFAULT_SOURCES)
    for source in read_source_file(extra_source_file):
        if source not in sources:
            sources.append(source)
    return sources


def filter_records(harvester: ProxyHarvester, limit: int, min_score: float):
    visible = [
        record
        for record in harvester.ranked_active_records()
        if record.score >= min_score
    ]
    return visible[:limit]


def write_session_info(
    args: argparse.Namespace, summary: dict, sources: List[str]
) -> None:
    payload = {
        "session_dir": args.session_dir,
        "updated_at": to_iso(utc_now()),
        "active_total": summary.get("active_proxies", 0),
        "files": {
            "active_pool_json": args.output,
            "working_txt": args.txt_output,
            "working_json": args.json_output,
        },
        "sources_count": len(sources),
        "progress": getattr(args, "progress_state", {}),
    }
    Path(args.session_info).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def export_live_outputs(
    records: Iterable, args: argparse.Namespace, summary: dict
) -> None:
    records = list(records)
    Path(args.txt_output).write_text(
        "\n".join(record.proxy for record in records),
        encoding="utf-8",
    )

    payload = {
        "updated_at": to_iso(utc_now()),
        "count": len(records),
        "active_total": summary.get("active_proxies", len(records)),
        "proxies": [
            {
                "proxy": record.proxy,
                "score": record.score,
                "success_rate": round(record.success_rate, 6),
                "avg_response_time": round(record.avg_response_time, 4),
                "last_origin": record.last_origin,
                "source_count": len(record.source_urls),
            }
            for record in records
        ],
    }
    Path(args.json_output).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def render_plain(records: Iterable, summary: dict, args: argparse.Namespace) -> None:
    records = list(records)
    clear_screen()
    console.print(f"Live working proxies | updated={to_iso(utc_now())}")
    console.print(
        f"visible={len(records)} | active_total={summary.get('active_proxies', 0)}"
    )
    console.print(f"session_dir={args.session_dir}")
    console.print(f"active_pool={args.output}")
    console.print(f"working_txt={args.txt_output}")
    console.print(f"working_json={args.json_output}")
    console.print("")
    if not records:
        console.print("No working proxies right now.")
        flush_console()
        return
    for record in records:
        console.print(record.proxy)
    flush_console()


def render_table(records: Iterable, summary: dict, args: argparse.Namespace) -> None:
    records = list(records)
    clear_screen()

    if args.plain or not RICH_AVAILABLE:
        render_plain(records, summary, args)
        return

    console.print(
        f"[bold green]Live working proxies[/bold green]  "
        f"updated={to_iso(utc_now())}  visible={len(records)}  active_total={summary.get('active_proxies', 0)}"
    )
    console.print(f"session={args.session_dir}")
    console.print(f"active_pool={args.output}")
    console.print(f"working_txt={args.txt_output}  working_json={args.json_output}")

    if not records:
        console.print("No working proxies right now.")
        return

    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Rank", justify="right", style="cyan")
    table.add_column("Proxy", style="green")
    table.add_column("Score", justify="right", style="yellow")
    table.add_column("Success %", justify="right", style="bright_green")
    table.add_column("Avg RTT", justify="right", style="blue")
    table.add_column("Origin", style="magenta")

    for index, record in enumerate(records, start=1):
        table.add_row(
            str(index),
            record.proxy,
            f"{record.score:.3f}",
            f"{record.success_rate * 100:.1f}",
            f"{record.avg_response_time:.2f}s",
            record.last_origin or "-",
        )

    console.print(table)
    flush_console()


def render_startup_status(args: argparse.Namespace, sources: List[str]) -> None:
    clear_screen()
    console.print("Starting live proxy session...")
    console.print(f"session={args.session_dir}")
    console.print(f"active_pool={args.output}")
    console.print(f"working_txt={args.txt_output}")
    console.print(f"working_json={args.json_output}")
    console.print(f"sources={len(sources)}")
    console.print("")
    console.print(
        "Collecting and verifying proxies. First screen update can take some time."
    )
    flush_console()


def render_progress(args: argparse.Namespace) -> None:
    progress = getattr(args, "progress_state", {})
    phase = progress.get("phase", "starting")
    clear_screen()
    console.print("Live proxy session in progress...")
    console.print(f"phase={phase}")
    console.print(f"session={args.session_dir}")
    console.print(f"active_pool={args.output}")
    console.print(f"working_txt={args.txt_output}")
    console.print(f"working_json={args.json_output}")
    console.print("")

    if phase == "collecting_sources":
        console.print(
            f"sources_done={progress.get('completed_sources', 0)}/{progress.get('total_sources', 0)} | "
            f"candidates_found={progress.get('collected_candidates', 0)}"
        )
        if progress.get("current_source"):
            console.print(
                f"last_source={progress['current_source']} | found={progress.get('current_source_count', 0)}"
            )
    elif phase == "verifying_proxies":
        console.print(
            f"verified={progress.get('verified_count', 0)}/{progress.get('total_verify', 0)} | "
            f"working_now={progress.get('working_count', 0)}"
        )
        if progress.get("current_proxy"):
            console.print(f"last_proxy={progress['current_proxy']}")
    elif phase == "cycle_complete":
        console.print(
            f"active_now={progress.get('active_now', 0)} | "
            f"collected={progress.get('collected_candidates', 0)} | "
            f"verified={progress.get('verified_count', 0)}"
        )
        if progress.get("best_proxy"):
            console.print(f"best_proxy={progress['best_proxy']}")
    else:
        console.print(f"active_now={progress.get('active_now', 0)}")
    flush_console()


def make_progress_callback(args: argparse.Namespace):
    args.progress_state = {"phase": "starting"}
    args._last_progress_render = 0.0

    def _callback(payload: Dict[str, object]) -> None:
        args.progress_state.update(payload)
        now = time.monotonic()
        phase = str(payload.get("phase", ""))
        should_render = phase.endswith("_complete") or phase in {
            "cycle_start",
            "cycle_complete",
        }
        if not should_render and (now - args._last_progress_render) < 0.4:
            return
        args._last_progress_render = now
        render_progress(args)

    return _callback


async def run_live_window(args: argparse.Namespace) -> None:
    configure_windows_console()
    cleanup_legacy_root_outputs()
    prepare_session(args)
    config = build_config(args)
    sources = build_sources(args.source_file)
    progress_callback = make_progress_callback(args)
    write_session_info(
        args,
        summary={"active_proxies": 0},
        sources=sources,
    )
    render_startup_status(args, sources)

    async with ProxyHarvester(
        config=config, sources=sources, progress_callback=progress_callback
    ) as harvester:
        try:
            while True:
                summary = await harvester.run_cycle()
                records = filter_records(
                    harvester, limit=args.limit, min_score=args.min_score
                )
                export_live_outputs(records, args, summary)
                write_session_info(args, summary, sources)
                render_table(records, summary, args)
                if args.once:
                    return
                await asyncio.sleep(args.refresh_delay)
        except (asyncio.CancelledError, KeyboardInterrupt):
            # H-4: Ensure pool is flushed to disk even on abrupt exit
            try:
                await harvester.save_pool(force=True)
            except Exception:
                pass
            raise


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        run_async_entrypoint(run_live_window(args))
    except ModuleNotFoundError as exc:
        console.print(
            f"Missing dependency: {exc.name}. Run: pip install -r requirements.txt"
        )
    except KeyboardInterrupt:
        console.print("Stopped by user.")


if __name__ == "__main__":
    main()
