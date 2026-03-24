"""
LySec - CLI Query & Management Tool
Command-line interface for querying forensic logs, viewing alerts,
generating timeline reports, and managing the daemon.

Usage:
    lysec status                                # daemon status
    lysec alerts [--severity HIGH] [--last 1h]  # view alerts
    lysec timeline [--from ... --to ...]        # event timeline
    lysec search --query "ssh root"             # search logs
    lysec export --format csv --output out.csv  # export evidence
    lysec verify                                # verify log integrity
"""

import argparse
import json
import os
import re
import sys
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from dftool.config import load_config, DEFAULT_CONFIG_PATH


console = Console() if HAS_RICH else None


# ──────────────────────────────────────────────
# Log reader utilities
# ──────────────────────────────────────────────

def read_log_entries(log_path: str, max_entries: int = 10000) -> list[dict]:
    """Read JSON log entries from a LySec log file."""
    entries = []
    if not os.path.isfile(log_path):
        return entries
    with open(log_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            if len(entries) >= max_entries:
                break
    return entries


def parse_duration(s: str) -> timedelta:
    """Parse a human duration like '1h', '30m', '2d' into timedelta."""
    match = re.match(r"^(\d+)(s|m|h|d)$", s.strip())
    if not match:
        raise ValueError(f"Invalid duration: {s} — use format like 1h, 30m, 2d")
    val = int(match.group(1))
    unit = match.group(2)
    return {
        "s": timedelta(seconds=val),
        "m": timedelta(minutes=val),
        "h": timedelta(hours=val),
        "d": timedelta(days=val),
    }[unit]


# ──────────────────────────────────────────────
# Commands
# ──────────────────────────────────────────────

def cmd_status(args, config):
    """Show daemon status."""
    pid_file = config["daemon"]["pid_file"]
    pid = _get_running_pid(pid_file)
    if pid:
        _print_success(f"LySec daemon is running (pid {pid})")
    else:
        _print_warn("LySec daemon is NOT running")
    # Show log sizes
    log_dir = config["logging"]["log_dir"]
    if os.path.isdir(log_dir):
        _print_info(f"Log directory: {log_dir}")
        for f in sorted(os.listdir(log_dir)):
            fp = os.path.join(log_dir, f)
            if os.path.isfile(fp):
                size = os.path.getsize(fp)
                _print_info(f"  {f}: {_human_size(size)}")


def cmd_alerts(args, config):
    """Display recent alerts."""
    alert_log = config.get("alerts", {}).get(
        "alert_log", "/var/log/lysec/alerts.log"
    )
    entries = read_log_entries(alert_log)

    # Filter by severity
    if args.severity:
        entries = [e for e in entries if e.get("severity") == args.severity.upper()]

    # Filter by time
    if args.last:
        try:
            delta = parse_duration(args.last)
            cutoff = datetime.now(timezone.utc) - delta
            filtered = []
            for e in entries:
                ts_str = e.get("timestamp", "")
                try:
                    ts = datetime.fromisoformat(ts_str)
                    if ts >= cutoff:
                        filtered.append(e)
                except Exception:
                    filtered.append(e)  # keep if unparseable
            entries = filtered
        except ValueError as exc:
            _print_error(str(exc))
            return

    if not entries:
        _print_info("No alerts found matching criteria.")
        return

    # Display
    if HAS_RICH:
        table = Table(title="LySec Alerts", box=box.ROUNDED, show_lines=True)
        table.add_column("Time", style="cyan", width=26)
        table.add_column("Severity", width=10)
        table.add_column("Monitor", style="green", width=12)
        table.add_column("Event", style="yellow", width=24)
        table.add_column("Message", style="white")

        sev_colors = {
            "CRITICAL": "[bold red]",
            "HIGH": "[red]",
            "MEDIUM": "[yellow]",
            "LOW": "[blue]",
            "INFO": "[dim]",
        }

        for e in entries[-50:]:  # last 50
            sev = e.get("severity", "?")
            color = sev_colors.get(sev, "")
            table.add_row(
                e.get("timestamp", "?")[:26],
                f"{color}{sev}",
                e.get("monitor", "?"),
                e.get("event_type", "?"),
                e.get("message", "?"),
            )
        console.print(table)
    else:
        for e in entries[-50:]:
            print(
                f"[{e.get('timestamp', '?')[:19]}] "
                f"{e.get('severity', '?'):10s} "
                f"{e.get('monitor', '?'):12s} "
                f"{e.get('event_type', '?'):24s} "
                f"{e.get('message', '?')}"
            )


def cmd_timeline(args, config):
    """Generate an event timeline from forensic logs."""
    log_dir = config["logging"]["log_dir"]
    main_log = os.path.join(log_dir, "lysec.log")
    if not os.path.isfile(main_log):
        main_log = os.path.join(log_dir, "dftool.log")
    entries = read_log_entries(main_log)

    # Filter by time range
    if args.start:
        start = datetime.fromisoformat(args.start).replace(tzinfo=timezone.utc)
        entries = [
            e for e in entries
            if _parse_ts(e.get("timestamp")) and _parse_ts(e.get("timestamp")) >= start
        ]
    if args.end:
        end = datetime.fromisoformat(args.end).replace(tzinfo=timezone.utc)
        entries = [
            e for e in entries
            if _parse_ts(e.get("timestamp")) and _parse_ts(e.get("timestamp")) <= end
        ]

    # Filter by monitor
    if args.monitor:
        entries = [e for e in entries if e.get("monitor") == args.monitor]

    if not entries:
        _print_info("No events found for the specified criteria.")
        return

    _print_info(f"Timeline: {len(entries)} events")
    if HAS_RICH:
        table = Table(title="Forensic Timeline", box=box.SIMPLE_HEAVY)
        table.add_column("Timestamp", style="cyan", width=26)
        table.add_column("Level", width=8)
        table.add_column("Source", style="green", width=20)
        table.add_column("Message", style="white")
        for e in entries:
            table.add_row(
                e.get("timestamp", "?")[:26],
                e.get("level", "?"),
                e.get("source", "?"),
                e.get("message", "?"),
            )
        console.print(table)
    else:
        for e in entries:
            print(
                f"{e.get('timestamp', '?')[:26]}  "
                f"{e.get('level', '?'):8s}  "
                f"{e.get('source', '?'):20s}  "
                f"{e.get('message', '?')}"
            )


def cmd_search(args, config):
    """Full-text search across forensic logs."""
    log_dir = config["logging"]["log_dir"]
    query = args.query.lower()
    results = []

    for fname in os.listdir(log_dir):
        fpath = os.path.join(log_dir, fname)
        if not os.path.isfile(fpath) or not fname.endswith(".log"):
            continue
        for entry in read_log_entries(fpath):
            text = json.dumps(entry, default=str).lower()
            if query in text:
                entry["_source_file"] = fname
                results.append(entry)

    if not results:
        _print_info(f"No results for '{args.query}'")
        return

    _print_info(f"Found {len(results)} matching entries")
    for e in results[-30:]:
        print(json.dumps(e, indent=2, default=str))
        print("---")


def cmd_export(args, config):
    """Export forensic data to CSV or JSON."""
    log_dir = config["logging"]["log_dir"]
    main_log = os.path.join(log_dir, "lysec.log")
    if not os.path.isfile(main_log):
        main_log = os.path.join(log_dir, "dftool.log")
    alert_log = config.get("alerts", {}).get("alert_log", "/var/log/lysec/alerts.log")

    source = args.source or "all"
    entries = []
    if source in ("all", "events"):
        entries.extend(read_log_entries(main_log))
    if source in ("all", "alerts"):
        entries.extend(read_log_entries(alert_log))

    # Sort by timestamp
    entries.sort(key=lambda e: e.get("timestamp", ""))

    output = args.output
    fmt = args.format or "json"

    if fmt == "json":
        with open(output, "w") as f:
            json.dump(entries, f, indent=2, default=str)
    elif fmt == "csv":
        import csv
        if not entries:
            _print_info("No data to export")
            return
        keys = set()
        for e in entries:
            keys.update(e.keys())
        keys = sorted(keys)
        with open(output, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
            writer.writeheader()
            for e in entries:
                writer.writerow({k: json.dumps(v) if isinstance(v, (dict, list)) else v for k, v in e.items()})

    _print_success(f"Exported {len(entries)} entries to {output} ({fmt})")


def cmd_verify(args, config):
    """Verify log file integrity using SHA-256 manifest."""
    log_dir = config["logging"]["log_dir"]
    manifests = [
        f for f in os.listdir(log_dir) if f.endswith(".sha256")
    ] if os.path.isdir(log_dir) else []

    if not manifests:
        _print_info("No integrity manifests found (logs may not have rotated yet)")
        return

    ok = 0
    fail = 0
    for mf in manifests:
        mf_path = os.path.join(log_dir, mf)
        with open(mf_path) as f:
            for line in f:
                parts = line.strip().split("  ")
                if len(parts) < 3:
                    continue
                ts, expected_hash, filepath = parts[0], parts[1], parts[2]
                if os.path.isfile(filepath):
                    actual = _hash_file(filepath)
                    if actual == expected_hash:
                        _print_success(f"  OK  {filepath}")
                        ok += 1
                    else:
                        _print_error(
                            f"  TAMPERED  {filepath} "
                            f"(expected {expected_hash[:16]}… got {actual[:16]}…)"
                        )
                        fail += 1
                else:
                    _print_warn(f"  MISSING  {filepath}")
                    fail += 1

    _print_info(f"Verification complete: {ok} OK, {fail} failed/missing")


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _get_running_pid(pid_file: str):
    if not os.path.isfile(pid_file):
        return None
    try:
        with open(pid_file) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        return pid
    except (ValueError, OSError):
        return None


def _parse_ts(ts_str: str | None):
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str)
    except Exception:
        return None


def _hash_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _human_size(nbytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if nbytes < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} TB"


def _print_info(msg):
    if HAS_RICH:
        console.print(f"[cyan]ℹ[/cyan] {msg}")
    else:
        print(f"[INFO] {msg}")

def _print_success(msg):
    if HAS_RICH:
        console.print(f"[green]✔[/green] {msg}")
    else:
        print(f"[ OK ] {msg}")

def _print_warn(msg):
    if HAS_RICH:
        console.print(f"[yellow]⚠[/yellow] {msg}")
    else:
        print(f"[WARN] {msg}")

def _print_error(msg):
    if HAS_RICH:
        console.print(f"[bold red]✖[/bold red] {msg}")
    else:
        print(f"[FAIL] {msg}")


# ──────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="lysec",
        description="LySec - Linux Forensics Log Query & Management CLI",
    )
    parser.add_argument(
        "--config", "-c",
        default=DEFAULT_CONFIG_PATH,
        help="Path to configuration file",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # status
    sub.add_parser("status", help="Show daemon status")

    # alerts
    p_alerts = sub.add_parser("alerts", help="View alerts")
    p_alerts.add_argument("--severity", "-s", help="Filter by severity (INFO/LOW/MEDIUM/HIGH/CRITICAL)")
    p_alerts.add_argument("--last", "-l", help="Show alerts from last duration (e.g., 1h, 30m, 2d)")

    # timeline
    p_tl = sub.add_parser("timeline", help="Generate event timeline")
    p_tl.add_argument("--start", help="Start time (ISO 8601)")
    p_tl.add_argument("--end", help="End time (ISO 8601)")
    p_tl.add_argument("--monitor", "-m", help="Filter by monitor name")

    # search
    p_search = sub.add_parser("search", help="Search forensic logs")
    p_search.add_argument("--query", "-q", required=True, help="Search query")

    # export
    p_export = sub.add_parser("export", help="Export forensic data")
    p_export.add_argument("--format", "-f", choices=["json", "csv"], default="json")
    p_export.add_argument("--output", "-o", required=True, help="Output file path")
    p_export.add_argument("--source", choices=["all", "events", "alerts"], default="all")

    # verify
    sub.add_parser("verify", help="Verify log file integrity")

    args = parser.parse_args()
    config = load_config(args.config)

    commands = {
        "status": cmd_status,
        "alerts": cmd_alerts,
        "timeline": cmd_timeline,
        "search": cmd_search,
        "export": cmd_export,
        "verify": cmd_verify,
    }

    cmd_func = commands.get(args.command)
    if cmd_func:
        cmd_func(args, config)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
