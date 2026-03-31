"""
LySec - CLI Query & Management Tool
Command-line interface for querying forensic logs, viewing alerts,
generating timeline reports, and managing the daemon.

Usage:
    lysec status                                # daemon status
    lysec alerts [--severity HIGH] [--last 1h]  # view alerts
    lysec anomalies [--last 1h] [--top 20]      # ranked ML anomaly incidents
    lysec split [--last 1h] [--output-dir /tmp/lysec_split]  # per-monitor split
    lysec correlate --scenario usb_login_modify --last 6h     # attack chain search
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
from collections import deque
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

from lysec.config import load_config, DEFAULT_CONFIG_PATH


console = Console() if HAS_RICH else None


# ──────────────────────────────────────────────
# Log reader utilities
# ──────────────────────────────────────────────

def read_log_entries(log_path: str, max_entries: int = 10000) -> list[dict]:
    """Read JSON log entries from a LySec log file."""
    entries = deque(maxlen=max_entries)
    if not os.path.isfile(log_path):
        return []
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return list(entries)


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

    # Filter by monitor(s)
    if getattr(args, "monitor", None):
        monitors = {
            m.strip().lower()
            for m in str(args.monitor).split(",")
            if m.strip()
        }
        if monitors:
            entries = [e for e in entries if str(e.get("monitor", "")).lower() in monitors]

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

    limit = int(getattr(args, "limit", 50) or 50)
    if limit < 0:
        limit = 50
    view_entries = entries if limit == 0 else entries[-limit:]

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

        for e in view_entries:
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
        for e in view_entries:
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


def cmd_anomalies(args, config):
    """Display ranked live ML anomaly incidents."""
    alert_log = config.get("alerts", {}).get(
        "alert_log", "/var/log/lysec/alerts.log"
    )
    entries = read_log_entries(alert_log)

    entries = [
        e
        for e in entries
        if e.get("event_type") == "ML_ANOMALY_INCIDENT" or e.get("monitor") == "ml"
    ]

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
                    filtered.append(e)
            entries = filtered
        except ValueError as exc:
            _print_error(str(exc))
            return

    if args.min_score is not None:
        try:
            threshold = float(args.min_score)
            entries = [
                e
                for e in entries
                if float((e.get("details", {}) or {}).get("anomaly_score", 0.0)) >= threshold
            ]
        except (TypeError, ValueError):
            _print_error("Invalid --min-score value")
            return

    entries.sort(
        key=lambda e: (
            float((e.get("details", {}) or {}).get("anomaly_score", 0.0)),
            e.get("timestamp", ""),
        ),
        reverse=True,
    )

    top_n = max(1, int(args.top or 20))
    entries = entries[:top_n]

    if not entries:
        _print_info("No ML anomaly incidents found for the specified criteria.")
        return

    if HAS_RICH:
        table = Table(title="LySec ML Anomaly Triage", box=box.ROUNDED, show_lines=True)
        table.add_column("Time", style="cyan", width=26)
        table.add_column("Severity", width=10)
        table.add_column("Anomaly", style="magenta", width=10)
        table.add_column("Indicator", style="green", width=24)
        table.add_column("Events", width=8)
        table.add_column("Monitors", style="yellow")

        for e in entries:
            details = e.get("details", {}) or {}
            score = float(details.get("anomaly_score", 0.0))
            table.add_row(
                str(e.get("timestamp", "?"))[:26],
                str(e.get("severity", "?")),
                f"{score:.2f}",
                str(details.get("indicator", "?")),
                str(details.get("event_count", "?")),
                ",".join(details.get("monitors", []) or []),
            )
        console.print(table)
    else:
        for e in entries:
            details = e.get("details", {}) or {}
            score = float(details.get("anomaly_score", 0.0))
            print(
                f"[{str(e.get('timestamp', '?'))[:19]}] "
                f"{str(e.get('severity', '?')):10s} "
                f"anomaly={score:6.2f} "
                f"indicator={details.get('indicator', '?')} "
                f"events={details.get('event_count', '?')} "
                f"monitors={','.join(details.get('monitors', []) or [])}"
            )


def cmd_split(args, config):
    """Split alerts by monitor and optionally export separate files."""
    alert_log = config.get("alerts", {}).get("alert_log", "/var/log/lysec/alerts.log")
    entries = read_log_entries(alert_log)
    entries = _filter_entries_last(entries, args.last)

    buckets: dict[str, list[dict]] = {}
    for entry in entries:
        mon = str(entry.get("monitor", "unknown") or "unknown")
        buckets.setdefault(mon, []).append(entry)

    if not buckets:
        _print_info("No entries found for split criteria.")
        return

    if HAS_RICH:
        table = Table(title="LySec Monitor Split", box=box.ROUNDED, show_lines=True)
        table.add_column("Monitor", style="green")
        table.add_column("Alerts", style="cyan")
        table.add_column("Top Events", style="yellow")
        for mon in sorted(buckets.keys()):
            mon_entries = buckets[mon]
            event_counts: dict[str, int] = {}
            for e in mon_entries:
                ev = str(e.get("event_type", "?"))
                event_counts[ev] = event_counts.get(ev, 0) + 1
            top_events = ", ".join(
                f"{k}:{v}" for k, v in sorted(event_counts.items(), key=lambda item: item[1], reverse=True)[:3]
            )
            table.add_row(mon, str(len(mon_entries)), top_events or "-")
        console.print(table)
    else:
        print("Monitor split summary")
        for mon in sorted(buckets.keys()):
            print(f"- {mon}: {len(buckets[mon])} alerts")

    if args.output_dir:
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for mon in sorted(buckets.keys()):
            out_file = out_dir / f"{mon}.json"
            with open(out_file, "w", encoding="utf-8") as fh:
                json.dump(buckets[mon], fh, indent=2, default=str)
        _print_success(f"Per-monitor exports written to {out_dir}")


SCENARIOS = {
    "usb_login_modify": ["USB_DEVICE_ATTACHED", "LOGIN_SUCCESS", "FS_FILE_MODIFIED"],
    "usb_login_delete": ["USB_DEVICE_ATTACHED", "LOGIN_SUCCESS", "FS_FILE_DELETED"],
    "usb_to_priv_esc": ["USB_DEVICE_ATTACHED", "LOGIN_SUCCESS", "PRIVILEGE_ESCALATION"],
    "recon_to_priv": ["NEW_INTERFACE", "PROMISCUOUS_MODE", "PRIVILEGE_ESCALATION"],
}


EVENT_ALIASES = {
    "FILE_CREATED": {"FILE_CREATED", "FS_FILE_CREATED"},
    "FILE_MODIFIED": {"FILE_MODIFIED", "FS_FILE_MODIFIED"},
    "FILE_DELETED": {"FILE_DELETED", "FS_FILE_DELETED"},
    "FILE_MOVED": {"FILE_MOVED", "FS_FILE_MOVED"},
    "DIR_CREATED": {"DIR_CREATED", "FS_DIR_CREATED"},
    "DIR_DELETED": {"DIR_DELETED", "FS_DIR_DELETED"},
}


def cmd_correlate(args, config):
    """Find ordered multi-step attack chains in alert history."""
    alert_log = config.get("alerts", {}).get("alert_log", "/var/log/lysec/alerts.log")
    entries = read_log_entries(alert_log)
    entries = _filter_entries_last(entries, args.last)

    sequence = _resolve_sequence(args.scenario, args.sequence)
    if not sequence:
        _print_error("Provide --scenario or --sequence EVENT1,EVENT2,EVENT3")
        return

    try:
        max_span = parse_duration(args.window)
    except ValueError as exc:
        _print_error(str(exc))
        return

    findings = _find_ordered_sequences(entries, sequence, max_span)
    if not findings:
        _print_info("No correlated chains found for specified criteria.")
        return

    if HAS_RICH:
        table = Table(title="LySec Correlated Chains", box=box.ROUNDED, show_lines=True)
        table.add_column("Start", style="cyan", width=26)
        table.add_column("End", style="cyan", width=26)
        table.add_column("Span", style="magenta", width=10)
        table.add_column("Sequence", style="green")
        table.add_column("Evidence", style="yellow")
        for chain in findings[: args.top]:
            ev_summary = " | ".join(f"{e.get('monitor', '?')}:{e.get('event_type', '?')}" for e in chain["events"])
            table.add_row(
                chain["start"][:26],
                chain["end"][:26],
                chain["span"],
                " -> ".join(sequence),
                ev_summary,
            )
        console.print(table)
    else:
        for chain in findings[: args.top]:
            print(
                f"[{chain['start'][:19]} -> {chain['end'][:19]}] "
                f"span={chain['span']} seq={' -> '.join(sequence)}"
            )

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "sequence": sequence,
                    "scenario": args.scenario,
                    "window": args.window,
                    "result_count": len(findings),
                    "chains": findings[: args.top],
                },
                fh,
                indent=2,
                default=str,
            )
        _print_success(f"Correlation report written to {args.output}")


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


def _filter_entries_last(entries: list[dict], last: str | None) -> list[dict]:
    if not last:
        return entries
    delta = parse_duration(last)
    cutoff = datetime.now(timezone.utc) - delta
    filtered = []
    for e in entries:
        ts = _parse_ts(e.get("timestamp"))
        if ts is None:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if ts >= cutoff:
            filtered.append(e)
    return filtered


def _resolve_sequence(scenario: str | None, sequence: str | None) -> list[str]:
    if sequence:
        raw = [s.strip() for s in sequence.split(",") if s.strip()]
        return [_normalize_event_name(s) for s in raw]
    if scenario:
        return SCENARIOS.get(scenario, [])
    return []


def _normalize_event_name(name: str) -> str:
    key = str(name or "").strip().upper()
    if not key:
        return key
    aliases = EVENT_ALIASES.get(key)
    if aliases:
        # Prefer canonical FS_* representation for filesystem events.
        for item in aliases:
            if item.startswith("FS_"):
                return item
    return key


def _event_matches(actual_event: str, expected_event: str) -> bool:
    actual = str(actual_event or "").strip().upper()
    expected = _normalize_event_name(expected_event)
    if actual == expected:
        return True

    aliases = EVENT_ALIASES.get(expected)
    if aliases and actual in aliases:
        return True

    # Also allow expected to be a plain alias key while actual is canonical.
    aliases = EVENT_ALIASES.get(str(expected_event or "").strip().upper())
    if aliases and actual in aliases:
        return True

    return False


def _find_ordered_sequences(
    entries: list[dict],
    sequence: list[str],
    max_span: timedelta,
) -> list[dict]:
    if len(sequence) < 2:
        return []

    events = []
    for e in entries:
        ts = _parse_ts(e.get("timestamp"))
        if ts is None:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        events.append((ts, e))

    events.sort(key=lambda item: item[0])
    findings: list[dict] = []

    for idx, (start_ts, start_event) in enumerate(events):
        if not _event_matches(start_event.get("event_type", ""), sequence[0]):
            continue

        chain = [start_event]
        current_step = 1
        end_ts = start_ts

        for j in range(idx + 1, len(events)):
            ts, entry = events[j]
            if ts - start_ts > max_span:
                break
            if _event_matches(entry.get("event_type", ""), sequence[current_step]):
                chain.append(entry)
                end_ts = ts
                current_step += 1
                if current_step == len(sequence):
                    findings.append(
                        {
                            "start": start_ts.isoformat(),
                            "end": end_ts.isoformat(),
                            "span": str(end_ts - start_ts),
                            "events": chain,
                        }
                    )
                    break

    findings.sort(key=lambda c: c["start"], reverse=True)
    return findings


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
    p_alerts.add_argument("--monitor", "-m", help="Filter by monitor (single or CSV, e.g., usb,filesystem)")
    p_alerts.add_argument("--limit", type=int, default=50, help="Max rows to display (0 = all, default: 50)")

    # anomalies
    p_anom = sub.add_parser("anomalies", help="Rank live ML anomaly incidents")
    p_anom.add_argument("--last", "-l", help="Show anomalies from last duration (e.g., 1h, 30m, 2d)")
    p_anom.add_argument("--top", "-t", type=int, default=20, help="Max incidents to display (default: 20)")
    p_anom.add_argument("--min-score", type=float, help="Minimum anomaly score to include")

    # split
    p_split = sub.add_parser("split", help="Show/export alerts separated by monitor")
    p_split.add_argument("--last", "-l", help="Show alerts from last duration (e.g., 1h, 30m, 2d)")
    p_split.add_argument("--output-dir", "-o", help="Write per-monitor JSON files to this directory")

    # correlate
    p_corr = sub.add_parser("correlate", help="Find ordered attack chains")
    p_corr.add_argument("--scenario", choices=sorted(SCENARIOS.keys()), help="Predefined attack scenario")
    p_corr.add_argument("--sequence", help="Custom event sequence CSV (e.g., USB_DEVICE_ATTACHED,LOGIN_SUCCESS,FS_FILE_MODIFIED)")
    p_corr.add_argument("--last", "-l", default="6h", help="Lookback duration (default: 6h)")
    p_corr.add_argument("--window", "-w", default="30m", help="Max allowed span for one chain (default: 30m)")
    p_corr.add_argument("--top", "-t", type=int, default=20, help="Max chains to display (default: 20)")
    p_corr.add_argument("--output", "-o", help="Write correlation result JSON")

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
        "anomalies": cmd_anomalies,
        "split": cmd_split,
        "correlate": cmd_correlate,
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

