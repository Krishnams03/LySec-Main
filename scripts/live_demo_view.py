#!/usr/bin/env python3
"""
LySec live demo viewer.
Follows the alerts log and prints selected monitors for demo mode.

Usage:
  sudo python3 scripts/live_demo_view.py
  sudo python3 scripts/live_demo_view.py --alerts-log /var/log/lysec/alerts.log
    sudo python3 scripts/live_demo_view.py --show-fuzzy
"""

import argparse
import json
import os
import time

MONITORS = {"daemon", "usb", "process", "filesystem", "watchdog"}


def _usb_type_from_event(event: dict) -> str:
    details = event.get("details", {})
    if not isinstance(details, dict):
        return ""
    return str(details.get("usb_type", "")).strip().lower()


def _print_highlights(event: dict):
    mon = str(event.get("monitor", ""))
    et = str(event.get("event_type", ""))
    details = event.get("details", {})
    details = details if isinstance(details, dict) else {}

    if et == "DAEMON_START":
        startup = details.get("startup_context")
        if isinstance(startup, dict):
            uptime = startup.get("uptime_sec", "?")
            default_target = startup.get("default_target", "")
            dm = startup.get("display_manager_status", {})
            print(f"{'':48} [evidence] startup_context uptime_sec={uptime} default_target={default_target}")
            if isinstance(dm, dict) and dm:
                print(f"{'':48} [evidence] display_manager_status={dm}")

    if mon == "usb" and et == "USB_DEVICE_ATTACHED":
        utype = _usb_type_from_event(event)
        if utype == "mass_storage":
            print(f"{'':48} [PASS] usb_type=mass_storage seen")
        elif utype == "hid":
            print(f"{'':48} [PASS] usb_type=hid seen")
        elif utype:
            print(f"{'':48} [PASS] usb_type=other seen ({utype})")

    if mon == "process" and et in {"PROCESS_STARTED", "SUSPICIOUS_PROCESS"}:
        pname = details.get("name") or details.get("process_name") or "?"
        print(f"{'':48} [PASS] process signal {et} name={pname}")

    if mon == "filesystem":
        if "fuzzy_hash" in details:
            print(f"{'':48} [PASS] filesystem fuzzy_hash present")
        if "fuzzy_similarity" in details:
            print(f"{'':48} [PASS] filesystem fuzzy_similarity present")

    if "alert_fuzzy" in details:
        print(f"{'':48} [PASS] global alert_fuzzy present")

    if mon == "process" and et == "LOGIN_SERVICE_RESTART_BURST":
        print(f"{'':48} [WARN] login service restart burst detected")

    if mon == "watchdog":
        print(f"{'':48} [PASS] watchdog monitor activity observed")


def follow(path: str, show_fuzzy: bool = False):
    while not os.path.exists(path):
        print(f"[wait] alerts log not found yet: {path}")
        time.sleep(1)

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        fh.seek(0, os.SEEK_END)
        print(f"[info] watching {path}")
        print("[info] filters: usb, process, filesystem, watchdog")
        print("[info] highlights: usb types, process signals, fuzzy fields, watchdog, startup_context")
        while True:
            line = fh.readline()
            if not line:
                time.sleep(0.2)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            mon = str(event.get("monitor", ""))
            if mon not in MONITORS:
                continue

            ts = str(event.get("timestamp", ""))[:26]
            sev = str(event.get("severity", "?"))
            et = str(event.get("event_type", "?"))
            msg = str(event.get("message", ""))
            print(f"{ts}  {sev:<9}  {mon:<10}  {et:<28}  {msg}")
            _print_highlights(event)

            if show_fuzzy and mon == "filesystem":
                details = event.get("details", {})
                if isinstance(details, dict):
                    fuzzy = details.get("fuzzy_hash")
                    similarity = details.get("fuzzy_similarity")
                    alert_fuzzy = details.get("alert_fuzzy")
                    if fuzzy:
                        print(f"{'':48} fuzzy_hash={fuzzy}")
                    if similarity:
                        print(f"{'':48} fuzzy_similarity={similarity}")
                    if alert_fuzzy:
                        print(f"{'':48} alert_fuzzy={alert_fuzzy}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live LySec demo event viewer")
    parser.add_argument(
        "--alerts-log",
        default="/var/log/lysec/alerts.log",
        help="Path to LySec alerts log",
    )
    parser.add_argument(
        "--show-fuzzy",
        action="store_true",
        help="Print fuzzy hash and similarity fields for filesystem alerts",
    )
    args = parser.parse_args()
    follow(args.alerts_log, show_fuzzy=args.show_fuzzy)
