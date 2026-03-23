#!/usr/bin/env python3
"""
LySec live demo viewer.
Follows the alerts log and prints only usb/process/filesystem events.

Usage:
  sudo python3 scripts/live_demo_view.py
  sudo python3 scripts/live_demo_view.py --alerts-log /var/log/lysec/alerts.log
"""

import argparse
import json
import os
import time

MONITORS = {"usb", "process", "filesystem"}


def follow(path: str):
    while not os.path.exists(path):
        print(f"[wait] alerts log not found yet: {path}")
        time.sleep(1)

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        fh.seek(0, os.SEEK_END)
        print(f"[info] watching {path}")
        print("[info] filters: usb, process, filesystem")
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live LySec demo event viewer")
    parser.add_argument(
        "--alerts-log",
        default="/var/log/lysec/alerts.log",
        help="Path to LySec alerts log",
    )
    args = parser.parse_args()
    follow(args.alerts_log)
