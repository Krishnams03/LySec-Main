"""
LySec - Process Monitor
Watches process creation, privilege escalation, and suspicious binaries.
Uses psutil to poll the process table on each interval.

Forensic value:
    * Detect malicious or recon tools being launched.
    * Track privilege escalation (UID changes).
    * Build a process timeline for incident reconstruction.

NOTE: Detection & Logging ONLY — no process killing.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from lysec.monitors.base import BaseMonitor
from lysec.alert_engine import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_MEDIUM,
)

logger = logging.getLogger("lysec.monitor.process")


class ProcessMonitor(BaseMonitor):
    name = "process"

    def __init__(self, config: dict, alert_engine):
        super().__init__(config, alert_engine)
        self._mon_cfg = config.get("monitors", {}).get("process", {})
        self._suspicious: set[str] = set(
            self._mon_cfg.get("suspicious_names", [])
        )
        self._alert_on_new_process = bool(self._mon_cfg.get("alert_on_new_process", True))
        # pid -> snapshot
        self._known_procs: dict[int, dict] = {}
        self._first_run = True

    def setup(self):
        if not HAS_PSUTIL:
            logger.error("psutil required for process monitoring")
            return
        self._snapshot()
        logger.info(
            "Process monitor initialised — %d running processes",
            len(self._known_procs),
        )

    def poll(self):
        if not HAS_PSUTIL:
            return

        current: dict[int, dict] = {}
        for proc in psutil.process_iter(
            ["pid", "name", "username", "cmdline", "exe",
             "ppid", "create_time", "uids", "status"]
        ):
            try:
                info = proc.info
                pid = info["pid"]
                current[pid] = info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if self._first_run:
            self._known_procs = current
            self._first_run = False
            return

        current_pids = set(current.keys())
        known_pids = set(self._known_procs.keys())

        # ── New processes ──
        for pid in current_pids - known_pids:
            info = current[pid]
            self._on_new_process(info)

        # ── Examine still-running processes for changes ──
        for pid in current_pids & known_pids:
            old = self._known_procs[pid]
            new = current[pid]
            self._check_priv_change(old, new)

        self._known_procs = current

    # ──────────────────────── Event handlers ────────────────────────────

    def _on_new_process(self, info: dict):
        name = info.get("name", "")
        cmdline = " ".join(info.get("cmdline") or [])
        user = info.get("username", "?")
        pid = info.get("pid")
        exe = info.get("exe", "")
        ppid = info.get("ppid")

        base_details = {
            "pid": pid,
            "name": name,
            "exe": exe,
            "cmdline": cmdline,
            "user": user,
            "ppid": ppid,
        }
        if exe:
            base_details["path"] = exe

        if self._alert_on_new_process:
            self._alert.fire(
                monitor="process",
                event_type="PROCESS_STARTED",
                message=f"Process started: {name} (pid {pid}) by {user}",
                severity=SEVERITY_INFO,
                details=base_details,
            )

        logger.debug(
            "NEW_PROCESS pid=%s name=%s user=%s cmd=%s",
            pid, name, user, cmdline,
        )

        # Check against suspicious names
        basename = os.path.basename(exe or name or "").lower()
        if basename in self._suspicious or name.lower() in self._suspicious:
            logger.warning(
                "SUSPICIOUS_PROCESS pid=%s name=%s user=%s cmd=%s",
                pid, name, user, cmdline,
            )
            self._alert.fire(
                monitor="process",
                event_type="SUSPICIOUS_PROCESS",
                message=f"Suspicious process detected: {name} (pid {pid}) by {user}",
                severity=SEVERITY_HIGH,
                details=base_details,
            )

        # Root process spawned by non-root parent?
        uids = info.get("uids")
        if uids and uids.real == 0:
            ppid = info.get("ppid")
            if ppid and ppid in self._known_procs:
                parent = self._known_procs[ppid]
                parent_uids = parent.get("uids")
                if parent_uids and parent_uids.real != 0:
                    logger.warning(
                        "PRIV_ESCALATION new root process pid=%s name=%s "
                        "spawned by non-root parent pid=%s name=%s",
                        pid, name, ppid, parent.get("name"),
                    )
                    self._alert.fire(
                        monitor="process",
                        event_type="PRIVILEGE_ESCALATION",
                        message=(
                            f"Root process {name} (pid {pid}) spawned by "
                            f"non-root parent {parent.get('name')} (pid {ppid})"
                        ),
                        severity=SEVERITY_CRITICAL,
                        details={
                            "pid": pid,
                            "name": name,
                            "uid": 0,
                            "parent_pid": ppid,
                            "parent_name": parent.get("name"),
                            "parent_uid": parent_uids.real if parent_uids else "?",
                        },
                    )

    def _check_priv_change(self, old: dict, new: dict):
        """Detect if a running process changed its effective UID."""
        old_uids = old.get("uids")
        new_uids = new.get("uids")
        if not old_uids or not new_uids:
            return

        if old_uids.effective != new_uids.effective:
            pid = new.get("pid")
            name = new.get("name", "?")
            logger.warning(
                "UID_CHANGE pid=%s name=%s uid %s -> %s",
                pid, name, old_uids.effective, new_uids.effective,
            )
            severity = SEVERITY_CRITICAL if new_uids.effective == 0 else SEVERITY_HIGH
            self._alert.fire(
                monitor="process",
                event_type="UID_CHANGE",
                message=(
                    f"Process {name} (pid {pid}) changed UID: "
                    f"{old_uids.effective} -> {new_uids.effective}"
                ),
                severity=severity,
                details={
                    "pid": pid,
                    "name": name,
                    "old_uid": old_uids.effective,
                    "new_uid": new_uids.effective,
                },
            )

    # ──────────────────────── Snapshot ──────────────────────────────────
    def _snapshot(self):
        for proc in psutil.process_iter(
            ["pid", "name", "username", "cmdline", "exe",
             "ppid", "create_time", "uids", "status"]
        ):
            try:
                info = proc.info
                self._known_procs[info["pid"]] = info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

