"""
LySec - Filesystem Monitor
Watches critical filesystem paths for modifications using the watchdog
library (inotify backend on Linux).  Optionally hashes changed files.

Monitored events:
    * File creation, modification, deletion
    * Permission / ownership changes
    * Critical config file tampering (/etc/passwd, /etc/shadow, sudoers, ...)

Forensic value:
    * Evidence of persistence mechanisms (cron, systemd, ssh keys).
    * Evidence of credential harvesting (shadow, passwd).
    * Timeline of attacker filesystem activity.

NOTE: Detection & Logging ONLY — no file restoration, no write blocking.
"""

import hashlib
import logging
import os
import stat
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from watchdog.observers import Observer
    from watchdog.events import (
        FileSystemEventHandler,
        FileCreatedEvent,
        FileModifiedEvent,
        FileDeletedEvent,
        FileMovedEvent,
        DirCreatedEvent,
        DirDeletedEvent,
        DirMovedEvent,
    )
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

from lysec.monitors.base import BaseMonitor
from lysec.alert_engine import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_MEDIUM,
)

logger = logging.getLogger("lysec.monitor.filesystem")

# Files that are especially critical from a forensic perspective
CRITICAL_FILES = {
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/sudoers", "/etc/ssh/sshd_config",
    "/etc/pam.d/common-auth", "/etc/pam.d/sshd",
    "/etc/ld.so.preload", "/etc/ld.so.conf",
    "/etc/crontab", "/etc/hosts", "/etc/resolv.conf",
    "/root/.bashrc", "/root/.bash_profile",
}


class ForensicEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler that logs every fs event with forensic detail.
    """

    def __init__(self, alert_engine, mon_cfg: dict):
        super().__init__()
        self._alert = alert_engine
        self._mon_cfg = mon_cfg

    def on_created(self, event):
        if event.is_directory:
            self._handle("DIR_CREATED", event.src_path)
        else:
            self._handle("FILE_CREATED", event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._handle("FILE_MODIFIED", event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            self._handle("DIR_DELETED", event.src_path)
        else:
            self._handle("FILE_DELETED", event.src_path)

    def on_moved(self, event):
        self._handle("FILE_MOVED", event.src_path, dest=event.dest_path)

    def _handle(self, event_type: str, path: str, dest: str = None):
        is_critical = path in CRITICAL_FILES or any(
            path.startswith(cf) for cf in CRITICAL_FILES
        )
        severity = SEVERITY_CRITICAL if is_critical else SEVERITY_MEDIUM

        details: dict[str, Any] = {
            "path": path,
            "event": event_type,
        }

        if dest:
            details["dest_path"] = dest

        # Capture file metadata if still exists
        if os.path.exists(path):
            try:
                st = os.stat(path)
                details["uid"] = st.st_uid
                details["gid"] = st.st_gid
                details["mode"] = oct(st.st_mode)
                details["size"] = st.st_size
                details["mtime"] = datetime.fromtimestamp(
                    st.st_mtime, tz=timezone.utc
                ).isoformat()
            except Exception:
                pass

            # Hash small files for evidence integrity
            if os.path.isfile(path):
                try:
                    size = os.path.getsize(path)
                    if size < 10 * 1024 * 1024:  # < 10 MB
                        details["sha256"] = _hash_file(path)
                except Exception:
                    pass

        action_word = {
            "FILE_CREATED": "created",
            "FILE_MODIFIED": "modified",
            "FILE_DELETED": "deleted",
            "FILE_MOVED": "moved",
            "DIR_CREATED": "created (dir)",
            "DIR_DELETED": "deleted (dir)",
        }.get(event_type, event_type)

        message = f"Filesystem {action_word}: {path}"
        if dest:
            message += f" -> {dest}"

        logger.info("FS_%s: %s", event_type, path)

        # Only fire alerts per config
        should_alert = False
        if "CREATED" in event_type and self._mon_cfg.get("alert_on_create"):
            should_alert = True
        elif "MODIFIED" in event_type and self._mon_cfg.get("alert_on_modify"):
            should_alert = True
        elif "DELETED" in event_type and self._mon_cfg.get("alert_on_delete"):
            should_alert = True
        elif "MOVED" in event_type:
            should_alert = True

        if should_alert or is_critical:
            self._alert.fire(
                monitor="filesystem",
                event_type=f"FS_{event_type}",
                message=message,
                severity=severity,
                details=details,
            )


class FilesystemMonitor(BaseMonitor):
    name = "filesystem"

    def __init__(self, config: dict, alert_engine):
        super().__init__(config, alert_engine)
        self._mon_cfg = config.get("monitors", {}).get("filesystem", {})
        self._observer = None
        self._handler = None
        self._watched_paths: set[str] = set()
        self._watch_removable = bool(self._mon_cfg.get("watch_removable_media", True))
        self._mount_roots = self._mon_cfg.get(
            "mount_watch_roots", ["/media", "/run/media", "/mnt"]
        )

    def setup(self):
        if not HAS_WATCHDOG:
            logger.error("watchdog library required for filesystem monitoring")
            return

        self._observer = Observer()
        self._handler = ForensicEventHandler(self._alert, self._mon_cfg)
        recursive = self._mon_cfg.get("recursive", True)

        watch_paths = self._mon_cfg.get("watch_paths", [])
        for path in watch_paths:
            self._schedule_watch(path, recursive=recursive)

        # Also add currently mounted removable paths at startup.
        if self._watch_removable:
            self._watch_new_mount_points(recursive=recursive)

        if self._watched_paths:
            self._observer.start()
            logger.info(
                "Filesystem observer started — watching %d path(s)",
                len(self._watched_paths),
            )
        else:
            logger.warning("No valid paths to watch")

    def poll(self):
        # Add new removable-media mount points discovered after daemon start.
        if self._watch_removable and self._observer:
            recursive = self._mon_cfg.get("recursive", True)
            self._watch_new_mount_points(recursive=recursive)

    def teardown(self):
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)

    def _schedule_watch(self, path: str, recursive: bool):
        if not self._observer or not self._handler:
            return

        norm = os.path.abspath(path)
        if norm in self._watched_paths:
            return

        if not os.path.exists(norm):
            logger.warning("Watch path does not exist: %s", norm)
            return

        try:
            self._observer.schedule(
                self._handler,
                norm,
                recursive=recursive and os.path.isdir(norm),
            )
            self._watched_paths.add(norm)
            logger.info("Watching: %s (recursive=%s)", norm, recursive)
        except Exception as exc:
            logger.error("Cannot watch %s: %s", norm, exc)

    def _watch_new_mount_points(self, recursive: bool):
        for mount in self._discover_mount_points():
            self._schedule_watch(mount, recursive=recursive)

    def _discover_mount_points(self) -> list[str]:
        mounts: list[str] = []
        roots = [os.path.abspath(r) for r in self._mount_roots]

        try:
            with open("/proc/mounts", "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    mnt = parts[1].replace("\\040", " ")
                    mnt_abs = os.path.abspath(mnt)
                    for root in roots:
                        if mnt_abs == root or mnt_abs.startswith(root + os.sep):
                            mounts.append(mnt_abs)
                            break
        except Exception:
            pass

        return sorted(set(mounts))


def _hash_file(filepath: str, algorithm: str = "sha256") -> str:
    h = hashlib.new(algorithm)
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

