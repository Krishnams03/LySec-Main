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

from dftool.monitors.base import BaseMonitor
from dftool.alert_engine import (
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

    def setup(self):
        if not HAS_WATCHDOG:
            logger.error("watchdog library required for filesystem monitoring")
            return

        self._observer = Observer()
        handler = ForensicEventHandler(self._alert, self._mon_cfg)
        recursive = self._mon_cfg.get("recursive", True)

        watch_paths = self._mon_cfg.get("watch_paths", [])
        scheduled = 0
        for path in watch_paths:
            if os.path.exists(path):
                try:
                    self._observer.schedule(
                        handler, path, recursive=recursive and os.path.isdir(path)
                    )
                    scheduled += 1
                    logger.info("Watching: %s (recursive=%s)", path, recursive)
                except Exception as exc:
                    logger.error("Cannot watch %s: %s", path, exc)
            else:
                logger.warning("Watch path does not exist: %s", path)

        if scheduled > 0:
            self._observer.start()
            logger.info("Filesystem observer started — watching %d paths", scheduled)
        else:
            logger.warning("No valid paths to watch")

    def poll(self):
        # Watchdog runs its own thread; poll is a no-op unless we want to
        # do periodic integrity checks on specific files
        pass

    def teardown(self):
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)


def _hash_file(filepath: str, algorithm: str = "sha256") -> str:
    h = hashlib.new(algorithm)
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()
