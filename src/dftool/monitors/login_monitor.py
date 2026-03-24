"""
LySec - Login / Authentication Monitor
Watches authentication log files (auth.log, secure, wtmp, btmp) for:
    * Successful and failed logins
    * Root / sudo escalation
    * SSH sessions
    * Brute-force patterns (N failures within window)

Forensic value:
    * Timeline of who accessed the system and when.
    * Evidence of unauthorised access attempts.
    * Lateral movement detection.

NOTE: Detection & Logging ONLY — no account locking or IP blocking.
"""

import logging
import os
import re
import struct
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import BinaryIO

from dftool.monitors.base import BaseMonitor
from dftool.alert_engine import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_MEDIUM,
)

logger = logging.getLogger("lysec.monitor.login")

# Regex patterns for auth.log / secure
RE_SSHD_ACCEPTED = re.compile(
    r"sshd\[\d+\]: Accepted (\S+) for (\S+) from ([\d.]+) port (\d+)"
)
RE_SSHD_FAILED = re.compile(
    r"sshd\[\d+\]: Failed (\S+) for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)"
)
RE_SUDO = re.compile(
    r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)"
)
RE_SU = re.compile(
    r"su\[\d+\]: (?:Successful|FAILED) su for (\S+) by (\S+)"
)
RE_SESSION_OPENED = re.compile(
    r"pam_unix\(\S+:session\): session opened for user (\S+)"
)
RE_SESSION_CLOSED = re.compile(
    r"pam_unix\(\S+:session\): session closed for user (\S+)"
)
RE_FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)"
)

# utmp / wtmp record struct (Linux, x86_64) — 384 bytes
UTMP_STRUCT = struct.Struct("hi32s4s32s256shhiii4I20s")
UTMP_SIZE = UTMP_STRUCT.size


class LoginMonitor(BaseMonitor):
    name = "login"

    def __init__(self, config: dict, alert_engine):
        super().__init__(config, alert_engine)
        self._mon_cfg = config.get("monitors", {}).get("login", {})
        self._watch_files: list[str] = self._mon_cfg.get("watch_files", [])
        self._file_offsets: dict[str, int] = {}
        # Brute-force tracker: ip -> [timestamps]
        self._failed_attempts: dict[str, list[float]] = defaultdict(list)
        self._fail_threshold = self._mon_cfg.get("failed_login_threshold", 5)
        self._fail_window = self._mon_cfg.get("failed_login_window_sec", 300)

    def setup(self):
        # Seek to end of each existing log so we don't replay history
        for path in self._watch_files:
            if os.path.isfile(path):
                if path.endswith(("wtmp", "btmp")):
                    self._file_offsets[path] = os.path.getsize(path)
                else:
                    self._file_offsets[path] = os.path.getsize(path)
        logger.info(
            "Login monitor watching %d files: %s",
            len(self._watch_files),
            self._watch_files,
        )

    def poll(self):
        for path in self._watch_files:
            if not os.path.isfile(path):
                continue
            try:
                if path.endswith(("wtmp", "btmp")):
                    self._poll_binary_log(path)
                else:
                    self._poll_text_log(path)
            except PermissionError:
                logger.debug("Permission denied reading %s", path)
            except Exception as exc:
                logger.error("Error reading %s: %s", path, exc)

    # ──────────────────────── Text log parsing (auth.log / secure) ──────
    def _poll_text_log(self, path: str):
        current_size = os.path.getsize(path)
        offset = self._file_offsets.get(path, 0)

        if current_size < offset:
            # Log was rotated — start from beginning
            offset = 0

        if current_size == offset:
            return

        with open(path, "r", errors="replace") as fh:
            fh.seek(offset)
            new_lines = fh.readlines()
            self._file_offsets[path] = fh.tell()

        for line in new_lines:
            self._parse_auth_line(line.strip())

    def _parse_auth_line(self, line: str):
        # SSH accepted
        m = RE_SSHD_ACCEPTED.search(line)
        if m:
            method, user, ip, port = m.groups()
            self._on_login_success(user, ip, method, "ssh")
            return

        # SSH failed
        m = RE_SSHD_FAILED.search(line)
        if m:
            method, user, ip, port = m.groups()
            self._on_login_failed(user, ip, method, "ssh")
            return

        # Generic failed password
        m = RE_FAILED_PASSWORD.search(line)
        if m:
            user, ip = m.groups()
            self._on_login_failed(user, ip, "password", "pam")
            return

        # sudo
        m = RE_SUDO.search(line)
        if m:
            user, command = m.groups()
            self._on_sudo(user, command.strip())
            return

        # su
        m = RE_SU.search(line)
        if m:
            target_user, source_user = m.groups()
            self._on_su(source_user, target_user, "Successful" in line)
            return

        # PAM session opened
        m = RE_SESSION_OPENED.search(line)
        if m:
            user = m.group(1)
            logger.info("SESSION_OPENED user=%s", user)
            self._alert.fire(
                monitor="login",
                event_type="SESSION_OPENED",
                message=f"Session opened for {user}",
                severity=SEVERITY_INFO,
                details={"user": user},
            )
            return

        # PAM session closed
        m = RE_SESSION_CLOSED.search(line)
        if m:
            user = m.group(1)
            logger.info("SESSION_CLOSED user=%s", user)

    # ──────────────────────── Binary log parsing (wtmp/btmp) ───────────
    def _poll_binary_log(self, path: str):
        current_size = os.path.getsize(path)
        offset = self._file_offsets.get(path, 0)

        if current_size < offset:
            offset = 0
        if current_size - offset < UTMP_SIZE:
            return

        try:
            with open(path, "rb") as fh:
                fh.seek(offset)
                while True:
                    data = fh.read(UTMP_SIZE)
                    if len(data) < UTMP_SIZE:
                        break
                    self._parse_utmp_record(data, source=path)
                self._file_offsets[path] = fh.tell()
        except Exception as exc:
            logger.error("Error parsing %s: %s", path, exc)

    def _parse_utmp_record(self, data: bytes, source: str):
        try:
            fields = UTMP_STRUCT.unpack(data)
            ut_type = fields[0]
            ut_user = fields[4].split(b"\x00")[0].decode("utf-8", errors="replace")
            ut_host = fields[5].split(b"\x00")[0].decode("utf-8", errors="replace")
            ut_tv_sec = fields[9]
            ts = datetime.fromtimestamp(ut_tv_sec, tz=timezone.utc).isoformat()

            # ut_type: 7 = USER_PROCESS (login), 8 = DEAD_PROCESS (logout)
            if ut_type == 7:
                detail = {
                    "user": ut_user,
                    "host": ut_host,
                    "time": ts,
                    "source": source,
                }
                if "btmp" in source:
                    self._on_login_failed(ut_user, ut_host, "unknown", source)
                else:
                    logger.info("WTMP LOGIN: user=%s host=%s at %s", ut_user, ut_host, ts)
                    self._alert.fire(
                        monitor="login",
                        event_type="WTMP_LOGIN",
                        message=f"Login recorded: {ut_user} from {ut_host}",
                        severity=SEVERITY_INFO,
                        details=detail,
                    )

        except Exception:
            pass  # malformed record, skip

    # ──────────────────────── Event handlers ────────────────────────────
    def _on_login_success(self, user: str, ip: str, method: str, service: str):
        logger.info(
            "LOGIN_SUCCESS user=%s ip=%s method=%s service=%s",
            user, ip, method, service,
        )
        severity = SEVERITY_INFO
        if user == "root" and self._mon_cfg.get("alert_on_root_login", True):
            severity = SEVERITY_HIGH

        self._alert.fire(
            monitor="login",
            event_type="LOGIN_SUCCESS",
            message=f"Successful {service} login: {user} from {ip} ({method})",
            severity=severity,
            details={"user": user, "ip": ip, "method": method, "service": service},
        )

    def _on_login_failed(self, user: str, ip: str, method: str, service: str):
        logger.info(
            "LOGIN_FAILED user=%s ip=%s method=%s service=%s",
            user, ip, method, service,
        )

        if self._mon_cfg.get("alert_on_failed_login", True):
            self._alert.fire(
                monitor="login",
                event_type="LOGIN_FAILED",
                message=f"Failed {service} login: {user} from {ip} ({method})",
                severity=SEVERITY_MEDIUM,
                details={"user": user, "ip": ip, "method": method, "service": service},
            )

        # Brute-force detection
        now = time.time()
        self._failed_attempts[ip].append(now)
        # Prune old entries
        self._failed_attempts[ip] = [
            t for t in self._failed_attempts[ip] if now - t < self._fail_window
        ]
        if len(self._failed_attempts[ip]) >= self._fail_threshold:
            self._alert.fire(
                monitor="login",
                event_type="BRUTE_FORCE_DETECTED",
                message=(
                    f"Possible brute-force from {ip}: "
                    f"{len(self._failed_attempts[ip])} failures in "
                    f"{self._fail_window}s"
                ),
                severity=SEVERITY_CRITICAL,
                details={
                    "ip": ip,
                    "count": len(self._failed_attempts[ip]),
                    "window_sec": self._fail_window,
                    "last_user": user,
                },
            )
            # Reset to avoid re-alerting every poll
            self._failed_attempts[ip] = []

    def _on_sudo(self, user: str, command: str):
        logger.info("SUDO user=%s command=%s", user, command)
        self._alert.fire(
            monitor="login",
            event_type="SUDO_COMMAND",
            message=f"sudo executed by {user}: {command}",
            severity=SEVERITY_MEDIUM,
            details={"user": user, "command": command},
        )

    def _on_su(self, source_user: str, target_user: str, success: bool):
        ev = "SU_SUCCESS" if success else "SU_FAILED"
        sev = SEVERITY_HIGH if target_user == "root" else SEVERITY_MEDIUM
        logger.info("%s: %s -> %s", ev, source_user, target_user)
        self._alert.fire(
            monitor="login",
            event_type=ev,
            message=f"su {'success' if success else 'failed'}: {source_user} -> {target_user}",
            severity=sev,
            details={"source_user": source_user, "target_user": target_user, "success": success},
        )
