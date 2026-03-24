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
import socket
import struct
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from lysec.monitors.base import BaseMonitor
from lysec.monitors.process_ebpf import EbpfExecAdapter
from lysec.alert_engine import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_MEDIUM,
)

logger = logging.getLogger("lysec.monitor.process")


# Process connector netlink constants (linux/connector.h + cn_proc.h)
_NETLINK_CONNECTOR = 11
_NLMSG_DONE = 0x3
_CN_IDX_PROC = 0x1
_CN_VAL_PROC = 0x1
_PROC_CN_MCAST_LISTEN = 1

_PROC_EVENT_FORK = 0x00000001
_PROC_EVENT_EXEC = 0x00000002
_PROC_EVENT_EXIT = 0x80000000


class ProcessMonitor(BaseMonitor):
    name = "process"

    def __init__(self, config: dict, alert_engine):
        super().__init__(config, alert_engine)
        self._mon_cfg = config.get("monitors", {}).get("process", {})
        self._suspicious: set[str] = set(
            self._mon_cfg.get("suspicious_names", [])
        )
        self._alert_on_new_process = bool(self._mon_cfg.get("alert_on_new_process", True))
        self._alert_on_deleted_exe = bool(self._mon_cfg.get("alert_on_deleted_exe", True))
        self._alert_on_masquerade = bool(self._mon_cfg.get("alert_on_masquerade", True))
        self._alert_on_suspicious_tree = bool(self._mon_cfg.get("alert_on_suspicious_tree", True))
        self._management_parents = {
            str(x).lower()
            for x in self._mon_cfg.get(
                "management_parent_names",
                ["nginx", "apache2", "httpd", "php-fpm", "uwsgi", "gunicorn"],
            )
        }
        self._shell_children = {
            str(x).lower()
            for x in self._mon_cfg.get(
                "shell_child_names",
                ["sh", "bash", "zsh", "dash", "ksh"],
            )
        }
        self._env_keys = [
            str(x)
            for x in self._mon_cfg.get(
                "env_keys",
                ["LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PATH", "HOME", "USER"],
            )
        ]
        self._fork_burst_window_sec = float(self._mon_cfg.get("fork_burst_window_sec", 1.0))
        self._fork_burst_threshold = int(self._mon_cfg.get("fork_burst_threshold", 120))
        self._rare_process_window_sec = float(self._mon_cfg.get("rare_process_window_sec", 1.0))
        self._rare_process_threshold = int(self._mon_cfg.get("rare_process_threshold", 200))
        self._event_source = str(self._mon_cfg.get("event_source", "auto")).strip().lower()
        self._use_proc_connector = bool(self._mon_cfg.get("use_proc_connector", True))
        self._use_ebpf = bool(self._mon_cfg.get("use_ebpf", False))
        self._ebpf_strict = bool(self._mon_cfg.get("ebpf_strict", False))
        self._alert_on_shortlived_exec = bool(self._mon_cfg.get("alert_on_shortlived_exec", True))
        self._spawn_history_by_parent: dict[int, deque[float]] = defaultdict(deque)
        self._spawn_history_by_name: dict[str, deque[float]] = defaultdict(deque)
        self._proc_sock: socket.socket | None = None
        self._ebpf_adapter: EbpfExecAdapter | None = None
        self._ebpf_active = False
        self._degraded_source_alerted = False
        self._active_event_source = "poll"
        # pid -> snapshot
        self._known_procs: dict[int, dict] = {}
        self._first_run = True

    def setup(self):
        if not HAS_PSUTIL:
            logger.error("psutil required for process monitoring")
            return
        self._snapshot()
        self._active_event_source = self._select_event_source()
        logger.info(
            "Process monitor initialised (%s source) — %d running processes",
            self._active_event_source,
            len(self._known_procs),
        )

    def poll(self):
        if not HAS_PSUTIL:
            return

        current: dict[int, dict] = {}
        for proc in psutil.process_iter(
            ["pid", "name", "username", "cmdline", "exe",
               "ppid", "create_time", "uids", "gids", "cwd", "status"]
        ):
            try:
                info = proc.info
                pid = info["pid"]
                current[pid] = info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if self._active_event_source == "proc_connector":
            handled_pids = self._handle_proc_connector_events(current)
        elif self._active_event_source == "ebpf":
            handled_pids = self._handle_ebpf_events(current)
        else:
            handled_pids = set()

        if self._first_run:
            self._known_procs = current
            self._first_run = False
            return

        current_pids = set(current.keys())
        known_pids = set(self._known_procs.keys())

        # ── New processes ──
        for pid in current_pids - known_pids:
            if pid in handled_pids:
                continue
            info = current[pid]
            self._on_new_process(info)

        # ── Examine still-running processes for changes ──
        for pid in current_pids & known_pids:
            old = self._known_procs[pid]
            new = current[pid]
            # PID reuse safety: same PID but different start time means new process lineage.
            if old.get("create_time") != new.get("create_time"):
                self._on_new_process(new)
            else:
                self._check_priv_change(old, new)

        self._known_procs = current

    def teardown(self):
        if self._ebpf_adapter:
            try:
                self._ebpf_adapter.stop()
            except Exception:
                pass
            self._ebpf_adapter = None
        if self._proc_sock:
            try:
                self._proc_sock.close()
            except OSError:
                pass
            self._proc_sock = None

    def _select_event_source(self) -> str:
        source = self._event_source
        if source not in {"auto", "poll", "proc_connector", "ebpf"}:
            logger.warning("Unknown process event_source '%s', defaulting to auto", source)
            source = "auto"

        if source == "poll":
            return "poll"

        if source == "proc_connector":
            if self._setup_proc_connector():
                return "proc_connector"
            self._emit_source_degraded(
                requested="proc_connector",
                active="poll",
                reason="proc connector unavailable",
            )
            return "poll"

        if source == "ebpf":
            if self._setup_ebpf():
                return "ebpf"
            if self._ebpf_strict:
                logger.error("eBPF strict mode enabled and source unavailable; poll fallback disabled")
                return "poll"
            if self._use_proc_connector and self._setup_proc_connector():
                self._emit_source_degraded(
                    requested="ebpf",
                    active="proc_connector",
                    reason="eBPF unavailable",
                )
                return "proc_connector"
            self._emit_source_degraded(
                requested="ebpf",
                active="poll",
                reason="eBPF and proc connector unavailable",
            )
            return "poll"

        # auto mode
        if self._use_ebpf and self._setup_ebpf():
            return "ebpf"
        if self._use_proc_connector and self._setup_proc_connector():
            return "proc_connector"
        if self._use_ebpf:
            self._emit_source_degraded(
                requested="ebpf",
                active="poll",
                reason="eBPF unavailable in auto mode",
            )
        return "poll"

    def _emit_source_degraded(self, requested: str, active: str, reason: str):
        if self._degraded_source_alerted:
            return
        self._degraded_source_alerted = True
        self._alert.fire(
            monitor="process",
            event_type="PROCESS_EVENT_SOURCE_DEGRADED",
            message=(
                f"Process event source degraded from {requested} to {active}: {reason}"
            ),
            severity=SEVERITY_MEDIUM,
            details={
                "requested_source": requested,
                "active_source": active,
                "reason": reason,
            },
        )

    # ──────────────────────── Event handlers ────────────────────────────

    def _on_new_process(self, info: dict):
        name = info.get("name", "")
        cmdline = " ".join(info.get("cmdline") or [])
        user = info.get("username", "?")
        pid = info.get("pid")
        exe = info.get("exe", "")
        ppid = info.get("ppid")
        comm = self._read_comm(pid)
        cwd = info.get("cwd") or self._read_cwd(pid)
        env_hints = self._read_env_hints(pid)
        lineage = self._build_lineage(ppid)
        uids = info.get("uids")
        gids = info.get("gids")

        base_details = {
            "pid": pid,
            "name": name,
            "comm": comm,
            "exe": exe,
            "cmdline": cmdline,
            "cwd": cwd,
            "env_hints": env_hints,
            "user": user,
            "ppid": ppid,
            "uid": getattr(uids, "real", None) if uids else None,
            "euid": getattr(uids, "effective", None) if uids else None,
            "gid": getattr(gids, "real", None) if gids else None,
            "egid": getattr(gids, "effective", None) if gids else None,
            "create_time": info.get("create_time"),
            "lineage": lineage,
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

        self._record_spawn(ppid, name)
        self._check_spawn_bursts(ppid, name, base_details)

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

        if self._alert_on_deleted_exe and self._is_deleted_exe(pid, exe):
            self._alert.fire(
                monitor="process",
                event_type="PROCESS_DELETED_ON_DISK",
                message=f"Process executable appears deleted on disk: {name} (pid {pid})",
                severity=SEVERITY_CRITICAL,
                details=base_details,
            )

        if self._alert_on_masquerade and self._is_masquerade(comm, cmdline):
            self._alert.fire(
                monitor="process",
                event_type="PROCESS_MASQUERADE",
                message=f"Possible command line masquerading: {name} (pid {pid})",
                severity=SEVERITY_HIGH,
                details=base_details,
            )

        if self._alert_on_suspicious_tree and self._is_suspicious_tree(ppid, name):
            parent = self._known_procs.get(ppid, {})
            self._alert.fire(
                monitor="process",
                event_type="SUSPICIOUS_PROCESS_TREE",
                message=(
                    f"Management process {parent.get('name', '?')} (pid {ppid}) "
                    f"spawned shell {name} (pid {pid})"
                ),
                severity=SEVERITY_CRITICAL,
                details={
                    **base_details,
                    "parent_name": parent.get("name"),
                    "parent_exe": parent.get("exe"),
                },
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
             "ppid", "create_time", "uids", "gids", "cwd", "status"]
        ):
            try:
                info = proc.info
                self._known_procs[info["pid"]] = info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _setup_proc_connector(self):
        """Subscribe to kernel process fork/exec/exit events for short-lived process visibility."""
        try:
            sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, _NETLINK_CONNECTOR)
            sock.bind((os.getpid(), _CN_IDX_PROC))
            sock.setblocking(False)

            # nlmsghdr + cn_msg + enum proc_cn_mcast_op
            payload = struct.pack("I", _PROC_CN_MCAST_LISTEN)
            cn_msg = struct.pack("IIIIHH", _CN_IDX_PROC, _CN_VAL_PROC, 0, 0, len(payload), 0)
            nl_len = 16 + len(cn_msg) + len(payload)
            nl_hdr = struct.pack("IHHII", nl_len, _NLMSG_DONE, 0, os.getpid(), 0)
            sock.send(nl_hdr + cn_msg + payload)

            self._proc_sock = sock
            logger.info("Process connector netlink enabled")
            return True
        except OSError as exc:
            self._proc_sock = None
            logger.warning("Process connector unavailable, poll-only mode: %s", exc)
            return False

    def _setup_ebpf(self) -> bool:
        """Set up eBPF event source for exec visibility."""
        if not self._use_ebpf and self._event_source != "ebpf":
            return False
        adapter = EbpfExecAdapter()
        if not adapter.start():
            self._ebpf_adapter = None
            self._ebpf_active = False
            return False
        self._ebpf_adapter = adapter
        self._ebpf_active = True
        logger.info("eBPF event source enabled")
        return True

    def _handle_ebpf_events(self, current: dict[int, dict]) -> set[int]:
        """Consume eBPF events; return pids handled in this poll cycle."""
        handled: set[int] = set()
        if not self._ebpf_adapter:
            return handled

        for ev in self._ebpf_adapter.poll_events():
            pid = int(ev.get("pid", 0) or 0)
            what = str(ev.get("what", "")).lower()
            if not pid or what != "exec":
                continue

            if pid in current and pid not in self._known_procs:
                self._on_new_process(current[pid])
                handled.add(pid)
                continue

            if self._alert_on_shortlived_exec and pid not in current:
                self._alert.fire(
                    monitor="process",
                    event_type="PROCESS_SHORTLIVED_EVENT",
                    message=(
                        f"Short-lived process {what} event observed for pid {pid} "
                        "before full snapshot capture"
                    ),
                    severity=SEVERITY_MEDIUM,
                    details={
                        "pid": pid,
                        "event": what,
                        "source": "ebpf",
                        "comm": ev.get("comm", ""),
                        "filename": ev.get("filename", ""),
                        "uid": ev.get("uid"),
                    },
                )

        return handled

    def _handle_proc_connector_events(self, current: dict[int, dict]) -> set[int]:
        """Consume process connector events; return pids handled in this poll cycle."""
        handled: set[int] = set()
        if not self._proc_sock:
            return handled

        while True:
            try:
                payload = self._proc_sock.recv(65535)
            except BlockingIOError:
                break
            except OSError:
                break

            for ev in self._parse_proc_connector_messages(payload):
                pid = int(ev.get("pid", 0) or 0)
                what = str(ev.get("what", "")).lower()
                if not pid:
                    continue

                if pid in current and pid not in self._known_procs and what in {"exec", "fork"}:
                    self._on_new_process(current[pid])
                    handled.add(pid)
                    continue

                # Short-lived process likely exited before polling snapshot.
                if self._alert_on_shortlived_exec and what in {"exec", "fork"} and pid not in current:
                    self._alert.fire(
                        monitor="process",
                        event_type="PROCESS_SHORTLIVED_EVENT",
                        message=(
                            f"Short-lived process {what} event observed for pid {pid} "
                            "before full snapshot capture"
                        ),
                        severity=SEVERITY_MEDIUM,
                        details={
                            "pid": pid,
                            "event": what,
                            "source": "proc_connector",
                        },
                    )
        return handled

    @staticmethod
    def _parse_proc_connector_messages(payload: bytes) -> list[dict[str, Any]]:
        """Best-effort parser for proc connector netlink payloads."""
        events: list[dict[str, Any]] = []
        offset = 0
        plen = len(payload)

        while offset + 16 <= plen:
            nl_len, _nl_type, _flags, _seq, _pid = struct.unpack("IHHII", payload[offset : offset + 16])
            if nl_len < 16:
                break
            msg_end = min(plen, offset + nl_len)
            body = payload[offset + 16 : msg_end]

            # cn_msg is 20 bytes; proc_event starts after it.
            if len(body) >= 20 + 16:
                proc_ev = body[20:]
                what, _cpu = struct.unpack("II", proc_ev[0:8])

                if what == _PROC_EVENT_EXEC and len(proc_ev) >= 24:
                    # exec_proc_event: process_pid, process_tgid
                    process_pid, _tgid = struct.unpack("II", proc_ev[16:24])
                    events.append({"what": "exec", "pid": process_pid})
                elif what == _PROC_EVENT_FORK and len(proc_ev) >= 32:
                    # fork_proc_event: parent_pid,parent_tgid,child_pid,child_tgid
                    _ppid, _ptgid, child_pid, _ctgid = struct.unpack("IIII", proc_ev[16:32])
                    events.append({"what": "fork", "pid": child_pid})
                elif what == _PROC_EVENT_EXIT and len(proc_ev) >= 24:
                    process_pid, _tgid = struct.unpack("II", proc_ev[16:24])
                    events.append({"what": "exit", "pid": process_pid})

            offset += (nl_len + 3) & ~3

        return events

    @staticmethod
    def _read_comm(pid: int | None) -> str:
        if not pid:
            return ""
        try:
            with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="replace") as fh:
                return fh.read().strip()
        except Exception:
            return ""

    @staticmethod
    def _read_cwd(pid: int | None) -> str:
        if not pid:
            return ""
        try:
            return os.readlink(f"/proc/{pid}/cwd")
        except Exception:
            return ""

    def _read_env_hints(self, pid: int | None) -> dict[str, str]:
        if not pid:
            return {}
        try:
            with open(f"/proc/{pid}/environ", "rb") as fh:
                raw = fh.read()
        except Exception:
            return {}

        out: dict[str, str] = {}
        for chunk in raw.split(b"\x00"):
            if b"=" not in chunk:
                continue
            key_b, val_b = chunk.split(b"=", 1)
            key = key_b.decode("utf-8", errors="replace")
            if key not in self._env_keys:
                continue
            out[key] = val_b.decode("utf-8", errors="replace")[:256]
        return out

    def _build_lineage(self, ppid: int | None, max_depth: int = 6) -> list[dict[str, Any]]:
        lineage: list[dict[str, Any]] = []
        current = ppid
        depth = 0
        while current and depth < max_depth:
            proc = self._known_procs.get(current)
            if not proc:
                break
            lineage.append(
                {
                    "pid": current,
                    "name": proc.get("name"),
                    "exe": proc.get("exe"),
                    "ppid": proc.get("ppid"),
                }
            )
            current = proc.get("ppid")
            depth += 1
        return lineage

    @staticmethod
    def _is_deleted_exe(pid: int | None, exe: str) -> bool:
        if exe and " (deleted)" in exe:
            return True
        if not pid:
            return False
        try:
            target = os.readlink(f"/proc/{pid}/exe")
            return " (deleted)" in target
        except Exception:
            return False

    @staticmethod
    def _is_masquerade(comm: str, cmdline: str) -> bool:
        c = str(comm or "").strip().lower()
        if not c:
            return False
        argv0 = str(cmdline or "").strip().split(" ", 1)[0].lower()
        if not argv0:
            return False
        basename = os.path.basename(argv0)
        if c.startswith("[") and c.endswith("]"):
            # Kernel-thread-like style from user process argv may indicate masquerade.
            return True
        return c not in basename and basename not in c

    def _is_suspicious_tree(self, ppid: int | None, child_name: str) -> bool:
        if not ppid:
            return False
        parent = self._known_procs.get(ppid)
        if not parent:
            return False
        parent_name = str(parent.get("name", "")).lower()
        child = str(child_name or "").lower()
        return parent_name in self._management_parents and child in self._shell_children

    def _record_spawn(self, ppid: int | None, child_name: str):
        now = time.time()
        if ppid:
            dq = self._spawn_history_by_parent[ppid]
            dq.append(now)
            self._prune_history(dq, now - self._fork_burst_window_sec)

        key = str(child_name or "").lower()
        if key:
            dq2 = self._spawn_history_by_name[key]
            dq2.append(now)
            self._prune_history(dq2, now - self._rare_process_window_sec)

    @staticmethod
    def _prune_history(dq: deque[float], cutoff: float):
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _check_spawn_bursts(self, ppid: int | None, child_name: str, base_details: dict[str, Any]):
        if ppid:
            parent_dq = self._spawn_history_by_parent.get(ppid)
            if parent_dq and len(parent_dq) >= self._fork_burst_threshold:
                self._alert.fire(
                    monitor="process",
                    event_type="PROCESS_FORK_BURST",
                    message=(
                        f"High fork/exec burst from parent pid {ppid}: "
                        f"{len(parent_dq)} spawns in {self._fork_burst_window_sec:.1f}s"
                    ),
                    severity=SEVERITY_HIGH,
                    details={
                        **base_details,
                        "burst_parent_pid": ppid,
                        "burst_count": len(parent_dq),
                        "burst_window_sec": self._fork_burst_window_sec,
                    },
                )

        key = str(child_name or "").lower()
        if key:
            name_dq = self._spawn_history_by_name.get(key)
            if name_dq and len(name_dq) >= self._rare_process_threshold:
                self._alert.fire(
                    monitor="process",
                    event_type="RARE_PROCESS_BURST",
                    message=(
                        f"Process {key} executed {len(name_dq)} times in "
                        f"{self._rare_process_window_sec:.1f}s"
                    ),
                    severity=SEVERITY_MEDIUM,
                    details={
                        **base_details,
                        "process_name": key,
                        "burst_count": len(name_dq),
                        "burst_window_sec": self._rare_process_window_sec,
                    },
                )

