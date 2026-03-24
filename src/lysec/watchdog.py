"""
LySec - Watchdog Daemon
Monitors LySec primary daemon liveness using PID + Unix socket heartbeat.
If primary is down or heartbeat stalls, emits a high-severity alert and
restarts the primary service.
"""

import argparse
import logging
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from lysec.alert_engine import AlertEngine, SEVERITY_CRITICAL, SEVERITY_INFO
from lysec.config import DEFAULT_CONFIG_PATH, load_config
from lysec.forensic_logger import log_event, setup_logging

logger = logging.getLogger("lysec.watchdog")


class WatchdogDaemon:
    def __init__(self, config: dict):
        daemon_cfg = config.get("daemon", {})
        wd_cfg = daemon_cfg.get("watchdog", {})

        self._config = config
        self._running = False

        self._primary_pid_file = daemon_cfg.get("pid_file", "/var/run/lysec/lysecd.pid")
        self._watchdog_pid_file = wd_cfg.get("pid_file", "/var/run/lysec/lysec-watchdog.pid")
        self._heartbeat_socket_path = wd_cfg.get("heartbeat_socket", "/var/run/lysec/lysec-heartbeat.sock")
        self._heartbeat_timeout_sec = float(wd_cfg.get("heartbeat_timeout_sec", 8))
        self._restart_cooldown_sec = float(wd_cfg.get("restart_cooldown_sec", 20))
        self._service_name = wd_cfg.get("service_name", "lysec.service")

        self._last_heartbeat = 0.0
        self._last_restart = 0.0
        self._logger = None
        self._alert = None
        self._sock = None

    def start(self, foreground: bool = False):
        if not foreground:
            self._daemonize()

        self._write_pid()
        self._setup_signals()

        self._logger = setup_logging(self._config)
        self._alert = AlertEngine(self._config)

        self._bind_heartbeat_socket()
        self._last_heartbeat = time.time()
        self._running = True

        log_event(
            self._logger,
            logging.INFO,
            "LySec watchdog started",
            event_type="WATCHDOG_START",
            monitor="watchdog",
            details={
                "primary_pid_file": self._primary_pid_file,
                "heartbeat_socket": self._heartbeat_socket_path,
            },
        )
        self._alert.fire(
            monitor="watchdog",
            event_type="WATCHDOG_START",
            message="LySec watchdog daemon started",
            severity=SEVERITY_INFO,
            details={
                "primary_pid_file": self._primary_pid_file,
                "heartbeat_socket": self._heartbeat_socket_path,
            },
        )

        while self._running:
            self._poll_heartbeat()
            self._check_primary_health()

    def stop(self):
        self._running = False
        if self._alert:
            self._alert.fire(
                monitor="watchdog",
                event_type="WATCHDOG_STOP",
                message="LySec watchdog daemon stopped",
                severity=SEVERITY_INFO,
            )
        self._cleanup_socket()
        self._remove_pid()

    def _poll_heartbeat(self):
        if not self._sock:
            time.sleep(1)
            return

        self._sock.settimeout(1.0)
        try:
            payload = self._sock.recv(1024)
            if payload:
                self._last_heartbeat = time.time()
        except socket.timeout:
            pass
        except Exception:
            pass

    def _check_primary_health(self):
        now = time.time()
        pid_ok = self._is_primary_alive()
        heartbeat_ok = (now - self._last_heartbeat) <= self._heartbeat_timeout_sec

        if pid_ok and heartbeat_ok:
            return

        if (now - self._last_restart) < self._restart_cooldown_sec:
            return

        reason = []
        if not pid_ok:
            reason.append("primary_pid_missing_or_dead")
        if not heartbeat_ok:
            reason.append("heartbeat_timeout")

        self._alert.fire(
            monitor="watchdog",
            event_type="WATCHDOG_PRIMARY_DOWN",
            message="Primary LySec daemon appears down or unresponsive",
            severity=SEVERITY_CRITICAL,
            details={
                "reason": reason,
                "heartbeat_age_sec": round(now - self._last_heartbeat, 2),
                "primary_pid_file": self._primary_pid_file,
            },
        )

        restarted = self._restart_primary_service()
        self._last_restart = now

        self._alert.fire(
            monitor="watchdog",
            event_type="WATCHDOG_RESTART_ACTION",
            message=(
                "Watchdog restart action "
                + ("succeeded" if restarted else "failed")
            ),
            severity=SEVERITY_CRITICAL if not restarted else SEVERITY_INFO,
            details={
                "service": self._service_name,
                "result": "ok" if restarted else "error",
            },
        )

    def _restart_primary_service(self) -> bool:
        try:
            cp = subprocess.run(
                ["systemctl", "restart", self._service_name],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
            return cp.returncode == 0
        except Exception:
            return False

    def _is_primary_alive(self) -> bool:
        try:
            if not os.path.isfile(self._primary_pid_file):
                return False
            with open(self._primary_pid_file, "r", encoding="utf-8") as fh:
                pid = int(fh.read().strip())
            os.kill(pid, 0)
            return True
        except Exception:
            return False

    def _bind_heartbeat_socket(self):
        sock_dir = os.path.dirname(self._heartbeat_socket_path)
        Path(sock_dir).mkdir(parents=True, exist_ok=True)

        self._cleanup_socket()

        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self._sock.bind(self._heartbeat_socket_path)
        os.chmod(self._heartbeat_socket_path, 0o660)

    def _cleanup_socket(self):
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        self._sock = None
        try:
            if os.path.exists(self._heartbeat_socket_path):
                os.unlink(self._heartbeat_socket_path)
        except Exception:
            pass

    def _daemonize(self):
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as exc:
            sys.stderr.write(f"Fork #1 failed: {exc}\n")
            sys.exit(1)

        os.chdir("/")
        os.setsid()
        os.umask(0)

        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as exc:
            sys.stderr.write(f"Fork #2 failed: {exc}\n")
            sys.exit(1)

        sys.stdout.flush()
        sys.stderr.flush()
        devnull = open(os.devnull, "r+b")
        os.dup2(devnull.fileno(), sys.stdin.fileno())
        os.dup2(devnull.fileno(), sys.stdout.fileno())
        os.dup2(devnull.fileno(), sys.stderr.fileno())

    def _setup_signals(self):
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

    def _handle_signal(self, signum, frame):
        logger.info("Watchdog received signal %d", signum)
        self._running = False

    def _write_pid(self):
        pid_dir = os.path.dirname(self._watchdog_pid_file)
        Path(pid_dir).mkdir(parents=True, exist_ok=True)
        with open(self._watchdog_pid_file, "w", encoding="utf-8") as fh:
            fh.write(str(os.getpid()))

    def _remove_pid(self):
        try:
            os.unlink(self._watchdog_pid_file)
        except OSError:
            pass


def get_running_pid(pid_file: str) -> int | None:
    if not os.path.isfile(pid_file):
        return None
    try:
        with open(pid_file, "r", encoding="utf-8") as fh:
            pid = int(fh.read().strip())
        os.kill(pid, 0)
        return pid
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(description="LySec watchdog daemon")
    parser.add_argument("action", choices=["start", "stop", "status", "restart"])
    parser.add_argument("--config", "-c", default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--foreground", "-f", action="store_true")
    args = parser.parse_args()

    config = load_config(args.config)
    wd_cfg = config.get("daemon", {}).get("watchdog", {})
    pid_file = wd_cfg.get("pid_file", "/var/run/lysec/lysec-watchdog.pid")

    if args.action == "start":
        pid = get_running_pid(pid_file)
        if pid:
            print(f"LySec watchdog already running (pid {pid})")
            sys.exit(1)
        daemon = WatchdogDaemon(config)
        daemon.start(foreground=args.foreground)
        return

    if args.action == "status":
        pid = get_running_pid(pid_file)
        if pid:
            print(f"LySec watchdog is running (pid {pid})")
        else:
            print("LySec watchdog is not running")
            sys.exit(1)
        return

    pid = get_running_pid(pid_file)
    if not pid:
        print("LySec watchdog is not running")
        if args.action == "stop":
            sys.exit(1)

    if args.action in ("stop", "restart") and pid:
        os.kill(pid, signal.SIGTERM)
        for _ in range(30):
            try:
                os.kill(pid, 0)
                time.sleep(0.5)
            except OSError:
                break

    if args.action == "restart":
        daemon = WatchdogDaemon(config)
        daemon.start(foreground=args.foreground)


if __name__ == "__main__":
    main()
