"""
LySec - Daemon Entry Point
Main daemon process that initializes all monitors and runs them
as a background service.

Usage:
    lysecd start [--config /path/to/config.yaml] [--foreground]
    lysecd stop
    lysecd status
"""

import argparse
import logging
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from lysec.config import load_config, DEFAULT_CONFIG_PATH
from lysec.forensic_logger import setup_logging, log_event
from lysec.alert_engine import AlertEngine, SEVERITY_INFO, SEVERITY_CRITICAL
from lysec.monitors.usb_monitor import USBMonitor
from lysec.monitors.login_monitor import LoginMonitor
from lysec.monitors.network_monitor import NetworkMonitor
from lysec.monitors.process_monitor import ProcessMonitor
from lysec.monitors.filesystem_monitor import FilesystemMonitor
from lysec.monitors.ports_monitor import PortsMonitor

logger = logging.getLogger("lysec.daemon")

MONITORS = {
    "usb": USBMonitor,
    "ports": PortsMonitor,
    "login": LoginMonitor,
    "network": NetworkMonitor,
    "process": ProcessMonitor,
    "filesystem": FilesystemMonitor,
}


class LySecDaemon:
    """
    Core daemon orchestrator.
    Starts all enabled monitors, handles signals, manages PID file.
    """

    def __init__(self, config: dict):
        self._config = config
        self._logger = None
        self._alert_engine = None
        self._monitors = []
        self._running = False
        self._pid_file = config["daemon"]["pid_file"]
        wd_cfg = config.get("daemon", {}).get("watchdog", {})
        self._heartbeat_enabled = bool(wd_cfg.get("enabled", True))
        self._heartbeat_socket_path = wd_cfg.get(
            "heartbeat_socket", "/var/run/lysec/lysec-heartbeat.sock"
        )
        self._heartbeat_interval_sec = float(wd_cfg.get("heartbeat_interval_sec", 2))
        self._heartbeat_thread: threading.Thread | None = None

    @staticmethod
    def _run_cmd_output(args: list[str]) -> str:
        try:
            out = subprocess.check_output(args, stderr=subprocess.DEVNULL, text=True)
            return out.strip()
        except Exception:
            return ""

    @staticmethod
    def _read_uptime_seconds() -> float:
        try:
            with open("/proc/uptime", "r", encoding="utf-8", errors="replace") as fh:
                return float(fh.read().split()[0])
        except Exception:
            return 0.0

    def _collect_startup_context(self) -> dict:
        """Collect best-effort boot/login stage context at daemon start."""
        dm_units = [
            "display-manager.service",
            "gdm.service",
            "gdm3.service",
            "lightdm.service",
            "sddm.service",
        ]
        dm_active = {}
        for unit in dm_units:
            status = self._run_cmd_output(["systemctl", "is-active", unit])
            if status:
                dm_active[unit] = status

        return {
            "uptime_sec": round(self._read_uptime_seconds(), 3),
            "boot_monotonic_sec": round(time.monotonic(), 3),
            "default_target": self._run_cmd_output(["systemctl", "get-default"]),
            "display_manager_status": dm_active,
            "lysec_service_unit": self._run_cmd_output(["systemctl", "show", "-p", "Id", "--value", "lysec.service"]),
        }

    def start(self, foreground: bool = False):
        """Initialize and start the daemon."""
        # Daemonize unless running in foreground
        if not foreground:
            self._daemonize()

        self._write_pid()
        self._setup_signals()

        # Initialize logging and alert engine
        self._logger = setup_logging(self._config)
        self._alert_engine = AlertEngine(self._config)

        log_event(
            self._logger, logging.INFO,
            "LySec daemon starting",
            event_type="DAEMON_START",
            monitor="daemon",
        )

        self._alert_engine.fire(
            monitor="daemon",
            event_type="DAEMON_START",
            message="LySec forensic monitoring daemon started",
            severity=SEVERITY_INFO,
            details={
                "pid": os.getpid(),
                "config_monitors": list(
                    k for k, v in self._config.get("monitors", {}).items()
                    if v.get("enabled", False)
                ),
                "startup_context": self._collect_startup_context(),
            },
        )

        # Start enabled monitors
        monitor_cfg = self._config.get("monitors", {})
        for name, cls in MONITORS.items():
            if monitor_cfg.get(name, {}).get("enabled", False):
                try:
                    mon = cls(self._config, self._alert_engine)
                    mon.start()
                    self._monitors.append(mon)
                    logger.info("Monitor started: %s", name)
                except Exception as exc:
                    logger.error("Failed to start monitor %s: %s", name, exc)

        self._running = True

        if self._heartbeat_enabled:
            self._start_heartbeat()

        # Main loop — keep daemon alive
        logger.info("LySec daemon running (pid %d) — %d monitors active",
                     os.getpid(), len(self._monitors))
        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        """Gracefully stop all monitors and clean up."""
        logger.info("LySec daemon shutting down …")
        self._running = False

        for mon in self._monitors:
            try:
                mon.stop()
            except Exception as exc:
                logger.error("Error stopping %s: %s", mon.name, exc)

        if self._alert_engine:
            self._alert_engine.fire(
                monitor="daemon",
                event_type="DAEMON_STOP",
                message="LySec daemon stopped gracefully",
                severity=SEVERITY_INFO,
            )

        self._remove_pid()
        logger.info("LySec daemon stopped")

    def _start_heartbeat(self):
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            name="lysec-heartbeat",
            daemon=True,
        )
        self._heartbeat_thread.start()

    def _heartbeat_loop(self):
        while self._running:
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                payload = f"lysec:{os.getpid()}:{int(time.time())}".encode("utf-8")
                sock.sendto(payload, self._heartbeat_socket_path)
                sock.close()
            except Exception:
                pass
            time.sleep(self._heartbeat_interval_sec)

    # ──────────────────────── Internals ─────────────────────────────────

    def _daemonize(self):
        """Classic double-fork to become a daemon."""
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            sys.stderr.write(f"Fork #1 failed: {e}\n")
            sys.exit(1)

        os.chdir("/")
        os.setsid()
        os.umask(0)

        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            sys.stderr.write(f"Fork #2 failed: {e}\n")
            sys.exit(1)

        # Redirect stdio to /dev/null
        sys.stdout.flush()
        sys.stderr.flush()
        devnull = open(os.devnull, "r+b")
        os.dup2(devnull.fileno(), sys.stdin.fileno())
        os.dup2(devnull.fileno(), sys.stdout.fileno())
        os.dup2(devnull.fileno(), sys.stderr.fileno())

    def _write_pid(self):
        pid_dir = os.path.dirname(self._pid_file)
        Path(pid_dir).mkdir(parents=True, exist_ok=True)
        with open(self._pid_file, "w") as f:
            f.write(str(os.getpid()))

    def _remove_pid(self):
        try:
            os.unlink(self._pid_file)
        except OSError:
            pass

    def _setup_signals(self):
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGHUP, self._handle_sighup)

    def _handle_signal(self, signum, frame):
        logger.info("Received signal %d — initiating shutdown", signum)
        self._running = False

    def _handle_sighup(self, signum, frame):
        """Reload configuration on SIGHUP."""
        logger.info("Received SIGHUP — reloading configuration")
        try:
            self._config = load_config()
            self._alert_engine = AlertEngine(self._config)
            logger.info("Configuration reloaded successfully")
        except Exception as exc:
            logger.error("Config reload failed: %s", exc)


def get_running_pid(pid_file: str) -> int | None:
    """Return PID from pidfile if process is still running."""
    if not os.path.isfile(pid_file):
        return None
    try:
        with open(pid_file) as f:
            pid = int(f.read().strip())
        # Check if process exists
        os.kill(pid, 0)
        return pid
    except (ValueError, OSError):
        return None


def main():
    parser = argparse.ArgumentParser(
        description="LySec - Linux Forensics Monitoring Daemon"
    )
    parser.add_argument(
        "action",
        choices=["start", "stop", "status", "restart"],
        help="Daemon action",
    )
    parser.add_argument(
        "--config", "-c",
        default=DEFAULT_CONFIG_PATH,
        help="Path to configuration file",
    )
    parser.add_argument(
        "--foreground", "-f",
        action="store_true",
        help="Run in foreground (don't daemonize)",
    )

    args = parser.parse_args()
    config = load_config(args.config)
    pid_file = config["daemon"]["pid_file"]

    if args.action == "start":
        running = get_running_pid(pid_file)
        if running:
            print(f"LySec daemon already running (pid {running})")
            sys.exit(1)
        print("Starting LySec daemon …")
        daemon = LySecDaemon(config)
        daemon.start(foreground=args.foreground)

    elif args.action == "stop":
        pid = get_running_pid(pid_file)
        if pid is None:
            print("LySec daemon is not running")
            sys.exit(1)
        print(f"Stopping LySec daemon (pid {pid}) …")
        os.kill(pid, signal.SIGTERM)
        # Wait for it to die
        for _ in range(30):
            try:
                os.kill(pid, 0)
                time.sleep(0.5)
            except OSError:
                break
        print("LySec daemon stopped")

    elif args.action == "restart":
        pid = get_running_pid(pid_file)
        if pid:
            print(f"Stopping LySec daemon (pid {pid}) …")
            os.kill(pid, signal.SIGTERM)
            for _ in range(30):
                try:
                    os.kill(pid, 0)
                    time.sleep(0.5)
                except OSError:
                    break
        print("Starting LySec daemon …")
        daemon = LySecDaemon(config)
        daemon.start(foreground=args.foreground)

    elif args.action == "status":
        pid = get_running_pid(pid_file)
        if pid:
            print(f"LySec daemon is running (pid {pid})")
        else:
            print("LySec daemon is not running")
            sys.exit(1)


if __name__ == "__main__":
    main()

