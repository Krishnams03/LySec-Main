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
import sys
import time
from pathlib import Path

from dftool.config import load_config, DEFAULT_CONFIG_PATH
from dftool.forensic_logger import setup_logging, log_event
from dftool.alert_engine import AlertEngine, SEVERITY_INFO, SEVERITY_CRITICAL
from dftool.monitors.usb_monitor import USBMonitor
from dftool.monitors.login_monitor import LoginMonitor
from dftool.monitors.network_monitor import NetworkMonitor
from dftool.monitors.process_monitor import ProcessMonitor
from dftool.monitors.filesystem_monitor import FilesystemMonitor

logger = logging.getLogger("lysec.daemon")

MONITORS = {
    "usb": USBMonitor,
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
