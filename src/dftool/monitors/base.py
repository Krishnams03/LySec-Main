"""
LySec - Base Monitor
Abstract base class that every monitor inherits from.
Provides the threading scaffold and common interface.
"""

import abc
import logging
import threading
import time


class BaseMonitor(abc.ABC):
    """
    Every monitor runs in its own daemon thread.
    Subclasses implement `setup()` and `poll()`.
    """

    name: str = "base"

    def __init__(self, config: dict, alert_engine):
        self._config = config
        self._alert = alert_engine
        self._logger = logging.getLogger(f"lysec.monitor.{self.name}")
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ── Lifecycle ──

    def start(self):
        """Spawn the monitor thread."""
        self._logger.info("Starting monitor: %s", self.name)
        self._thread = threading.Thread(
            target=self._run, name=f"lysec-{self.name}", daemon=True
        )
        self._thread.start()

    def stop(self):
        """Signal the monitor to stop and join."""
        self._logger.info("Stopping monitor: %s", self.name)
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)

    # ── Internal loop ──

    def _run(self):
        try:
            self.setup()
        except Exception as exc:
            self._logger.exception("Setup failed for %s: %s", self.name, exc)
            return

        poll_interval = self._get_poll_interval()

        while not self._stop_event.is_set():
            try:
                self.poll()
            except Exception as exc:
                self._logger.exception("Poll error in %s: %s", self.name, exc)
            self._stop_event.wait(poll_interval)

        try:
            self.teardown()
        except Exception:
            pass

    def _get_poll_interval(self) -> float:
        """Return poll interval from monitor-specific config."""
        mon_cfg = self._config.get("monitors", {}).get(self.name, {})
        return float(mon_cfg.get("poll_interval", 5))

    # ── Subclass hooks ──

    def setup(self):
        """Called once before the polling loop begins."""
        pass

    @abc.abstractmethod
    def poll(self):
        """Called every poll_interval seconds.  Must not block long."""
        ...

    def teardown(self):
        """Called once after the polling loop ends."""
        pass
