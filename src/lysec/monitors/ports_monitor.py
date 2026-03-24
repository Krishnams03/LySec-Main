"""
LySec - Ports Monitor
Tracks dynamic hardware port activity after daemon startup.

Coverage (configurable subsystems):
    * usb
    * thunderbolt
    * net
    * block
    * sound
    * drm
    * pci

Uses pyudev for real-time add/remove/change events.
Falls back to sysfs snapshot-diff polling if pyudev is unavailable.
"""

import logging
import os
from typing import Any

from lysec.monitors.base import BaseMonitor
from lysec.alert_engine import SEVERITY_HIGH, SEVERITY_INFO, SEVERITY_MEDIUM

logger = logging.getLogger("lysec.monitor.ports")


DEFAULT_SUBSYSTEMS = [
    "usb",
    "thunderbolt",
    "net",
    "block",
    "sound",
    "drm",
    "pci",
]


SYSFS_ROOTS = {
    "usb": "/sys/bus/usb/devices",
    "thunderbolt": "/sys/bus/thunderbolt/devices",
    "net": "/sys/class/net",
    "block": "/sys/block",
    "sound": "/sys/class/sound",
    "drm": "/sys/class/drm",
    "pci": "/sys/bus/pci/devices",
}


class PortsMonitor(BaseMonitor):
    name = "ports"

    def __init__(self, config: dict, alert_engine):
        super().__init__(config, alert_engine)
        self._mon_cfg = config.get("monitors", {}).get("ports", {})
        self._subsystems = set(self._mon_cfg.get("subsystems", DEFAULT_SUBSYSTEMS))
        self._alert_on_change = bool(self._mon_cfg.get("alert_on_change", False))
        self._context = None
        self._udev_monitor = None
        self._sysfs_snapshot: dict[str, set[str]] = {}

    def setup(self):
        try:
            import pyudev

            self._context = pyudev.Context()
            self._udev_monitor = pyudev.Monitor.from_netlink(self._context)
            self._udev_monitor.start()
            logger.info(
                "Ports monitor using udev realtime mode for subsystems: %s",
                ", ".join(sorted(self._subsystems)),
            )
        except ImportError:
            logger.warning("pyudev not available - using sysfs polling fallback")
            self._take_sysfs_snapshot()
        except Exception as exc:
            logger.error("Ports monitor setup failed (%s) - using sysfs fallback", exc)
            self._take_sysfs_snapshot()

    def poll(self):
        if self._udev_monitor is not None:
            self._poll_udev_events()
        else:
            self._poll_sysfs_changes()

    def _poll_udev_events(self):
        while True:
            device = self._udev_monitor.poll(timeout=0)
            if device is None:
                break

            subsystem = getattr(device, "subsystem", None) or device.get("SUBSYSTEM", "")
            if subsystem not in self._subsystems:
                continue

            action = getattr(device, "action", None) or device.get("ACTION", "change")
            info = self._extract_udev_info(device, action)

            if action == "add":
                self._emit_add(info)
            elif action == "remove":
                self._emit_remove(info)
            elif action == "change" and self._alert_on_change:
                self._emit_change(info)

    def _extract_udev_info(self, device, action: str) -> dict[str, Any]:
        props = {}
        try:
            props = dict(device.properties)
        except Exception:
            props = {}

        return {
            "action": action,
            "subsystem": getattr(device, "subsystem", None) or props.get("SUBSYSTEM", ""),
            "devtype": getattr(device, "device_type", None) or props.get("DEVTYPE", ""),
            "sys_path": getattr(device, "sys_path", None) or props.get("DEVPATH", ""),
            "device_node": getattr(device, "device_node", None) or props.get("DEVNAME", ""),
            "driver": props.get("DRIVER", ""),
            "vendor_id": props.get("ID_VENDOR_ID", ""),
            "product_id": props.get("ID_MODEL_ID", ""),
            "vendor": props.get("ID_VENDOR_FROM_DATABASE", props.get("ID_VENDOR", "")),
            "model": props.get("ID_MODEL_FROM_DATABASE", props.get("ID_MODEL", "")),
            "serial": props.get("ID_SERIAL_SHORT", ""),
            "interface": props.get("INTERFACE", ""),
        }

    def _emit_add(self, info: dict):
        subsystem = info.get("subsystem", "unknown")
        msg = (
            f"Port device added: {subsystem} "
            f"{info.get('model') or info.get('device_node') or info.get('sys_path', '')}"
        )
        sev = SEVERITY_HIGH if subsystem in {"usb", "thunderbolt", "pci"} else SEVERITY_MEDIUM
        self._alert.fire(
            monitor="ports",
            event_type="PORT_DEVICE_ADDED",
            message=msg,
            severity=sev,
            details=info,
        )

    def _emit_remove(self, info: dict):
        subsystem = info.get("subsystem", "unknown")
        msg = (
            f"Port device removed: {subsystem} "
            f"{info.get('model') or info.get('device_node') or info.get('sys_path', '')}"
        )
        self._alert.fire(
            monitor="ports",
            event_type="PORT_DEVICE_REMOVED",
            message=msg,
            severity=SEVERITY_INFO,
            details=info,
        )

    def _emit_change(self, info: dict):
        subsystem = info.get("subsystem", "unknown")
        msg = (
            f"Port device changed: {subsystem} "
            f"{info.get('model') or info.get('device_node') or info.get('sys_path', '')}"
        )
        self._alert.fire(
            monitor="ports",
            event_type="PORT_DEVICE_CHANGED",
            message=msg,
            severity=SEVERITY_INFO,
            details=info,
        )

    def _take_sysfs_snapshot(self):
        self._sysfs_snapshot = {}
        for subsystem in self._subsystems:
            self._sysfs_snapshot[subsystem] = self._list_sysfs_entries(subsystem)

    def _poll_sysfs_changes(self):
        for subsystem in self._subsystems:
            prev = self._sysfs_snapshot.get(subsystem, set())
            curr = self._list_sysfs_entries(subsystem)

            for entry in curr - prev:
                self._emit_add(
                    {
                        "action": "add",
                        "subsystem": subsystem,
                        "sys_path": entry,
                    }
                )

            for entry in prev - curr:
                self._emit_remove(
                    {
                        "action": "remove",
                        "subsystem": subsystem,
                        "sys_path": entry,
                    }
                )

            self._sysfs_snapshot[subsystem] = curr

    @staticmethod
    def _list_sysfs_entries(subsystem: str) -> set[str]:
        root = SYSFS_ROOTS.get(subsystem)
        if not root or not os.path.isdir(root):
            return set()

        entries: set[str] = set()
        try:
            for name in os.listdir(root):
                full = os.path.join(root, name)
                entries.add(full)
        except Exception:
            return set()
        return entries
