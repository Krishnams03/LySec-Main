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
import subprocess
import struct
from typing import Any

from lysec.monitors.base import BaseMonitor
from lysec.alert_engine import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)

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
        usb_cfg = config.get("monitors", {}).get("usb", {})
        self._global_severity_policy = config.get("alerts", {}).get("severity_policy", {})
        self._subsystems = set(self._mon_cfg.get("subsystems", DEFAULT_SUBSYSTEMS))
        self._alert_on_change = bool(self._mon_cfg.get("alert_on_change", False))
        self._suppress_usb_if_usb_monitor_enabled = bool(
            self._mon_cfg.get("suppress_usb_if_usb_monitor_enabled", True)
        )
        self._usb_monitor_enabled = bool(usb_cfg.get("enabled", True))
        self._port_subsystem_severity = self._build_port_subsystem_severity_map()
        self._drm_suspicious_keywords = {
            str(x).strip().lower()
            for x in self._mon_cfg.get(
                "drm_suspicious_keywords",
                ["hid", "keyboard", "rubber", "ducky", "inject"],
            )
            if str(x).strip()
        }
        self._drm_allow_unknown_vendor = bool(
            self._mon_cfg.get("drm_allow_unknown_vendor", True)
        )
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
            if self._should_skip_subsystem(subsystem):
                continue
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

        info = {
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
            "serial_full": props.get("ID_SERIAL", ""),
            "manufacturer": props.get("ID_VENDOR", ""),
            "product": props.get("ID_MODEL", ""),
            "bus_num": props.get("BUSNUM", ""),
            "dev_num": props.get("DEVNUM", ""),
            "device_class": props.get("bDeviceClass", ""),
            "usb_interfaces_raw": props.get("ID_USB_INTERFACES", ""),
            "id_bus": props.get("ID_BUS", ""),
            "path_tag": props.get("ID_PATH_TAG", ""),
            "revision": props.get("ID_REVISION", ""),
            "interface": props.get("INTERFACE", ""),
        }
        if str(info.get("subsystem", "")).strip().lower() == "usb":
            self._enrich_usb_port_context(info)
        return info

    @staticmethod
    def _read_sysfs_attr(path: str, name: str) -> str:
        fp = os.path.join(path, name)
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read().strip()
        except Exception:
            return ""

    def _extract_sysfs_info(self, subsystem: str, entry: str, action: str) -> dict[str, Any]:
        info: dict[str, Any] = {
            "action": action,
            "subsystem": subsystem,
            "sys_path": entry,
        }

        if subsystem == "usb":
            info.update(
                {
                    "vendor_id": self._read_sysfs_attr(entry, "idVendor"),
                    "product_id": self._read_sysfs_attr(entry, "idProduct"),
                    "serial": self._read_sysfs_attr(entry, "serial"),
                    "serial_full": self._read_sysfs_attr(entry, "serial"),
                    "manufacturer": self._read_sysfs_attr(entry, "manufacturer"),
                    "vendor": self._read_sysfs_attr(entry, "manufacturer"),
                    "product": self._read_sysfs_attr(entry, "product"),
                    "model": self._read_sysfs_attr(entry, "product"),
                    "bus_num": self._read_sysfs_attr(entry, "busnum"),
                    "dev_num": self._read_sysfs_attr(entry, "devnum"),
                    "device_class": self._read_sysfs_attr(entry, "bDeviceClass"),
                    "revision": self._read_sysfs_attr(entry, "bcdDevice"),
                }
            )
            self._enrich_usb_port_context(info)

        return info

    @staticmethod
    def _build_usb_uid(info: dict[str, Any]) -> str:
        serial = str(info.get("serial", "")).strip() or str(info.get("serial_full", "")).strip()
        path_hint = str(info.get("path_tag", "")).strip() or str(info.get("sys_path", "")).strip()
        serial_or_path = serial or path_hint
        return f"{info.get('vendor_id', '')}:{info.get('product_id', '')}:{serial_or_path}"

    def _enrich_usb_port_context(self, info: dict[str, Any]):
        info["uid"] = self._build_usb_uid(info)
        bus = str(info.get("bus_num", "")).zfill(3) if str(info.get("bus_num", "")).strip() else ""
        dev = str(info.get("dev_num", "")).zfill(3) if str(info.get("dev_num", "")).strip() else ""
        vid = str(info.get("vendor_id", "")).strip()
        pid = str(info.get("product_id", "")).strip()
        name = str(info.get("model", "")).strip() or str(info.get("product", "")).strip()
        if bus and dev and (vid or pid):
            info["lsusb_like"] = f"Bus {bus} Device {dev}: ID {vid}:{pid} {name}".strip()

    def _emit_add(self, info: dict):
        subsystem = info.get("subsystem", "unknown")
        if subsystem == "thunderbolt":
            self._emit_thunderbolt_add(info)
            return
        if subsystem == "drm":
            self._emit_drm_add(info)
            return

        msg = (
            f"Port device added: {subsystem} "
            f"{info.get('model') or info.get('device_node') or info.get('sys_path', '')}"
        )
        sev = self._score_port_subsystem_severity(subsystem)
        self._alert.fire(
            monitor="ports",
            event_type="PORT_DEVICE_ADDED",
            message=msg,
            severity=sev,
            details=info,
        )

    def _emit_thunderbolt_add(self, info: dict):
        details = dict(info)
        details.update(self._thunderbolt_risk_context(details.get("sys_path", "")))
        locked = self._is_screen_locked()
        details["screen_locked"] = locked

        dma_enabled = bool(details.get("external_dma_protection_enabled", False))
        authorized = str(details.get("thunderbolt_authorized", "")).lower()
        security_level = str(details.get("thunderbolt_security_level", "")).lower()
        high_risk = (
            (not dma_enabled)
            or (authorized in ("0", "false", "no"))
            or (security_level in ("none", "dponly", "usbonly"))
            or locked
        )
        sev = (
            self._port_subsystem_severity.get("THUNDERBOLT_WHILE_LOCKED", SEVERITY_CRITICAL)
            if locked
            else self._port_subsystem_severity.get("THUNDERBOLT_NO_DMA_PROTECTION", SEVERITY_CRITICAL)
            if high_risk
            else self._score_port_subsystem_severity("thunderbolt")
        )
        msg = (
            "Thunderbolt device added"
            if not high_risk
            else "Thunderbolt device added with elevated DMA/trust risk"
        )
        details["thunderbolt_high_risk"] = high_risk
        if locked:
            details["thunderbolt_risk_reason"] = "screen_locked"
        self._alert.fire(
            monitor="ports",
            event_type="THUNDERBOLT_DEVICE_ADDED",
            message=msg,
            severity=sev,
            details=details,
        )

    @staticmethod
    def _is_screen_locked() -> bool:
        """Best-effort check using loginctl for active sessions with LockedHint=yes."""
        try:
            out = subprocess.check_output(
                ["loginctl", "list-sessions", "--no-legend"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
        except Exception:
            return False

        sessions = []
        for line in out.splitlines():
            parts = line.split()
            if parts:
                sessions.append(parts[0])

        for sid in sessions:
            try:
                prop = subprocess.check_output(
                    ["loginctl", "show-session", sid, "-p", "LockedHint", "--value"],
                    text=True,
                    stderr=subprocess.DEVNULL,
                    timeout=2,
                ).strip().lower()
            except Exception:
                continue
            if prop in ("yes", "true", "1"):
                return True
        return False

    def _emit_drm_add(self, info: dict):
        details = dict(info)
        connector = self._read_drm_connector_info(details.get("sys_path", ""))
        if connector:
            details.update(connector)
            suspicious = bool(details.get("edid_suspicious", False))
            sev = (
                self._port_subsystem_severity.get("DRM_SUSPICIOUS", SEVERITY_MEDIUM)
                if suspicious
                else self._score_port_subsystem_severity("drm")
            )
            self._alert.fire(
                monitor="ports",
                event_type="DISPLAY_CONNECTED",
                message=(
                    "Display connector connected"
                    if not suspicious
                    else "Suspicious display identity detected via EDID"
                ),
                severity=sev,
                details=details,
            )
            return

        msg = (
            "Port device added: drm "
            f"{info.get('device_node') or info.get('sys_path', '')}"
        )
        self._alert.fire(
            monitor="ports",
            event_type="PORT_DEVICE_ADDED",
            message=msg,
            severity=self._score_port_subsystem_severity("drm"),
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

    @staticmethod
    def _parse_severity(value: str, fallback: str) -> str:
        sev = str(value or "").upper().strip()
        mapping = {
            "CRITICAL": SEVERITY_CRITICAL,
            "HIGH": SEVERITY_HIGH,
            "MEDIUM": SEVERITY_MEDIUM,
            "LOW": SEVERITY_LOW,
            "INFO": SEVERITY_INFO,
        }
        return mapping.get(sev, fallback)

    def _build_port_subsystem_severity_map(self) -> dict[str, str]:
        base = {
            "USB": SEVERITY_HIGH,
            "THUNDERBOLT": SEVERITY_CRITICAL,
            "PCI": SEVERITY_HIGH,
            "NET": SEVERITY_HIGH,
            "BLOCK": SEVERITY_MEDIUM,
            "DRM": SEVERITY_LOW,
            "SOUND": SEVERITY_LOW,
            "THUNDERBOLT_NO_DMA_PROTECTION": SEVERITY_CRITICAL,
            "DRM_SUSPICIOUS": SEVERITY_MEDIUM,
        }
        cfg = self._global_severity_policy.get("port_subsystem_severity", {})
        for key, value in cfg.items():
            map_key = str(key).strip().upper()
            base[map_key] = self._parse_severity(value, fallback=base.get(map_key, SEVERITY_MEDIUM))
        return base

    def _score_port_subsystem_severity(self, subsystem: str) -> str:
        return self._port_subsystem_severity.get(str(subsystem or "unknown").upper(), SEVERITY_MEDIUM)

    def _thunderbolt_risk_context(self, sys_path: str) -> dict[str, Any]:
        external_dma_protection_enabled, markers, iommu_group_count = self._external_dma_protection_status()
        security_level = self._read_parent_attr(sys_path, "security")
        authorized = self._read_parent_attr(sys_path, "authorized")

        ctx: dict[str, Any] = {
            "external_dma_protection_enabled": external_dma_protection_enabled,
            "kernel_dma_markers": markers,
            "iommu_group_count": iommu_group_count,
            "thunderbolt_security_level": security_level,
            "thunderbolt_authorized": authorized,
        }
        ctx["dma_risk"] = "elevated" if not external_dma_protection_enabled else "reduced"
        ctx["recommendation"] = (
            "Enable IOMMU/Kernel DMA protection and restrict Thunderbolt authorization"
            if not external_dma_protection_enabled
            else "Keep DMA protection enabled and review Thunderbolt authorization policy"
        )
        return ctx

    @staticmethod
    def _external_dma_protection_status() -> tuple[bool, list[str], int]:
        groups_dir = "/sys/kernel/iommu_groups"
        iommu_group_count = 0
        try:
            if os.path.isdir(groups_dir):
                iommu_group_count = len(os.listdir(groups_dir))
        except Exception:
            pass

        markers_seen: list[str] = []
        try:
            with open("/proc/cmdline", "r", encoding="utf-8", errors="replace") as fh:
                cmdline = fh.read().lower()
            markers = [
                "intel_iommu=on",
                "amd_iommu=on",
                "iommu=on",
                "iommu=pt",
            ]
            markers_seen = [m for m in markers if m in cmdline]
        except Exception:
            markers_seen = []

        enabled = iommu_group_count > 0 or bool(markers_seen)
        return enabled, markers_seen, iommu_group_count

    @staticmethod
    def _read_parent_attr(sys_path: str, attr_name: str) -> str:
        path = os.path.realpath(sys_path) if sys_path else ""
        if not path:
            return ""

        for _ in range(5):
            fp = os.path.join(path, attr_name)
            try:
                if os.path.isfile(fp):
                    with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                        return fh.read().strip()
            except Exception:
                pass
            parent = os.path.dirname(path)
            if parent == path:
                break
            path = parent
        return ""

    def _read_drm_connector_info(self, sys_path: str) -> dict[str, Any]:
        connector_path = os.path.realpath(sys_path) if sys_path else ""
        if not connector_path or not os.path.exists(connector_path):
            return {}

        status_path = os.path.join(connector_path, "status")
        if not os.path.isfile(status_path):
            return {}

        try:
            with open(status_path, "r", encoding="utf-8", errors="replace") as fh:
                status = fh.read().strip().lower()
        except Exception:
            return {}

        info: dict[str, Any] = {
            "drm_connector": os.path.basename(connector_path),
            "drm_status": status,
        }
        if status != "connected":
            return info

        edid_path = os.path.join(connector_path, "edid")
        if not os.path.isfile(edid_path):
            return info

        try:
            with open(edid_path, "rb") as fh:
                edid = fh.read()
        except Exception:
            return info

        parsed = self._parse_edid_fields(edid)
        info.update(parsed)

        suspicious_reasons: list[str] = []
        if not info.get("edid_checksum_valid", True):
            suspicious_reasons.append("invalid_edid_checksum")
        if not info.get("edid_header_valid", True):
            suspicious_reasons.append("invalid_edid_header")

        vendor = str(info.get("edid_vendor", "")).strip()
        if not vendor and not self._drm_allow_unknown_vendor:
            suspicious_reasons.append("unknown_vendor")

        name_l = str(info.get("edid_monitor_name", "")).lower()
        serial_l = str(info.get("edid_serial", "")).lower()
        keyword_hit = any(k in name_l or k in serial_l for k in self._drm_suspicious_keywords)
        if keyword_hit:
            suspicious_reasons.append("suspicious_keyword")

        suspicious = bool(suspicious_reasons)
        info["edid_suspicious"] = suspicious
        if suspicious:
            info["edid_suspicious_reasons"] = suspicious_reasons
        return info

    @staticmethod
    def _parse_edid_fields(edid: bytes) -> dict[str, Any]:
        if len(edid) < 128:
            return {
                "edid_size": len(edid),
                "edid_header_valid": False,
                "edid_checksum_valid": False,
            }

        monitor_name = ""
        serial_text = ""
        base = edid[:128]
        header_valid = base[:8] == b"\x00\xff\xff\xff\xff\xff\xff\x00"
        checksum_valid = (sum(base) & 0xFF) == 0

        vendor_raw = struct.unpack(">H", base[8:10])[0]
        vendor = "".join(
            chr(((vendor_raw >> shift) & 0x1F) + 64)
            for shift in (10, 5, 0)
        ).strip("@")
        product_code = int.from_bytes(base[10:12], byteorder="little", signed=False)
        serial_num = int.from_bytes(base[12:16], byteorder="little", signed=False)

        for idx in range(54, 126, 18):
            block = base[idx : idx + 18]
            if len(block) != 18:
                continue
            if block[0:3] != b"\x00\x00\x00":
                continue
            tag = block[3]
            raw = block[5:18].split(b"\x0a", 1)[0].rstrip(b"\x00").strip()
            text = raw.decode("ascii", errors="ignore")
            if tag == 0xFC and text:
                monitor_name = text
            elif tag == 0xFF and text:
                serial_text = text

        out: dict[str, Any] = {
            "edid_size": len(edid),
            "edid_header_valid": header_valid,
            "edid_checksum_valid": checksum_valid,
            "edid_vendor": vendor,
            "edid_product_code": product_code,
            "edid_serial_number": serial_num,
        }
        if monitor_name:
            out["edid_monitor_name"] = monitor_name
        if serial_text:
            out["edid_serial"] = serial_text
        return out

    def _take_sysfs_snapshot(self):
        self._sysfs_snapshot = {}
        for subsystem in self._subsystems:
            self._sysfs_snapshot[subsystem] = self._list_sysfs_entries(subsystem)

    def _poll_sysfs_changes(self):
        for subsystem in self._subsystems:
            if self._should_skip_subsystem(subsystem):
                continue
            prev = self._sysfs_snapshot.get(subsystem, set())
            curr = self._list_sysfs_entries(subsystem)

            for entry in curr - prev:
                self._emit_add(self._extract_sysfs_info(subsystem, entry, "add"))

            for entry in prev - curr:
                self._emit_remove(self._extract_sysfs_info(subsystem, entry, "remove"))

            self._sysfs_snapshot[subsystem] = curr

    def _should_skip_subsystem(self, subsystem: str) -> bool:
        """Prevent duplicate USB alerts when dedicated USB monitor is active."""
        return (
            str(subsystem).strip().lower() == "usb"
            and self._usb_monitor_enabled
            and self._suppress_usb_if_usb_monitor_enabled
        )

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
