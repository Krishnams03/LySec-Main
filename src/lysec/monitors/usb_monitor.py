"""
LySec - USB Monitor
Detects USB device attach / detach events using pyudev (Linux udev).
Logs full device metadata and raises alerts for unknown devices.

Forensic value:
    * Tracks every USB mass-storage, HID, network adapter plug event.
    * Evidence of data exfiltration via removable media.
    * Evidence of BadUSB / Rubber-Ducky style attacks.

NOTE: Detection & Logging ONLY — no device blocking.
"""

import logging
import os
import subprocess
import time
from typing import Any

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from lysec.monitors.base import BaseMonitor
from lysec.alert_engine import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)

logger = logging.getLogger("lysec.monitor.usb")


_SEVERITY_BY_NAME = {
    "INFO": SEVERITY_INFO,
    "LOW": SEVERITY_LOW,
    "MEDIUM": SEVERITY_MEDIUM,
    "HIGH": SEVERITY_HIGH,
    "CRITICAL": SEVERITY_CRITICAL,
}


_USB_CLASS_TO_TYPE = {
    "01": "audio",
    "02": "communications",
    "03": "hid",
    "08": "mass_storage",
    "09": "hub",
    "0a": "cdc_data",
    "0b": "smart_card",
    "0e": "video",
    "e0": "wireless_controller",
    "ef": "miscellaneous",
    "ff": "vendor_specific",
}


class USBMonitor(BaseMonitor):
    name = "usb"

    def __init__(self, config: dict, alert_engine):
        super().__init__(config, alert_engine)
        self._mon_cfg = config.get("monitors", {}).get("usb", {})
        self._whitelist: set[str] = set(self._mon_cfg.get("whitelist", []))
        self._known_devices: dict[str, dict] = {}  # sys_path -> info
        self._udev_monitor = None
        self._context = None
        # Track previously seen device paths for reliable change detection
        self._prev_device_paths: set[str] = set()
        # Track newly attached devices until mount context is available.
        self._pending_mount_context: dict[str, dict[str, Any]] = {}

    def new_method(self):
        self._whitelist: set[str] = set(self._mon_cfg.get("whitelist", []))

    # ── Setup ──
    def setup(self):
        try:
            import pyudev
            self._context = pyudev.Context()
            # Take initial inventory
            self._snapshot_devices()
            logger.info(
                "USB monitor initialised — %d device(s) present",
                len(self._known_devices),
            )
        except ImportError:
            logger.warning(
                "pyudev not installed — falling back to /sys/bus/usb polling"
            )
        except Exception as exc:
            logger.error("USB monitor setup error: %s", exc)

    # ── Poll ──
    def poll(self):
        if self._context is not None:
            self._poll_udev()
        else:
            self._poll_sysfs()
        self._process_pending_mount_context()

    # ──────────────────────── udev-based polling ────────────────────────
    def _poll_udev(self):
        import pyudev

        current: dict[str, dict] = {}
        for device in self._context.list_devices(subsystem="usb", DEVTYPE="usb_device"):
            info = self._extract_udev_info(device)
            current[device.sys_path] = info

        current_paths = set(current.keys())

        # New devices
        for path in current_paths - self._prev_device_paths:
            info = current[path]
            self._on_device_added(info)

        # Removed devices
        for path in self._prev_device_paths - current_paths:
            info = self._known_devices.get(path, {"sys_path": path})
            self._on_device_removed(info)

        self._known_devices = current
        self._prev_device_paths = current_paths

    def _extract_udev_info(self, device) -> dict:
        return {
            "sys_path": device.sys_path,
            "vendor_id": device.get("ID_VENDOR_ID", ""),
            "product_id": device.get("ID_MODEL_ID", ""),
            "vendor": device.get("ID_VENDOR_FROM_DATABASE", device.get("ID_VENDOR", "")),
            "model": device.get("ID_MODEL_FROM_DATABASE", device.get("ID_MODEL", "")),
            "serial": device.get("ID_SERIAL_SHORT", ""),
            "bus_num": device.get("BUSNUM", ""),
            "dev_num": device.get("DEVNUM", ""),
            "driver": device.get("DRIVER", ""),
            "device_class": device.get("bDeviceClass", ""),
            "usb_type": self._classify_usb_type(device.get("bDeviceClass", "")),
            "dev_name": device.get("DEVNAME", ""),
        }

    # ──────────────────────── sysfs fallback polling ────────────────────
    def _poll_sysfs(self):
        current: dict[str, dict] = {}
        usb_base = "/sys/bus/usb/devices"
        if not os.path.isdir(usb_base):
            return

        for entry in os.listdir(usb_base):
            dev_path = os.path.join(usb_base, entry)
            vendor_file = os.path.join(dev_path, "idVendor")
            if not os.path.isfile(vendor_file):
                continue
            info = self._read_sysfs_device(dev_path, entry)
            current[dev_path] = info

        current_paths = set(current.keys())

        for path in current_paths - self._prev_device_paths:
            info = current[path]
            self._on_device_added(info)

        for path in self._prev_device_paths - current_paths:
            info = self._known_devices.get(path, {"sys_path": path})
            self._on_device_removed(info)

        self._known_devices = current
        self._prev_device_paths = current_paths

    def _read_sysfs_device(self, path: str, name: str) -> dict:
        def _read(filename):
            fp = os.path.join(path, filename)
            try:
                return open(fp).read().strip()
            except Exception:
                return ""

        return {
            "sys_path": path,
            "name": name,
            "vendor_id": _read("idVendor"),
            "product_id": _read("idProduct"),
            "manufacturer": _read("manufacturer"),
            "product": _read("product"),
            "serial": _read("serial"),
            "bus_num": _read("busnum"),
            "dev_num": _read("devnum"),
            "device_class": _read("bDeviceClass"),
            "usb_type": self._classify_usb_type(_read("bDeviceClass")),
            "dev_name": "",
        }

    # ──────────────────────── Event handlers ────────────────────────────
    def _on_device_added(self, info: dict):
        vid_pid = f"{info.get('vendor_id', '')}:{info.get('product_id', '')}"
        is_whitelisted = vid_pid in self._whitelist
        usb_type = info.get("usb_type") or "unknown"
        unknown_severity = self._parse_severity(
            self._mon_cfg.get("unknown_device_severity", "MEDIUM"),
            fallback=SEVERITY_MEDIUM,
        )
        storage_severity = self._parse_severity(
            self._mon_cfg.get("storage_device_severity", "MEDIUM"),
            fallback=unknown_severity,
        )
        attach_severity = (
            storage_severity if usb_type == "mass_storage" else unknown_severity
        )
        self._enrich_usb_context(info)
        info["whitelisted"] = is_whitelisted

        logger.info(
            "USB ATTACHED: %s [%s] type=%s serial=%s whitelisted=%s",
            info.get("model") or info.get("product", "unknown"),
            vid_pid,
            usb_type,
            info.get("serial", "N/A"),
            is_whitelisted,
        )

        if self._mon_cfg.get("alert_on_new_device") and not is_whitelisted:
            self._alert.fire(
                monitor="usb",
                event_type="USB_DEVICE_ATTACHED",
                message=f"Unknown USB device attached: {vid_pid} "
                        f"({info.get('model') or info.get('product', 'unknown')}, type={usb_type})",
                severity=attach_severity,
                details=info,
            )

        if info.get("usb_type") == "mass_storage":
            self._track_pending_mount_context(info)
        else:
            self._alert.fire(
                monitor="usb",
                event_type="USB_DEVICE_ATTACHED",
                message=f"Known USB device attached: {vid_pid}",
                severity=SEVERITY_INFO,
                details=info,
            )

    @staticmethod
    def _parse_severity(value: str, fallback: str) -> str:
        sev = str(value or "").upper().strip()
        return _SEVERITY_BY_NAME.get(sev, fallback)

    @staticmethod
    def _classify_usb_type(device_class: str) -> str:
        if not device_class:
            return "unknown"
        code = device_class.strip().lower()
        if code.startswith("0x"):
            code = code[2:]
        code = code.zfill(2)
        return _USB_CLASS_TO_TYPE.get(code, "unknown")

    def _on_device_removed(self, info: dict):
        vid_pid = f"{info.get('vendor_id', '')}:{info.get('product_id', '')}"
        logger.info("USB REMOVED: %s [%s]", info.get("model", "unknown"), vid_pid)
        self._pending_mount_context.pop(info.get("sys_path", ""), None)

        self._alert.fire(
            monitor="usb",
            event_type="USB_DEVICE_REMOVED",
            message=f"USB device removed: {vid_pid}",
            severity=SEVERITY_INFO,
            details=info,
        )

    def _enrich_usb_context(self, info: dict):
        dev_candidates = self._candidate_device_nodes(info)
        mount = self._resolve_mount_context(dev_candidates)
        user_ctx = self._get_user_context(mount.get("mount_point", ""))

        if mount:
            info.update(mount)
        if dev_candidates and not info.get("dev_name"):
            info["dev_name"] = dev_candidates[0]
        if user_ctx:
            info.update(user_ctx)

    def _track_pending_mount_context(self, info: dict):
        if info.get("mount_point"):
            return
        timeout = float(self._mon_cfg.get("mount_enrich_timeout_sec", 15))
        self._pending_mount_context[info.get("sys_path", "")] = {
            "deadline": time.time() + max(1.0, timeout),
            "vendor_id": info.get("vendor_id", ""),
            "product_id": info.get("product_id", ""),
            "serial": info.get("serial", ""),
            "usb_type": info.get("usb_type", "unknown"),
            "model": info.get("model") or info.get("product", "unknown"),
            "sys_path": info.get("sys_path", ""),
            "dev_name": info.get("dev_name", ""),
            "event_emitted": False,
        }

    def _process_pending_mount_context(self):
        if not self._pending_mount_context:
            return

        now = time.time()
        done: list[str] = []
        for sys_path, pending in self._pending_mount_context.items():
            if now > float(pending.get("deadline", 0)):
                done.append(sys_path)
                continue

            enriched = dict(pending)
            self._enrich_usb_context(enriched)
            mount_point = enriched.get("mount_point")
            if not mount_point:
                continue

            if self._mon_cfg.get("emit_mount_event", True):
                self._alert.fire(
                    monitor="usb",
                    event_type="USB_DEVICE_MOUNTED",
                    message=(
                        "USB storage mounted: "
                        f"{enriched.get('dev_name', '?')} at {mount_point}"
                    ),
                    severity=SEVERITY_INFO,
                    details=enriched,
                )
            done.append(sys_path)

        for sys_path in done:
            self._pending_mount_context.pop(sys_path, None)

    def _candidate_device_nodes(self, info: dict) -> list[str]:
        candidates: list[str] = []
        dev_name = str(info.get("dev_name", "")).strip()
        if dev_name:
            candidates.append(dev_name)

        serial = str(info.get("serial", "")).strip().lower()
        if os.path.isdir("/dev/disk/by-id"):
            try:
                for entry in os.listdir("/dev/disk/by-id"):
                    entry_l = entry.lower()
                    if "usb" not in entry_l:
                        continue
                    if serial and serial not in entry_l:
                        continue
                    full = os.path.join("/dev/disk/by-id", entry)
                    if not os.path.islink(full):
                        continue
                    target = os.path.realpath(full)
                    if target and target not in candidates:
                        candidates.append(target)
            except Exception:
                pass

        return candidates

    @staticmethod
    def _read_mounts() -> list[dict[str, str]]:
        mounts: list[dict[str, str]] = []
        try:
            with open("/proc/self/mountinfo", "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    parts = line.strip().split(" - ", 1)
                    if len(parts) != 2:
                        continue
                    pre = parts[0].split()
                    post = parts[1].split()
                    if len(pre) < 5 or len(post) < 2:
                        continue
                    mount_point = pre[4].replace("\\040", " ")
                    fs_type = post[0]
                    source = post[1]
                    mounts.append(
                        {
                            "mount_point": mount_point,
                            "fs_type": fs_type,
                            "source_device": source,
                        }
                    )
        except Exception:
            pass
        return mounts

    def _resolve_mount_context(self, device_nodes: list[str]) -> dict[str, str]:
        if not device_nodes:
            return {}

        normalized_nodes = {os.path.realpath(node) for node in device_nodes}
        for mount in self._read_mounts():
            source = mount.get("source_device", "")
            if not source.startswith("/dev/"):
                continue
            source_real = os.path.realpath(source)
            if source in normalized_nodes or source_real in normalized_nodes:
                return {
                    "mount_point": mount.get("mount_point", ""),
                    "filesystem_type": mount.get("fs_type", ""),
                    "dev_name": source,
                }

        return {}

    def _get_user_context(self, mount_point: str) -> dict[str, Any]:
        users: list[str] = []

        if HAS_PSUTIL:
            try:
                users = sorted(
                    {
                        str(u.name)
                        for u in psutil.users()
                        if getattr(u, "name", None)
                    }
                )
            except Exception:
                users = []

        if not users:
            try:
                out = subprocess.check_output(["who"], text=True, stderr=subprocess.DEVNULL)
                for line in out.splitlines():
                    parts = line.split()
                    if parts:
                        users.append(parts[0])
                users = sorted(set(users))
            except Exception:
                users = []

        likely_user = ""
        norm_mount = os.path.abspath(mount_point) if mount_point else ""
        if norm_mount.startswith("/media/") or norm_mount.startswith("/run/media/"):
            chunks = [c for c in norm_mount.split(os.sep) if c]
            if norm_mount.startswith("/media/") and len(chunks) >= 2:
                likely_user = chunks[1]
            elif norm_mount.startswith("/run/media/") and len(chunks) >= 3:
                likely_user = chunks[2]

        if not likely_user and users:
            likely_user = users[0]

        return {
            "active_users": users,
            "user": likely_user,
        }

    # ──────────────────────── Helpers ───────────────────────────────────
    def _snapshot_devices(self):
        """Take initial snapshot so we don't alert on boot-time devices."""
        if self._context:
            import pyudev
            for device in self._context.list_devices(subsystem="usb", DEVTYPE="usb_device"):
                info = self._extract_udev_info(device)
                self._known_devices[device.sys_path] = info
                self._prev_device_paths.add(device.sys_path)
        logger.info("Initial USB snapshot: %d devices", len(self._known_devices))

