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
import re
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
        self._global_severity_policy = config.get("alerts", {}).get("severity_policy", {})
        self._severity_engine_cfg = self._mon_cfg.get("severity_engine", {})
        self._whitelist: set[str] = set(self._mon_cfg.get("whitelist", []))
        self._emit_startup_inventory = bool(self._mon_cfg.get("emit_startup_inventory", True))
        self._startup_inventory_severity = self._parse_severity(
            self._mon_cfg.get("startup_inventory_severity", "INFO"),
            fallback=SEVERITY_INFO,
        )
        self._usb_type_severity = self._build_usb_type_severity_map()
        self._hid_suspicious_keywords = {
            str(x).strip().lower()
            for x in self._mon_cfg.get(
                "hid_suspicious_keywords",
                ["rubber", "ducky", "inject", "badusb", "keystroke"],
            )
            if str(x).strip()
        }
        self._known_devices: dict[str, dict] = {}  # sys_path -> info
        self._recent_device_actions: dict[str, list[tuple[float, str]]] = {}
        self._recent_event_emissions: dict[str, float] = {}
        self._seen_device_signatures: set[str] = set()
        self._port_type_history: dict[str, set[str]] = {}
        self._udev_monitor = None
        self._context = None
        # Track previously seen device paths for reliable change detection
        self._prev_device_paths: set[str] = set()
        # Track newly attached devices until mount context is available.
        self._pending_mount_context: dict[str, dict[str, Any]] = {}

        weights = self._severity_engine_cfg.get("weights", {})
        self._weight_rule = float(weights.get("rule", 0.5))
        self._weight_heuristic = float(weights.get("heuristic", 0.3))
        self._weight_ml = float(weights.get("ml", 0.2))

        thresholds = self._severity_engine_cfg.get("score_thresholds", {})
        self._score_critical = float(thresholds.get("critical", 8.5))
        self._score_high = float(thresholds.get("high", 6.5))
        self._score_medium = float(thresholds.get("medium", 4.5))
        self._score_low = float(thresholds.get("low", 2.5))

        self._rapid_cycle_window_sec = float(
            self._severity_engine_cfg.get("rapid_cycle_window_sec", 2.0)
        )
        self._rapid_cycle_min_events = int(
            self._severity_engine_cfg.get("rapid_cycle_min_events", 3)
        )
        self._ghost_mount_timeout_sec = float(
            self._severity_engine_cfg.get("ghost_mount_timeout_sec", 3.0)
        )
        self._generic_serial_patterns = [
            str(x).strip().lower()
            for x in self._severity_engine_cfg.get(
                "generic_serial_patterns",
                ["123456", "12345678", "000000", "abcdef", "generic"],
            )
            if str(x).strip()
        ]
        self._off_hours_start = int(self._severity_engine_cfg.get("off_hours_start", 22))
        self._off_hours_end = int(self._severity_engine_cfg.get("off_hours_end", 6))
        self._power_draw_high_ma = int(self._severity_engine_cfg.get("power_draw_high_ma", 500))
        self._event_dedup_window_sec = float(self._mon_cfg.get("event_dedup_window_sec", 2.0))

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
        vendor_id = device.get("ID_VENDOR_ID", "")
        product_id = device.get("ID_MODEL_ID", "")
        serial_short = device.get("ID_SERIAL_SHORT", "")
        serial_full = device.get("ID_SERIAL", "")
        path_tag = device.get("ID_PATH_TAG", "")
        uid = self._build_device_uid(
            vendor_id=vendor_id,
            product_id=product_id,
            serial=serial_short or serial_full,
            path_hint=path_tag or device.sys_path,
        )
        interfaces = self._parse_interface_classes(device.get("ID_USB_INTERFACES", ""))
        usb_type = self._resolve_usb_type(device.get("bDeviceClass", ""), interfaces)

        return {
            "sys_path": device.sys_path,
            "vendor_id": vendor_id,
            "product_id": product_id,
            "vendor": device.get("ID_VENDOR_FROM_DATABASE", device.get("ID_VENDOR", "")),
            "model": device.get("ID_MODEL_FROM_DATABASE", device.get("ID_MODEL", "")),
            "manufacturer": device.get("ID_VENDOR", ""),
            "product": device.get("ID_MODEL", ""),
            "serial": serial_short,
            "serial_full": serial_full,
            "uid": uid,
            "path_tag": path_tag,
            "revision": device.get("ID_REVISION", ""),
            "id_bus": device.get("ID_BUS", ""),
            "bus_num": device.get("BUSNUM", ""),
            "dev_num": device.get("DEVNUM", ""),
            "driver": device.get("DRIVER", ""),
            "usb_interfaces_raw": device.get("ID_USB_INTERFACES", ""),
            "device_class": device.get("bDeviceClass", ""),
            "usb_type": usb_type,
            "usb_interfaces": interfaces,
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

        vendor_id = _read("idVendor")
        product_id = _read("idProduct")
        serial = _read("serial")
        uid = self._build_device_uid(
            vendor_id=vendor_id,
            product_id=product_id,
            serial=serial,
            path_hint=path,
        )
        interfaces = self._read_sysfs_interface_classes(path)
        usb_type = self._resolve_usb_type(_read("bDeviceClass"), interfaces)

        return {
            "sys_path": path,
            "name": name,
            "vendor_id": vendor_id,
            "product_id": product_id,
            "manufacturer": _read("manufacturer"),
            "product": _read("product"),
            "model": _read("product"),
            "serial": serial,
            "serial_full": serial,
            "uid": uid,
            "bus_num": _read("busnum"),
            "dev_num": _read("devnum"),
            "device_class": _read("bDeviceClass"),
            "usb_type": usb_type,
            "usb_interfaces": interfaces,
            "dev_name": "",
        }

    # ──────────────────────── Event handlers ────────────────────────────
    def _on_device_added(self, info: dict):
        if self._should_suppress_event("USB_DEVICE_ATTACHED", info):
            return

        vid_pid = f"{info.get('vendor_id', '')}:{info.get('product_id', '')}"
        is_whitelisted = vid_pid in self._whitelist
        usb_type = info.get("usb_type") or "unknown"
        self._enrich_usb_context(info)
        info["power_draw_ma"] = self._read_power_draw_ma(str(info.get("sys_path", "")))
        info["whitelisted"] = is_whitelisted
        device_key = self._device_key(info)
        self._record_device_action(device_key, "add")
        attach_severity, engine = self._score_usb_attach_severity(info, is_whitelisted)
        info["severity_engine"] = engine

        logger.info(
            "USB ATTACHED: %s [%s] uid=%s type=%s serial=%s bus=%s dev=%s whitelisted=%s",
            info.get("model") or info.get("product", "unknown"),
            vid_pid,
            info.get("uid", ""),
            usb_type,
            info.get("serial", "N/A"),
            info.get("bus_num", ""),
            info.get("dev_num", ""),
            is_whitelisted,
        )

        if self._mon_cfg.get("alert_on_new_device"):
            label = "known" if is_whitelisted else "unknown"
            vendor = info.get("vendor") or info.get("manufacturer") or "unknown"
            bus = str(info.get("bus_num", "")).zfill(3) if str(info.get("bus_num", "")).strip() else "?"
            dev = str(info.get("dev_num", "")).zfill(3) if str(info.get("dev_num", "")).strip() else "?"
            self._alert.fire(
                monitor="usb",
                event_type="USB_DEVICE_ATTACHED",
                message=(
                    f"{label.title()} USB device attached: {vid_pid} "
                    f"({vendor} {info.get('model') or info.get('product', 'unknown')}, "
                    f"bus={bus},dev={dev}, uid={info.get('uid', '')}, type={usb_type})"
                ),
                severity=attach_severity,
                details=info,
            )

        if info.get("usb_type") == "mass_storage":
            self._track_pending_mount_context(info)
        self._seen_device_signatures.add(self._device_signature(info))
        port_id = self._port_id(info)
        if port_id:
            self._port_type_history.setdefault(port_id, set()).add(
                str(info.get("usb_type", "unknown")).upper()
            )

    @staticmethod
    def _parse_severity(value: str, fallback: str) -> str:
        sev = str(value or "").upper().strip()
        return _SEVERITY_BY_NAME.get(sev, fallback)

    def _build_usb_type_severity_map(self) -> dict[str, str]:
        """Build class-based USB severity policy with backward-compatible fallbacks."""
        unknown = self._parse_severity(
            self._mon_cfg.get("unknown_device_severity", "MEDIUM"),
            fallback=SEVERITY_MEDIUM,
        )
        storage = self._parse_severity(
            self._mon_cfg.get("storage_device_severity", "MEDIUM"),
            fallback=unknown,
        )

        policy_cfg = self._global_severity_policy.get("usb_type_severity", {})
        policy_map = {
            "MASS_STORAGE": storage,
            "HID": SEVERITY_LOW,
            "HID_SUSPICIOUS": SEVERITY_HIGH,
            "UNKNOWN": unknown,
            "TRUSTED": SEVERITY_INFO,
        }
        for key, value in policy_cfg.items():
            policy_map[str(key).strip().upper()] = self._parse_severity(
                value,
                fallback=unknown,
            )
        return policy_map

    def _score_usb_attach_severity(
        self, info: dict[str, Any], is_whitelisted: bool
    ) -> tuple[str, dict[str, Any]]:
        if is_whitelisted:
            return self._usb_type_severity.get("TRUSTED", SEVERITY_INFO), {
                "mode": "trusted",
                "final_score": 1.0,
                "rule_score": 0.0,
                "heuristic_score": 0.0,
                "ml_score": 0.0,
                "rule_matches": [],
                "heuristic_matches": [],
                "ml_matches": [],
            }

        usb_type = str(info.get("usb_type") or "unknown").strip().upper()
        base_key = str(usb_type or "unknown").strip().upper()
        if base_key == "HID" and self._is_suspicious_hid(info):
            base_key = "HID_SUSPICIOUS"
        base_severity = self._usb_type_severity.get(
            base_key,
            self._usb_type_severity.get("UNKNOWN", SEVERITY_MEDIUM),
        )

        rule_score, rule_matches, hard_rule_severity = self._rule_score(info)
        heuristic_score, heuristic_matches, heuristic_min_severity = self._heuristic_score(info)
        ml_score, ml_matches = self._ml_novelty_score(info)

        final_score = (
            self._weight_rule * rule_score
            + self._weight_heuristic * heuristic_score
            + self._weight_ml * ml_score
        )
        scored_severity = self._score_to_severity(final_score)

        if usb_type == "HID" and not self._is_suspicious_hid(info):
            scored_severity = self._cap_severity(scored_severity, maximum=SEVERITY_MEDIUM)

        final_severity = self._max_severity(base_severity, scored_severity)
        if heuristic_min_severity:
            final_severity = self._max_severity(final_severity, heuristic_min_severity)
        if hard_rule_severity:
            final_severity = self._max_severity(final_severity, hard_rule_severity)

        engine = {
            "mode": "weighted_matrix",
            "weights": {
                "rule": self._weight_rule,
                "heuristic": self._weight_heuristic,
                "ml": self._weight_ml,
            },
            "rule_score": round(rule_score, 3),
            "heuristic_score": round(heuristic_score, 3),
            "ml_score": round(ml_score, 3),
            "final_score": round(final_score, 3),
            "base_severity": base_severity,
            "scored_severity": scored_severity,
            "final_severity": final_severity,
            "rule_matches": rule_matches,
            "heuristic_matches": heuristic_matches,
            "ml_matches": ml_matches,
        }
        return final_severity, engine

    def _rule_score(self, info: dict[str, Any]) -> tuple[float, list[str], str | None]:
        score = 0.0
        matches: list[str] = []
        hard: str | None = None

        interfaces = {str(x).upper() for x in info.get("usb_interfaces", [])}
        usb_type = str(info.get("usb_type", "")).upper()
        if usb_type == "MASS_STORAGE" and "HID" in interfaces:
            score = max(score, 10.0)
            matches.append("shadow_keyboard")
            hard = SEVERITY_CRITICAL

        serial = str(info.get("serial", "")).strip().lower()
        if usb_type not in {"HID"} and self._is_generic_serial(serial):
            score = max(score, 7.0)
            matches.append("unsigned_or_generic_serial")
            hard = self._max_severity(hard or SEVERITY_INFO, SEVERITY_HIGH)

        if self._is_suspicious_hid(info):
            score = max(score, 6.5)
            matches.append("suspicious_hid_identity")

        return score, matches, hard

    def _heuristic_score(self, info: dict[str, Any]) -> tuple[float, list[str], str | None]:
        score = 0.0
        matches: list[str] = []
        min_sev: str | None = None

        key = self._device_key(info)
        if self._has_rapid_cycle(key):
            score = max(score, 5.0)
            matches.append("rapid_cycling")
            min_sev = self._max_severity(min_sev or SEVERITY_INFO, SEVERITY_MEDIUM)

        if self._has_descriptor_mismatch(info):
            score = max(score, 7.5)
            matches.append("descriptor_mismatch")
            min_sev = self._max_severity(min_sev or SEVERITY_INFO, SEVERITY_HIGH)

        return score, matches, min_sev

    def _ml_novelty_score(self, info: dict[str, Any]) -> tuple[float, list[str]]:
        score = 0.0
        matches: list[str] = []

        signature = self._device_signature(info)
        if signature not in self._seen_device_signatures:
            score += 5.0
            matches.append("novel_device_signature")

        if self._is_off_hours():
            score += 1.5
            matches.append("off_hours_attach")

        port_id = self._port_id(info)
        usb_type = str(info.get("usb_type", "unknown")).upper()
        if port_id and usb_type:
            seen_types = self._port_type_history.get(port_id, set())
            if seen_types and usb_type not in seen_types:
                score += 2.0
                matches.append("new_type_on_known_port")

        power_ma = int(info.get("power_draw_ma", 0) or 0)
        if power_ma > self._power_draw_high_ma:
            score += 2.0
            matches.append("high_power_draw")

        if score <= 0:
            return 1.0, []
        return min(10.0, score), matches

    def _is_off_hours(self) -> bool:
        hour = time.localtime().tm_hour
        if self._off_hours_start == self._off_hours_end:
            return False
        if self._off_hours_start > self._off_hours_end:
            return hour >= self._off_hours_start or hour < self._off_hours_end
        return self._off_hours_start <= hour < self._off_hours_end

    @staticmethod
    def _port_id(info: dict[str, Any]) -> str:
        sys_path = str(info.get("sys_path", "")).strip()
        if not sys_path:
            return ""
        return os.path.basename(sys_path)

    @staticmethod
    def _read_power_draw_ma(sys_path: str) -> int:
        if not sys_path:
            return 0
        fp = os.path.join(sys_path, "bMaxPower")
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                raw = fh.read().strip().lower().replace("ma", "").strip()
            val = int(raw)
            # Some kernels expose units in 2mA increments.
            return val * 2 if val < 250 else val
        except Exception:
            return 0

    def _has_descriptor_mismatch(self, info: dict[str, Any]) -> bool:
        vendor_db = str(info.get("vendor", "")).strip().lower()
        manufacturer = str(info.get("manufacturer", info.get("vendor", ""))).strip().lower()
        if not vendor_db or not manufacturer:
            return False

        # A lightweight mismatch heuristic: if normalized vendor tokens do not overlap.
        token_re = re.compile(r"[a-z0-9]+")
        v_tokens = set(token_re.findall(vendor_db))
        m_tokens = set(token_re.findall(manufacturer))
        if not v_tokens or not m_tokens:
            return False
        return v_tokens.isdisjoint(m_tokens)

    def _is_generic_serial(self, serial: str) -> bool:
        if not serial:
            return True
        if len(serial) < 6:
            return True
        return any(pat in serial for pat in self._generic_serial_patterns)

    @staticmethod
    def _device_key(info: dict[str, Any]) -> str:
        return "|".join(
            [
                str(info.get("vendor_id", "")),
                str(info.get("product_id", "")),
                str(info.get("serial", "")),
                str(info.get("sys_path", "")),
            ]
        )

    @staticmethod
    def _device_signature(info: dict[str, Any]) -> str:
        return "|".join(
            [
                str(info.get("vendor_id", "")),
                str(info.get("product_id", "")),
                str(info.get("usb_type", "")),
                str(info.get("vendor", "")),
                str(info.get("model", info.get("product", ""))),
            ]
        )

    def _record_device_action(self, device_key: str, action: str):
        now = time.time()
        actions = self._recent_device_actions.setdefault(device_key, [])
        actions.append((now, action))
        cutoff = now - max(self._rapid_cycle_window_sec, 2.0)
        self._recent_device_actions[device_key] = [
            (ts, act) for ts, act in actions if ts >= cutoff
        ]

    def _has_rapid_cycle(self, device_key: str) -> bool:
        actions = self._recent_device_actions.get(device_key, [])
        if len(actions) < self._rapid_cycle_min_events:
            return False
        recent = actions[-self._rapid_cycle_min_events :]
        first_ts = recent[0][0]
        last_ts = recent[-1][0]
        if (last_ts - first_ts) > self._rapid_cycle_window_sec:
            return False
        pattern = [a for _, a in recent]
        return pattern == ["add", "remove", "add"]

    def _score_to_severity(self, score: float) -> str:
        if score >= self._score_critical:
            return SEVERITY_CRITICAL
        if score >= self._score_high:
            return SEVERITY_HIGH
        if score >= self._score_medium:
            return SEVERITY_MEDIUM
        if score >= self._score_low:
            return SEVERITY_LOW
        return SEVERITY_INFO

    @staticmethod
    def _max_severity(a: str, b: str) -> str:
        order = {
            SEVERITY_INFO: 0,
            SEVERITY_LOW: 1,
            SEVERITY_MEDIUM: 2,
            SEVERITY_HIGH: 3,
            SEVERITY_CRITICAL: 4,
        }
        aa = str(a or SEVERITY_MEDIUM).upper()
        bb = str(b or SEVERITY_MEDIUM).upper()
        return aa if order.get(aa, 2) >= order.get(bb, 2) else bb

    def _is_suspicious_hid(self, info: dict[str, Any]) -> bool:
        text = " ".join(
            str(info.get(k, ""))
            for k in ("vendor", "manufacturer", "model", "product", "driver", "serial")
        ).lower()
        return any(keyword in text for keyword in self._hid_suspicious_keywords)

    @staticmethod
    def _cap_severity(value: str, maximum: str) -> str:
        order = {
            SEVERITY_INFO: 0,
            SEVERITY_LOW: 1,
            SEVERITY_MEDIUM: 2,
            SEVERITY_HIGH: 3,
            SEVERITY_CRITICAL: 4,
        }
        v = str(value or SEVERITY_MEDIUM).upper()
        m = str(maximum or SEVERITY_MEDIUM).upper()
        if order.get(v, 2) > order.get(m, 2):
            return m
        return v

    @staticmethod
    def _classify_usb_type(device_class: str) -> str:
        if not device_class:
            return "unknown"
        code = device_class.strip().lower()
        if code.startswith("0x"):
            code = code[2:]
        code = code.zfill(2)
        return _USB_CLASS_TO_TYPE.get(code, "unknown")

    @classmethod
    def _resolve_usb_type(cls, device_class: str, interfaces: list[str]) -> str:
        usb_type = cls._classify_usb_type(device_class)
        if usb_type != "unknown":
            return usb_type

        interfaces_u = {str(x).strip().upper() for x in interfaces}
        if "MASS_STORAGE" in interfaces_u:
            return "mass_storage"
        if "HID" in interfaces_u:
            return "hid"
        return "unknown"

    def _on_device_removed(self, info: dict):
        if self._should_suppress_event("USB_DEVICE_REMOVED", info):
            return

        vid_pid = f"{info.get('vendor_id', '')}:{info.get('product_id', '')}"
        logger.info(
            "USB REMOVED: %s [%s] uid=%s bus=%s dev=%s",
            info.get("model", "unknown"),
            vid_pid,
            info.get("uid", ""),
            info.get("bus_num", ""),
            info.get("dev_num", ""),
        )
        self._record_device_action(self._device_key(info), "remove")
        self._pending_mount_context.pop(info.get("sys_path", ""), None)

        self._alert.fire(
            monitor="usb",
            event_type="USB_DEVICE_REMOVED",
            message=f"USB device removed: {vid_pid}",
            severity=SEVERITY_INFO,
            details=info,
        )

    @staticmethod
    def _build_device_uid(
        vendor_id: str,
        product_id: str,
        serial: str,
        path_hint: str,
    ) -> str:
        serial_or_path = str(serial or "").strip() or str(path_hint or "").strip()
        return f"{vendor_id}:{product_id}:{serial_or_path}"

    def _event_fingerprint(self, event_type: str, info: dict[str, Any]) -> str:
        uid = str(info.get("uid", "")).strip()
        if uid:
            return f"{event_type}|{uid}"

        return "|".join(
            [
                event_type,
                str(info.get("vendor_id", "")),
                str(info.get("product_id", "")),
                str(info.get("serial", "")),
                str(info.get("sys_path", "")),
            ]
        )

    def _should_suppress_event(self, event_type: str, info: dict[str, Any]) -> bool:
        if self._event_dedup_window_sec <= 0:
            return False

        now = time.time()
        fp = self._event_fingerprint(event_type, info)
        last = self._recent_event_emissions.get(fp)
        self._recent_event_emissions[fp] = now

        cutoff = now - max(self._event_dedup_window_sec * 4.0, 10.0)
        self._recent_event_emissions = {
            key: ts for key, ts in self._recent_event_emissions.items() if ts >= cutoff
        }

        return last is not None and (now - last) <= self._event_dedup_window_sec

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
        ghost_timeout = max(1.0, self._ghost_mount_timeout_sec)
        self._pending_mount_context[info.get("sys_path", "")] = {
            "deadline": time.time() + max(1.0, timeout),
            "ghost_deadline": time.time() + ghost_timeout,
            "vendor_id": info.get("vendor_id", ""),
            "product_id": info.get("product_id", ""),
            "serial": info.get("serial", ""),
            "usb_type": info.get("usb_type", "unknown"),
            "model": info.get("model") or info.get("product", "unknown"),
            "sys_path": info.get("sys_path", ""),
            "dev_name": info.get("dev_name", ""),
            "event_emitted": False,
            "ghost_alert_emitted": False,
        }

    def _process_pending_mount_context(self):
        if not self._pending_mount_context:
            return

        now = time.time()
        done: list[str] = []
        for sys_path, pending in self._pending_mount_context.items():
            if (
                not pending.get("ghost_alert_emitted", False)
                and now > float(pending.get("ghost_deadline", 0))
            ):
                self._alert.fire(
                    monitor="usb",
                    event_type="USB_GHOST_MOUNT",
                    message=(
                        "USB storage added but no partition mounted within "
                        f"{self._ghost_mount_timeout_sec:.1f}s"
                    ),
                    severity=SEVERITY_MEDIUM,
                    details=dict(pending),
                )
                pending["ghost_alert_emitted"] = True

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
        """Take initial snapshot and optionally emit startup inventory alerts."""
        if self._context:
            for device in self._context.list_devices(subsystem="usb", DEVTYPE="usb_device"):
                info = self._extract_udev_info(device)
                self._enrich_usb_context(info)
                info["power_draw_ma"] = self._read_power_draw_ma(str(info.get("sys_path", "")))
                vid_pid = f"{info.get('vendor_id', '')}:{info.get('product_id', '')}"
                is_whitelisted = vid_pid in self._whitelist
                info["whitelisted"] = is_whitelisted
                severity, engine = self._score_usb_attach_severity(info, is_whitelisted)
                info["severity_engine"] = engine
                self._known_devices[device.sys_path] = info
                self._prev_device_paths.add(device.sys_path)
                self._seen_device_signatures.add(self._device_signature(info))
                if self._emit_startup_inventory:
                    self._alert.fire(
                        monitor="usb",
                        event_type="USB_DEVICE_PRESENT_AT_START",
                        message=(
                            "USB device already present at daemon start: "
                            f"{vid_pid} ({info.get('model') or info.get('product', 'unknown')}, "
                            f"type={info.get('usb_type', 'unknown')})"
                        ),
                        severity=self._max_severity(self._startup_inventory_severity, severity),
                        details=info,
                    )
        logger.info("Initial USB snapshot: %d devices", len(self._known_devices))

    @staticmethod
    def _parse_interface_classes(raw: str) -> list[str]:
        if not raw:
            return []
        classes: list[str] = []
        # Example raw format: :080650:030101:
        for part in raw.split(":"):
            if len(part) < 2:
                continue
            class_hex = part[:2].lower()
            if class_hex == "03":
                classes.append("HID")
            elif class_hex == "08":
                classes.append("MASS_STORAGE")
        return sorted(set(classes))

    @staticmethod
    def _read_sysfs_interface_classes(dev_path: str) -> list[str]:
        classes: set[str] = set()
        try:
            for entry in os.listdir(dev_path):
                if ":" not in entry:
                    continue
                fp = os.path.join(dev_path, entry, "bInterfaceClass")
                if not os.path.isfile(fp):
                    continue
                with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                    code = fh.read().strip().lower().replace("0x", "")
                if code == "03":
                    classes.add("HID")
                elif code == "08":
                    classes.add("MASS_STORAGE")
        except Exception:
            return []
        return sorted(classes)

