import struct
import unittest

from lysec.monitors.ports_monitor import PortsMonitor
from lysec.monitors.usb_monitor import USBMonitor


class _DummyAlert:
    def __init__(self):
        self.events = []

    def fire(self, **kwargs):
        self.events.append(kwargs)


def _encode_vendor_id(vendor: str) -> int:
    vendor = (vendor or "AAA").upper()
    vendor = (vendor + "AAA")[:3]
    a = max(1, min(26, ord(vendor[0]) - 64))
    b = max(1, min(26, ord(vendor[1]) - 64))
    c = max(1, min(26, ord(vendor[2]) - 64))
    return (a << 10) | (b << 5) | c


def _build_valid_edid(vendor: str = "SAM", monitor_name: str = "TESTMON", serial_text: str = "SN123") -> bytes:
    edid = bytearray(128)
    edid[0:8] = b"\x00\xff\xff\xff\xff\xff\xff\x00"

    vendor_raw = _encode_vendor_id(vendor)
    edid[8:10] = struct.pack(">H", vendor_raw)
    edid[10:12] = (0x1234).to_bytes(2, byteorder="little", signed=False)
    edid[12:16] = (0x01020304).to_bytes(4, byteorder="little", signed=False)

    def put_descriptor(offset: int, tag: int, text: str):
        block = bytearray(18)
        block[0:3] = b"\x00\x00\x00"
        block[3] = tag
        payload = (text[:13] + "\n").encode("ascii", errors="ignore")[:13]
        block[5 : 5 + len(payload)] = payload
        edid[offset : offset + 18] = block

    put_descriptor(54, 0xFC, monitor_name)
    put_descriptor(72, 0xFF, serial_text)

    # EDID checksum rule: sum of all 128 bytes modulo 256 must equal 0.
    edid[127] = (-sum(edid[:127])) & 0xFF
    return bytes(edid)


class PortsMonitorTests(unittest.TestCase):
    def _monitor(self, ports_cfg: dict | None = None, usb_enabled: bool = True) -> PortsMonitor:
        config = {
            "monitors": {
                "ports": ports_cfg or {},
                "usb": {"enabled": usb_enabled},
            },
            "alerts": {},
        }
        return PortsMonitor(config, _DummyAlert())

    def test_parse_edid_fields_rejects_short_blob(self):
        parsed = PortsMonitor._parse_edid_fields(b"\x00" * 32)
        self.assertFalse(parsed["edid_header_valid"])
        self.assertFalse(parsed["edid_checksum_valid"])
        self.assertEqual(parsed["edid_size"], 32)

    def test_parse_edid_fields_extracts_identity_and_validity(self):
        edid = _build_valid_edid(vendor="SAM", monitor_name="LABMON", serial_text="SERIAL42")
        parsed = PortsMonitor._parse_edid_fields(edid)

        self.assertTrue(parsed["edid_header_valid"])
        self.assertTrue(parsed["edid_checksum_valid"])
        self.assertEqual(parsed["edid_vendor"], "SAM")
        self.assertEqual(parsed["edid_monitor_name"], "LABMON")
        self.assertEqual(parsed["edid_serial"], "SERIAL42")

    def test_skip_usb_subsystem_when_usb_monitor_enabled(self):
        mon = self._monitor(ports_cfg={"suppress_usb_if_usb_monitor_enabled": True}, usb_enabled=True)
        self.assertTrue(mon._should_skip_subsystem("usb"))

    def test_do_not_skip_usb_subsystem_when_suppression_disabled(self):
        mon = self._monitor(ports_cfg={"suppress_usb_if_usb_monitor_enabled": False}, usb_enabled=True)
        self.assertFalse(mon._should_skip_subsystem("usb"))

    def test_usb_benign_hid_is_not_high_or_critical(self):
        cfg = {
            "monitors": {"usb": {}},
            "alerts": {"severity_policy": {"usb_type_severity": {"HID": "LOW"}}},
        }
        mon = USBMonitor(cfg, _DummyAlert())
        severity, _engine = mon._score_usb_attach_severity(
            {
                "usb_type": "hid",
                "model": "Logitech USB Keyboard",
                "vendor": "Logitech",
            },
            is_whitelisted=False,
        )
        self.assertIn(severity, {"INFO", "LOW", "MEDIUM"})

    def test_usb_suspicious_hid_escalates(self):
        cfg = {
            "monitors": {"usb": {}},
            "alerts": {
                "severity_policy": {
                    "usb_type_severity": {
                        "HID": "LOW",
                        "HID_SUSPICIOUS": "HIGH",
                    }
                }
            },
        }
        mon = USBMonitor(cfg, _DummyAlert())
        severity, _engine = mon._score_usb_attach_severity(
            {
                "usb_type": "hid",
                "model": "Rubber Ducky",
                "vendor": "Hacker Gadget",
            },
            is_whitelisted=False,
        )
        self.assertEqual(severity, "HIGH")

    def test_usb_shadow_keyboard_rule_forces_critical(self):
        cfg = {"monitors": {"usb": {}}, "alerts": {}}
        mon = USBMonitor(cfg, _DummyAlert())
        severity, engine = mon._score_usb_attach_severity(
            {
                "usb_type": "mass_storage",
                "usb_interfaces": ["MASS_STORAGE", "HID"],
                "vendor_id": "abcd",
                "product_id": "1234",
                "serial": "ZXCVBN12",
            },
            is_whitelisted=False,
        )
        self.assertEqual(severity, "CRITICAL")
        self.assertIn("shadow_keyboard", engine["rule_matches"])

    def test_usb_generic_serial_rule_forces_high(self):
        cfg = {"monitors": {"usb": {}}, "alerts": {}}
        mon = USBMonitor(cfg, _DummyAlert())
        severity, engine = mon._score_usb_attach_severity(
            {
                "usb_type": "communications",
                "vendor_id": "beef",
                "product_id": "cafe",
                "serial": "12345678",
                "vendor": "Unknown",
                "model": "Generic USB",
            },
            is_whitelisted=False,
        )
        self.assertIn(severity, {"HIGH", "CRITICAL"})
        self.assertIn("unsigned_or_generic_serial", engine["rule_matches"])

    def test_usb_startup_inventory_emits_event(self):
        alert = _DummyAlert()
        cfg = {
            "monitors": {
                "usb": {
                    "emit_startup_inventory": True,
                    "startup_inventory_severity": "INFO",
                }
            },
            "alerts": {},
        }
        mon = USBMonitor(cfg, alert)

        class _FakeDevice:
            def __init__(self):
                self.sys_path = "/sys/bus/usb/devices/1-1"

            def get(self, key, default=""):
                data = {
                    "ID_VENDOR_ID": "abcd",
                    "ID_MODEL_ID": "1234",
                    "ID_VENDOR": "DemoVendor",
                    "ID_MODEL": "DemoKeyboard",
                    "ID_SERIAL_SHORT": "SER12345",
                    "bDeviceClass": "03",
                }
                return data.get(key, default)

        class _FakeContext:
            def list_devices(self, subsystem=None, DEVTYPE=None):
                if subsystem == "usb" and DEVTYPE == "usb_device":
                    return [_FakeDevice()]
                return []

        mon._context = _FakeContext()
        mon._snapshot_devices()

        event_types = [e.get("event_type") for e in alert.events]
        self.assertIn("USB_DEVICE_PRESENT_AT_START", event_types)


if __name__ == "__main__":
    unittest.main()
