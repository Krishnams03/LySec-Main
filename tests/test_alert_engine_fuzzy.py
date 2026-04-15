import unittest
import tempfile
from unittest.mock import patch

from lysec.alert_engine import AlertEngine


class AlertEngineFuzzyTests(unittest.TestCase):
    def _engine(self, cfg_overrides: dict | None = None) -> AlertEngine:
        cfg = {
            "alerts": {
                "alert_log": "/tmp/lysec_test_alerts.log",
                "syslog": False,
                "fuzzy_alert_fingerprints": {
                    "enabled": True,
                    "algorithms": ["ssdeep", "tlsh"],
                    "compare_previous": True,
                    "cache_size": 64,
                },
                "correlation": {"enabled": False},
                "ml_anomaly": {"enabled": False},
                "mitre": {"enabled": False},
            }
        }
        if cfg_overrides:
            cfg["alerts"].update(cfg_overrides.get("alerts", {}))
        return AlertEngine(cfg)

    @patch("lysec.alert_engine.compute_fuzzy_hashes_from_text")
    @patch("lysec.alert_engine.compare_fuzzy_hashes")
    @patch.object(AlertEngine, "_dispatch")
    def test_alert_fuzzy_attached_on_fire(self, mock_dispatch, _mock_compare, mock_compute):
        mock_compute.return_value = {"ssdeep": "abc"}
        eng = self._engine()

        eng.fire(
            monitor="process",
            event_type="PROCESS_STARTED",
            message="proc started",
            severity="INFO",
            details={"pid": 111},
        )

        self.assertEqual(mock_dispatch.call_count, 1)
        alert = mock_dispatch.call_args[0][0]
        self.assertIn("alert_fuzzy", alert["details"])
        self.assertEqual(alert["details"]["alert_fuzzy"]["hash"], {"ssdeep": "abc"})

    @patch("lysec.alert_engine.compute_fuzzy_hashes_from_text")
    @patch("lysec.alert_engine.compare_fuzzy_hashes")
    @patch.object(AlertEngine, "_dispatch")
    def test_alert_fuzzy_similarity_to_previous(self, mock_dispatch, mock_compare, mock_compute):
        mock_compute.side_effect = [
            {"ssdeep": "h1"},
            {"ssdeep": "h2"},
        ]
        mock_compare.return_value = {"ssdeep_score": 85}

        eng = self._engine()

        eng.fire(
            monitor="network",
            event_type="NEW_CONNECTION",
            message="conn",
            severity="MEDIUM",
            details={"ip": "10.0.0.1"},
        )
        eng.fire(
            monitor="network",
            event_type="NEW_CONNECTION",
            message="conn changed",
            severity="MEDIUM",
            details={"ip": "10.0.0.2"},
        )

        self.assertEqual(mock_dispatch.call_count, 2)
        second_alert = mock_dispatch.call_args_list[1][0][0]
        self.assertIn("alert_fuzzy", second_alert["details"])
        self.assertEqual(
            second_alert["details"]["alert_fuzzy"].get("similarity_prev"),
            {"ssdeep_score": 85},
        )

    @patch.object(AlertEngine, "_dispatch")
    def test_usb_dedup_uses_stable_identity_key(self, mock_dispatch):
        eng = self._engine(
            {
                "alerts": {
                    "dedup_window_sec": 60,
                    "usb_dedup_window_sec": 2.0,
                }
            }
        )

        base = {
            "uid": "8564:1000:ABC123",
            "vendor_id": "8564",
            "product_id": "1000",
            "serial": "ABC123",
            "sys_path": "/sys/bus/usb/devices/1-3",
            "model": "JetFlash",
            "dev_num": "2",
        }
        changed_non_identity = dict(base)
        changed_non_identity["dev_num"] = "3"
        changed_non_identity["active_users"] = ["alice"]

        eng.fire(
            monitor="usb",
            event_type="USB_DEVICE_ATTACHED",
            message="Unknown USB device attached",
            severity="MEDIUM",
            details=base,
        )
        eng.fire(
            monitor="usb",
            event_type="USB_DEVICE_ATTACHED",
            message="Unknown USB device attached",
            severity="MEDIUM",
            details=changed_non_identity,
        )

        self.assertEqual(mock_dispatch.call_count, 1)

    @patch.object(AlertEngine, "_dispatch")
    def test_usb_dedup_shared_state_across_instances(self, mock_dispatch):
        with tempfile.TemporaryDirectory() as tmp:
            state_fp = f"{tmp}/dedup.json"
            eng = self._engine(
                {
                    "alerts": {
                        "usb_dedup_window_sec": 5.0,
                        "dedup_state_file": state_fp,
                    }
                }
            )

            payload = {
                "uid": "8564:1000:ABC123",
                "vendor_id": "8564",
                "product_id": "1000",
                "serial": "ABC123",
                "sys_path": "/sys/bus/usb/devices/1-3",
            }

            eng.fire(
                monitor="usb",
                event_type="USB_DEVICE_ATTACHED",
                message="Unknown USB device attached",
                severity="MEDIUM",
                details=payload,
            )

            # Simulate another process by clearing in-memory cache while reusing shared dedup state file.
            eng._seen = {}

            eng.fire(
                monitor="usb",
                event_type="USB_DEVICE_ATTACHED",
                message="Unknown USB device attached",
                severity="MEDIUM",
                details=payload,
            )

            self.assertEqual(mock_dispatch.call_count, 1)


if __name__ == "__main__":
    unittest.main()
