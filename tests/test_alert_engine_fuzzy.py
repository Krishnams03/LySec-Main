import unittest
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


if __name__ == "__main__":
    unittest.main()
