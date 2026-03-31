import unittest
from unittest.mock import patch

from lysec.daemon import LySecDaemon


class DaemonStartupContextTests(unittest.TestCase):
    def _daemon(self) -> LySecDaemon:
        cfg = {
            "daemon": {
                "pid_file": "/tmp/lysec-test.pid",
                "watchdog": {"enabled": False},
            },
            "monitors": {},
            "alerts": {},
            "logging": {
                "log_dir": "/tmp",
                "evidence_dir": "/tmp",
                "max_log_size_mb": 1,
                "log_rotation_count": 1,
            },
        }
        return LySecDaemon(cfg)

    @patch("lysec.daemon.time.monotonic", return_value=123.456)
    @patch.object(LySecDaemon, "_read_uptime_seconds", return_value=78.9)
    @patch.object(LySecDaemon, "_run_cmd_output")
    def test_collect_startup_context(self, mock_run, _mock_uptime, _mock_mono):
        def _side_effect(args):
            if args[:2] == ["systemctl", "get-default"]:
                return "graphical.target"
            if args[:3] == ["systemctl", "show", "-p"]:
                return "lysec.service"
            if args[:2] == ["systemctl", "is-active"]:
                unit = args[2]
                if unit == "display-manager.service":
                    return "active"
                return "inactive"
            return ""

        mock_run.side_effect = _side_effect

        daemon = self._daemon()
        ctx = daemon._collect_startup_context()

        self.assertEqual(ctx["default_target"], "graphical.target")
        self.assertEqual(ctx["lysec_service_unit"], "lysec.service")
        self.assertEqual(ctx["display_manager_status"].get("display-manager.service"), "active")
        self.assertEqual(ctx["uptime_sec"], 78.9)
        self.assertEqual(ctx["boot_monotonic_sec"], 123.456)


if __name__ == "__main__":
    unittest.main()
