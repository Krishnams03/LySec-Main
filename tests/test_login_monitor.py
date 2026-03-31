import tempfile
import unittest
from pathlib import Path

from lysec.monitors.login_monitor import LoginMonitor, UTMP_SIZE


class _DummyAlert:
    def __init__(self):
        self.events = []

    def fire(self, **kwargs):
        self.events.append(kwargs)


class LoginMonitorTests(unittest.TestCase):
    def _monitor(self, watch_files):
        alert = _DummyAlert()
        cfg = {
            "monitors": {
                "login": {
                    "watch_files": watch_files,
                    "startup_backfill_enabled": True,
                    "startup_backfill_lines": 50,
                    "startup_backfill_records": 8,
                }
            }
        }
        return LoginMonitor(cfg, alert), alert

    def test_startup_backfill_text_emits_failed_login(self):
        with tempfile.TemporaryDirectory() as td:
            auth_path = Path(td) / "auth.log"
            auth_path.write_text(
                "Mar 10 10:00:00 host sshd[100]: Failed password for root from 1.2.3.4 port 22\n",
                encoding="utf-8",
            )

            mon, alert = self._monitor([str(auth_path)])
            mon.setup()

            event_types = [e.get("event_type") for e in alert.events]
            self.assertIn("LOGIN_FAILED", event_types)

    def test_startup_backfill_binary_reads_tail_records(self):
        with tempfile.TemporaryDirectory() as td:
            btmp_path = Path(td) / "btmp"
            btmp_path.write_bytes(b"\x00" * (UTMP_SIZE * 2))

            mon, _alert = self._monitor([str(btmp_path)])
            called = {"count": 0}

            def _fake_parse(_data, source):
                if source == str(btmp_path):
                    called["count"] += 1

            mon._parse_utmp_record = _fake_parse  # type: ignore[assignment]
            mon.setup()

            self.assertGreaterEqual(called["count"], 1)


if __name__ == "__main__":
    unittest.main()
