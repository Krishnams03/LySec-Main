import unittest
from unittest.mock import patch
import struct

from lysec.monitors.process_monitor import ProcessMonitor


class _DummyAlert:
    def __init__(self):
        self.events = []

    def fire(self, **kwargs):
        self.events.append(kwargs)


class ProcessMonitorTests(unittest.TestCase):
    def _monitor(self) -> tuple[ProcessMonitor, _DummyAlert]:
        alert = _DummyAlert()
        cfg = {
            "monitors": {
                "process": {
                    "fork_burst_threshold": 3,
                    "rare_process_threshold": 3,
                    "fork_burst_window_sec": 1.0,
                    "rare_process_window_sec": 1.0,
                }
            }
        }
        mon = ProcessMonitor(cfg, alert)
        return mon, alert

    def test_masquerade_detection_for_kernel_style_name(self):
        self.assertTrue(ProcessMonitor._is_masquerade("[kworker/u2:1]", "/tmp/evil"))

    def test_deleted_exe_detection(self):
        with patch("lysec.monitors.process_monitor.os.readlink", return_value="/tmp/a.out (deleted)"):
            self.assertTrue(ProcessMonitor._is_deleted_exe(123, ""))

    def test_suspicious_tree_detection(self):
        mon, _alert = self._monitor()
        mon._known_procs[100] = {"pid": 100, "name": "nginx", "ppid": 1}
        self.assertTrue(mon._is_suspicious_tree(100, "bash"))

    def test_fork_burst_emits_alert(self):
        mon, alert = self._monitor()
        base = {
            "pid": 200,
            "name": "bash",
            "ppid": 100,
            "cmdline": "bash",
            "exe": "/bin/bash",
        }
        mon._record_spawn(100, "bash")
        mon._record_spawn(100, "bash")
        mon._record_spawn(100, "bash")
        mon._check_spawn_bursts(100, "bash", base)

        event_types = [e.get("event_type") for e in alert.events]
        self.assertIn("PROCESS_FORK_BURST", event_types)

    def test_proc_connector_exec_parser(self):
        # Build one netlink message with cn_msg + proc_event(exec)
        what_exec = 0x00000002
        proc_ev = struct.pack("IIQII", what_exec, 0, 0, 4321, 4321)
        cn_msg = struct.pack("IIIIHH", 1, 1, 0, 0, len(proc_ev), 0)
        body = cn_msg + proc_ev
        nl_len = 16 + len(body)
        nl_hdr = struct.pack("IHHII", nl_len, 0x3, 0, 0, 0)
        payload = nl_hdr + body

        events = ProcessMonitor._parse_proc_connector_messages(payload)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["what"], "exec")
        self.assertEqual(events[0]["pid"], 4321)

    def test_invalid_event_source_defaults_to_poll(self):
        alert = _DummyAlert()
        cfg = {"monitors": {"process": {"event_source": "unknown", "use_proc_connector": False}}}
        mon = ProcessMonitor(cfg, alert)
        self.assertEqual(mon._select_event_source(), "poll")

    def test_ebpf_fallback_emits_degraded_alert(self):
        alert = _DummyAlert()
        cfg = {
            "monitors": {
                "process": {
                    "event_source": "ebpf",
                    "use_ebpf": True,
                    "use_proc_connector": False,
                }
            }
        }
        mon = ProcessMonitor(cfg, alert)
        self.assertEqual(mon._select_event_source(), "poll")
        event_types = [e.get("event_type") for e in alert.events]
        self.assertIn("PROCESS_EVENT_SOURCE_DEGRADED", event_types)

    def test_handle_ebpf_shortlived_event(self):
        mon, alert = self._monitor()

        class _FakeEbpf:
            def poll_events(self):
                return [{"what": "exec", "pid": 98765, "comm": "bash", "filename": "/bin/bash", "uid": 1000}]

        mon._ebpf_adapter = _FakeEbpf()
        handled = mon._handle_ebpf_events(current={})
        self.assertEqual(handled, set())
        event_types = [e.get("event_type") for e in alert.events]
        self.assertIn("PROCESS_SHORTLIVED_EVENT", event_types)


if __name__ == "__main__":
    unittest.main()
