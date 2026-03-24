import struct
import unittest
from unittest.mock import mock_open, patch

from lysec.monitors.network_monitor import (
    NetworkMonitor,
    RTM_NEWADDR,
    RTM_NEWLINK,
    RTM_NEWNEIGH,
    RTM_NEWROUTE,
)


class _DummyAlert:
    def __init__(self):
        self.events = []

    def fire(self, **kwargs):
        self.events.append(kwargs)


class _NetworkMonitorUnderTest(NetworkMonitor):
    def __init__(self, config: dict, alert):
        self._test_alert = alert
        super().__init__(config, alert)

    def _get_listeners(self) -> list[dict]:
        return []

    @staticmethod
    def _get_interfaces() -> set[str]:
        return set()


class _FakeNetlinkSocket:
    def __init__(self, payloads):
        self._payloads = list(payloads)

    def recv(self, _size):
        if not self._payloads:
            raise BlockingIOError()
        next_payload = self._payloads.pop(0)
        if isinstance(next_payload, BaseException):
            raise next_payload
        return next_payload


def _nlmsg(msg_type: int) -> bytes:
    # Netlink header only: len, type, flags, seq, pid
    return struct.pack("IHHII", 16, msg_type, 0, 0, 0)


class NetworkMonitorTests(unittest.TestCase):
    def _monitor(self, config_overrides: dict | None = None) -> NetworkMonitor:
        config = {
            "monitors": {
                "network": {
                    "use_netlink": True,
                    "alert_on_default_route_change": True,
                    "alert_on_arp_change": True,
                }
            },
            "alerts": {},
        }
        if config_overrides:
            if "monitors" in config_overrides and "network" in config_overrides["monitors"]:
                config["monitors"]["network"].update(config_overrides["monitors"]["network"])
            if "alerts" in config_overrides:
                config["alerts"].update(config_overrides["alerts"])
        self._alert = _DummyAlert()
        return _NetworkMonitorUnderTest(config, self._alert)

    def test_hex_to_ipv4_conversion(self):
        self.assertEqual(NetworkMonitor._hex_to_ipv4("0101A8C0"), "192.168.1.1")

    def test_get_default_route_parses_proc_net_route(self):
        mon = self._monitor()
        content = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
        )
        with patch("lysec.monitors.network_monitor.os.path.isfile", return_value=True), patch(
            "builtins.open", mock_open(read_data=content)
        ):
            route = mon._get_default_route()

        self.assertEqual(route.get("iface"), "eth0")
        self.assertEqual(route.get("gateway"), "192.168.1.1")
        self.assertEqual(route.get("metric"), 100)

    def test_read_arp_table_filters_invalid_rows(self):
        content = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n"
            "192.168.1.2      0x1         0x2         00:00:00:00:00:00     *        eth0\n"
            "192.168.1.3      0x1         0x0         incomplete             *        eth0\n"
        )
        with patch("lysec.monitors.network_monitor.os.path.isfile", return_value=True), patch(
            "builtins.open", mock_open(read_data=content)
        ):
            table = NetworkMonitor._read_arp_table()

        self.assertEqual(table, {"192.168.1.1": "aa:bb:cc:dd:ee:ff"})

    def test_drain_netlink_events_classifies_groups(self):
        mon = self._monitor()
        payload = b"".join(
            [
                _nlmsg(RTM_NEWROUTE),
                _nlmsg(RTM_NEWNEIGH),
                _nlmsg(RTM_NEWLINK),
                _nlmsg(RTM_NEWADDR),
            ]
        )
        mon._netlink_sock = _FakeNetlinkSocket([payload])

        events = mon._drain_netlink_events()
        self.assertEqual(events, {"route", "neigh", "link", "addr"})

    def test_default_route_change_emits_interception_alert(self):
        mon = self._monitor()
        mon._default_route = {
            "iface": "wlan0",
            "gateway": "192.168.1.1",
            "metric": 100,
            "flags": "0003",
        }
        mon._last_new_interfaces = {"eth0"}
        mon._get_default_route = lambda: {
            "iface": "eth0",
            "gateway": "10.0.0.1",
            "metric": 50,
            "flags": "0003",
        }

        mon._check_default_route()

        self.assertEqual(len(self._alert.events), 1)
        evt = self._alert.events[0]
        self.assertEqual(evt["event_type"], "DEFAULT_ROUTE_CHANGED")
        self.assertTrue(evt["details"]["potential_interception"])

    def test_default_route_imposter_uses_configured_severity(self):
        mon = self._monitor(
            {
                "alerts": {
                    "severity_policy": {
                        "network_event_severity": {
                            "DEFAULT_ROUTE_IMPOSTER": "CRITICAL",
                            "DEFAULT_ROUTE_CHANGED": "MEDIUM",
                        }
                    }
                }
            }
        )
        mon._default_route = {
            "iface": "wlan0",
            "gateway": "192.168.1.1",
            "metric": 100,
            "flags": "0003",
        }
        mon._last_new_interfaces = {"eth0"}
        mon._get_default_route = lambda: {
            "iface": "eth0",
            "gateway": "10.0.0.1",
            "metric": 50,
            "flags": "0003",
        }

        mon._check_default_route()

        self.assertEqual(self._alert.events[0]["severity"], "CRITICAL")

    def test_arp_mapping_change_emits_alert(self):
        mon = self._monitor()
        mon._arp_table = {"192.168.1.1": "aa:aa:aa:aa:aa:aa"}
        mon._read_arp_table = lambda: {"192.168.1.1": "bb:bb:bb:bb:bb:bb"}

        mon._check_arp_integrity()

        self.assertEqual(len(self._alert.events), 1)
        evt = self._alert.events[0]
        self.assertEqual(evt["event_type"], "ARP_MAPPING_CHANGED")
        self.assertEqual(evt["details"]["old_mac"], "aa:aa:aa:aa:aa:aa")
        self.assertEqual(evt["details"]["new_mac"], "bb:bb:bb:bb:bb:bb")


if __name__ == "__main__":
    unittest.main()
