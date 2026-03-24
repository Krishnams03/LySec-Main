"""
LySec - Network Monitor
Polls the network state using psutil and /proc/net to detect:
    * New listening sockets (unexpected services)
    * NIC in promiscuous mode (sniffing)
    * New network interfaces (rogue adapters)
    * Established connections to suspicious ports / IPs
    * ARP table changes

Forensic value:
    * Network-based lateral movement evidence.
    * Data exfiltration channel detection.
    * Rogue device / interface detection.

NOTE: Detection & Logging ONLY — no firewall rules, no connection killing.
"""

import logging
import os
import re
import socket
import struct
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

logger = logging.getLogger("lysec.monitor.network")


# Netlink constants (linux/rtnetlink.h)
NLMSG_HDRLEN = 16
RTM_NEWLINK = 16
RTM_DELLINK = 17
RTM_NEWADDR = 20
RTM_DELADDR = 21
RTM_NEWROUTE = 24
RTM_DELROUTE = 25
RTM_NEWNEIGH = 28
RTM_DELNEIGH = 29

RTMGRP_LINK = 0x1
RTMGRP_IPV4_IFADDR = 0x10
RTMGRP_IPV4_ROUTE = 0x40
RTMGRP_NEIGH = 0x4


class NetworkMonitor(BaseMonitor):
    name = "network"

    def __init__(self, config: dict, alert_engine):
        super().__init__(config, alert_engine)
        self._mon_cfg = config.get("monitors", {}).get("network", {})
        self._global_severity_policy = config.get("alerts", {}).get("severity_policy", {})
        self._network_event_severity = self._build_network_event_severity_map()
        self._alert_on_default_route_change = bool(
            self._mon_cfg.get("alert_on_default_route_change", True)
        )
        self._alert_on_arp_change = bool(self._mon_cfg.get("alert_on_arp_change", True))
        self._baseline_listeners: set[str] = set()
        self._known_interfaces: set[str] = set()
        self._last_new_interfaces: set[str] = set()
        self._known_connections: set[str] = set()
        self._connection_details: dict[str, dict[str, Any]] = {}
        self._default_route: dict[str, Any] = {}
        self._arp_table: dict[str, str] = {}
        self._promisc_cache: set[str] = set()
        self._netlink_enabled = bool(self._mon_cfg.get("use_netlink", True))
        self._netlink_sock: socket.socket | None = None
        self._first_run = True

    def setup(self):
        if not HAS_PSUTIL:
            logger.warning("psutil not installed — network monitoring limited")
        self._snapshot()
        if self._netlink_enabled:
            self._setup_netlink()
        logger.info(
            "Network monitor initialised — %d listeners, %d interfaces",
            len(self._baseline_listeners),
            len(self._known_interfaces),
        )

    def poll(self):
        netlink_events = self._drain_netlink_events() if self._netlink_sock else set()

        self._check_listeners()
        if (not netlink_events) or ({"link", "addr"} & netlink_events):
            self._check_interfaces()
        self._check_promiscuous()
        self._check_connections()
        if self._alert_on_default_route_change and ((not netlink_events) or ("route" in netlink_events)):
            self._check_default_route()
        if self._alert_on_arp_change and ((not netlink_events) or ("neigh" in netlink_events)):
            self._check_arp_integrity()

    def teardown(self):
        if self._netlink_sock:
            try:
                self._netlink_sock.close()
            except OSError:
                pass
            self._netlink_sock = None

    # ──────────────────────── Listeners ──────────────────────────────────
    def _check_listeners(self):
        current_listeners = self._get_listeners()
        current_set = {self._listener_key(c) for c in current_listeners}

        if self._first_run:
            self._baseline_listeners = current_set
            self._first_run = False
            return

        new_listeners = current_set - self._baseline_listeners

        for key in new_listeners:
            logger.warning("NEW_LISTENER: %s", key)
            if self._mon_cfg.get("alert_on_new_listener", True):
                self._alert.fire(
                    monitor="network",
                    event_type="NEW_LISTENER",
                    message=f"New listening socket detected: {key}",
                    severity=SEVERITY_HIGH,
                    details={"listener": key},
                )

        # Update baseline (listeners may legitimately come and go)
        self._baseline_listeners = current_set

    def _get_listeners(self) -> list[dict]:
        """Return list of listening sockets."""
        listeners = []
        if HAS_PSUTIL:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "LISTEN":
                    listeners.append({
                        "laddr": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "pid": conn.pid,
                        "family": str(conn.family),
                        "type": str(conn.type),
                    })
        else:
            listeners = self._parse_proc_net_tcp()
        return listeners

    @staticmethod
    def _listener_key(conn: dict) -> str:
        return f"{conn.get('laddr', '?')}|pid={conn.get('pid', '?')}"

    # ──────────────────────── Interfaces ────────────────────────────────
    def _check_interfaces(self):
        current = self._get_interfaces()
        new_ifaces = current - self._known_interfaces
        removed_ifaces = self._known_interfaces - current
        self._last_new_interfaces = set(new_ifaces)

        for iface in new_ifaces:
            logger.warning("NEW_INTERFACE: %s", iface)
            if self._mon_cfg.get("alert_on_new_interface", True):
                self._alert.fire(
                    monitor="network",
                    event_type="NEW_INTERFACE",
                    message=f"New network interface detected: {iface}",
                    severity=self._network_event_severity.get("NEW_INTERFACE", SEVERITY_HIGH),
                    details={"interface": iface},
                )

        for iface in removed_ifaces:
            logger.info("INTERFACE_REMOVED: %s", iface)
            self._alert.fire(
                monitor="network",
                event_type="INTERFACE_REMOVED",
                message=f"Network interface removed: {iface}",
                severity=SEVERITY_INFO,
                details={"interface": iface},
            )

        self._known_interfaces = current

    def _setup_netlink(self):
        """Subscribe to kernel routing notifications for low-latency topology updates."""
        try:
            sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
            groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_NEIGH
            sock.bind((0, groups))
            sock.setblocking(False)
            self._netlink_sock = sock
            logger.info("Network monitor netlink subscription enabled")
        except OSError as exc:
            self._netlink_sock = None
            logger.warning("Netlink subscription unavailable, using polling fallback: %s", exc)

    def _drain_netlink_events(self) -> set[str]:
        """Drain pending netlink messages and classify by event family."""
        if not self._netlink_sock:
            return set()

        events: set[str] = set()
        while True:
            try:
                payload = self._netlink_sock.recv(65535)
            except BlockingIOError:
                break
            except OSError:
                break

            offset = 0
            plen = len(payload)
            while offset + NLMSG_HDRLEN <= plen:
                hdr = payload[offset : offset + NLMSG_HDRLEN]
                msg_len, msg_type, _, _, _ = struct.unpack("IHHII", hdr)
                if msg_len < NLMSG_HDRLEN:
                    break

                if msg_type in (RTM_NEWROUTE, RTM_DELROUTE):
                    events.add("route")
                elif msg_type in (RTM_NEWNEIGH, RTM_DELNEIGH):
                    events.add("neigh")
                elif msg_type in (RTM_NEWADDR, RTM_DELADDR):
                    events.add("addr")
                elif msg_type in (RTM_NEWLINK, RTM_DELLINK):
                    events.add("link")

                # Netlink messages are 4-byte aligned.
                offset += (msg_len + 3) & ~3

        return events

    def _check_default_route(self):
        route = self._get_default_route()
        if not route:
            return

        if not self._default_route:
            self._default_route = route
            return

        if route == self._default_route:
            return

        potential_interception = route.get("iface") in self._last_new_interfaces
        severity = self._network_event_severity.get("DEFAULT_ROUTE_CHANGED", SEVERITY_HIGH)
        if potential_interception:
            severity = self._network_event_severity.get("DEFAULT_ROUTE_IMPOSTER", severity)

        self._alert.fire(
            monitor="network",
            event_type="DEFAULT_ROUTE_CHANGED",
            message="Default route changed on host",
            severity=severity,
            details={
                "old_default_route": self._default_route,
                "new_default_route": route,
                "potential_interception": potential_interception,
            },
        )
        self._default_route = route

    def _check_arp_integrity(self):
        table = self._read_arp_table()
        if not table:
            return

        if not self._arp_table:
            self._arp_table = table
            return

        for ip, mac in table.items():
            old_mac = self._arp_table.get(ip)
            if not old_mac or old_mac == mac:
                continue
            self._alert.fire(
                monitor="network",
                event_type="ARP_MAPPING_CHANGED",
                message=f"ARP mapping changed for {ip}: {old_mac} -> {mac}",
                severity=self._network_event_severity.get("ARP_MAPPING_CHANGED", SEVERITY_HIGH),
                details={
                    "ip": ip,
                    "old_mac": old_mac,
                    "new_mac": mac,
                },
            )

        self._arp_table = table

    @staticmethod
    def _get_interfaces() -> set[str]:
        if HAS_PSUTIL:
            return set(psutil.net_if_addrs().keys())
        try:
            return set(os.listdir("/sys/class/net"))
        except Exception:
            return set()

    @staticmethod
    def _hex_to_ipv4(hex_addr: str) -> str:
        try:
            raw = bytes.fromhex(hex_addr)
            return socket.inet_ntoa(raw[::-1])
        except Exception:
            return ""

    def _get_default_route(self) -> dict[str, Any]:
        route_file = "/proc/net/route"
        if not os.path.isfile(route_file):
            return {}

        try:
            with open(route_file, "r", encoding="utf-8", errors="replace") as fh:
                next(fh, None)
                for line in fh:
                    parts = line.strip().split()
                    if len(parts) < 8:
                        continue
                    iface, destination, gateway, flags, _, _, metric, mask = parts[:8]
                    if destination != "00000000":
                        continue
                    if mask not in ("00000000", "0"):
                        continue
                    gw_ip = self._hex_to_ipv4(gateway)
                    return {
                        "iface": iface,
                        "gateway": gw_ip,
                        "metric": int(metric),
                        "flags": flags,
                    }
        except Exception:
            return {}
        return {}

    @staticmethod
    def _read_arp_table() -> dict[str, str]:
        arp_file = "/proc/net/arp"
        if not os.path.isfile(arp_file):
            return {}

        out: dict[str, str] = {}
        try:
            with open(arp_file, "r", encoding="utf-8", errors="replace") as fh:
                next(fh, None)
                for line in fh:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    ip = parts[0]
                    mac = parts[3].lower()
                    if not ip or mac in ("00:00:00:00:00:00", "incomplete"):
                        continue
                    out[ip] = mac
        except Exception:
            return {}
        return out

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

    def _build_network_event_severity_map(self) -> dict[str, str]:
        base = {
            "NEW_INTERFACE": SEVERITY_HIGH,
            "PROMISCUOUS_MODE": SEVERITY_CRITICAL,
            "DEFAULT_ROUTE_CHANGED": SEVERITY_HIGH,
            "DEFAULT_ROUTE_IMPOSTER": SEVERITY_CRITICAL,
            "ARP_MAPPING_CHANGED": SEVERITY_HIGH,
        }
        cfg = self._global_severity_policy.get("network_event_severity", {})
        for key, value in cfg.items():
            map_key = str(key).strip().upper()
            base[map_key] = self._parse_severity(value, fallback=base.get(map_key, SEVERITY_MEDIUM))
        return base

    # ──────────────────────── Promiscuous mode ──────────────────────────
    def _check_promiscuous(self):
        promisc = set()
        for iface in self._get_interfaces():
            flags_path = f"/sys/class/net/{iface}/flags"
            try:
                with open(flags_path) as f:
                    flags = int(f.read().strip(), 16)
                if flags & 0x100:  # IFF_PROMISC
                    promisc.add(iface)
            except Exception:
                continue

        new_promisc = promisc - self._promisc_cache
        for iface in new_promisc:
            logger.critical("PROMISCUOUS_MODE: %s", iface)
            if self._mon_cfg.get("alert_on_promiscuous", True):
                self._alert.fire(
                    monitor="network",
                    event_type="PROMISCUOUS_MODE",
                    message=f"Interface {iface} entered promiscuous mode (possible sniffing)",
                    severity=SEVERITY_CRITICAL,
                    details={"interface": iface},
                )

        self._promisc_cache = promisc

    # ──────────────────────── Established connections ───────────────────
    def _check_connections(self):
        if not HAS_PSUTIL:
            return
        current_conns: set[str] = set()
        current_details: dict[str, dict[str, Any]] = {}
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "ESTABLISHED" and conn.raddr:
                key = (
                    f"{conn.laddr.ip}:{conn.laddr.port}->"
                    f"{conn.raddr.ip}:{conn.raddr.port}|pid={conn.pid}"
                )
                current_conns.add(key)
                detail: dict[str, Any] = {
                    "laddr": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "raddr": f"{conn.raddr.ip}:{conn.raddr.port}",
                    "ip": conn.raddr.ip,
                    "pid": conn.pid,
                    "status": conn.status,
                }
                if conn.pid and HAS_PSUTIL:
                    try:
                        proc = psutil.Process(conn.pid)
                        detail["process_name"] = proc.name()
                        detail["exe"] = proc.exe()
                        if detail.get("exe"):
                            detail["path"] = detail.get("exe")
                    except Exception:
                        pass
                current_details[key] = detail

        new_conns = current_conns - self._known_connections
        for key in new_conns:
            logger.info("NEW_CONNECTION: %s", key)
            if self._mon_cfg.get("alert_on_new_connection", True):
                details = current_details.get(key, {"connection": key})
                self._alert.fire(
                    monitor="network",
                    event_type="NEW_CONNECTION",
                    message=f"New established connection detected: {key}",
                    severity=SEVERITY_MEDIUM,
                    details=details,
                )

        self._known_connections = current_conns
        self._connection_details = current_details

    # ──────────────────────── /proc fallback ────────────────────────────
    @staticmethod
    def _parse_proc_net_tcp() -> list[dict]:
        """Parse /proc/net/tcp for listening sockets (fallback)."""
        listeners = []
        try:
            with open("/proc/net/tcp") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    state = parts[3]
                    if state == "0A":  # TCP_LISTEN
                        local = parts[1]
                        ip_hex, port_hex = local.split(":")
                        port = int(port_hex, 16)
                        ip_int = int(ip_hex, 16)
                        ip = socket.inet_ntoa(ip_int.to_bytes(4, "little"))
                        listeners.append({"laddr": f"{ip}:{port}", "pid": "?"})
        except Exception:
            pass
        return listeners

    # ──────────────────────── Snapshot ──────────────────────────────────
    def _snapshot(self):
        self._known_interfaces = self._get_interfaces()
        listeners = self._get_listeners()
        self._baseline_listeners = {self._listener_key(c) for c in listeners}
        self._default_route = self._get_default_route()
        self._arp_table = self._read_arp_table()

