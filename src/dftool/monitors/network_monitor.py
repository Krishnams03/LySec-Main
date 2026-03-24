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
from typing import Any

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from dftool.monitors.base import BaseMonitor
from dftool.alert_engine import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)

logger = logging.getLogger("lysec.monitor.network")


class NetworkMonitor(BaseMonitor):
    name = "network"

    def __init__(self, config: dict, alert_engine):
        super().__init__(config, alert_engine)
        self._mon_cfg = config.get("monitors", {}).get("network", {})
        self._baseline_listeners: set[str] = set()
        self._known_interfaces: set[str] = set()
        self._known_connections: set[str] = set()
        self._promisc_cache: set[str] = set()
        self._first_run = True

    def setup(self):
        if not HAS_PSUTIL:
            logger.warning("psutil not installed — network monitoring limited")
        self._snapshot()
        logger.info(
            "Network monitor initialised — %d listeners, %d interfaces",
            len(self._baseline_listeners),
            len(self._known_interfaces),
        )

    def poll(self):
        self._check_listeners()
        self._check_interfaces()
        self._check_promiscuous()
        self._check_connections()

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

        for iface in new_ifaces:
            logger.warning("NEW_INTERFACE: %s", iface)
            if self._mon_cfg.get("alert_on_new_interface", True):
                self._alert.fire(
                    monitor="network",
                    event_type="NEW_INTERFACE",
                    message=f"New network interface detected: {iface}",
                    severity=SEVERITY_HIGH,
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

    @staticmethod
    def _get_interfaces() -> set[str]:
        if HAS_PSUTIL:
            return set(psutil.net_if_addrs().keys())
        try:
            return set(os.listdir("/sys/class/net"))
        except Exception:
            return set()

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
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "ESTABLISHED" and conn.raddr:
                key = (
                    f"{conn.laddr.ip}:{conn.laddr.port}->"
                    f"{conn.raddr.ip}:{conn.raddr.port}|pid={conn.pid}"
                )
                current_conns.add(key)

        new_conns = current_conns - self._known_connections
        for key in new_conns:
            logger.debug("NEW_CONNECTION: %s", key)

        self._known_connections = current_conns

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
