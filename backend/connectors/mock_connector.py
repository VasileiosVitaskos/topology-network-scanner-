"""
connectors/mock_connector.py
Generates synthetic OT network logs for testing and demos.

No external dependencies — generates data in-process instead of
talking to a separate mock-api service (which didn't exist).

Usage:
    conn = MockConnector(scenario="normal")
    conn.connect()  # Always succeeds
    logs = conn.get_logs(limit=100)
"""

import logging
import random
import time
from typing import List, Dict

from app.models.schemas import LogEntry
from connectors.base import BaseConnector

logger = logging.getLogger(__name__)

# ── OT Network Segments ──────────────────────────────────
SEGMENTS = {
    "plc_network": {
        "hosts": ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"],
        "protocols": ["Modbus", "Ethernet/IP"],
    },
    "scada_network": {
        "hosts": ["192.168.2.20", "192.168.2.21"],
        "protocols": ["OPC-UA", "SMB"],
    },
    "workstation_vlan": {
        "hosts": ["192.168.3.50", "192.168.3.51", "192.168.3.52"],
        "protocols": ["HTTP", "DNS", "SSH"],
    },
    "dmz": {
        "hosts": ["10.0.0.5", "10.0.0.6"],
        "protocols": ["HTTPS", "DNS"],
    },
}

PROTO_PORT = {
    "HTTP": 80, "HTTPS": 443, "DNS": 53, "SSH": 22, "SMB": 445,
    "Modbus": 502, "OPC-UA": 4840, "Ethernet/IP": 44818,
    "RDP": 3389, "Telnet": 23, "SMTP": 25,
}


class MockConnector(BaseConnector):
    """
    Generates synthetic OT network logs in-process.
    Used for testing, demos, and development.
    """

    def __init__(self, scenario: str = "mixed"):
        """
        Args:
            scenario: "normal", "attack", or "mixed" (40% chance of attack)
        """
        self.scenario = scenario
        self._connected = False

    def connect(self) -> bool:
        self._connected = True
        return True

    def get_logs(self, since: float = 0, limit: int = 100) -> List[LogEntry]:
        """Generate synthetic logs."""
        if not self._connected:
            return []

        logs = []
        base_t = time.time() - limit

        # Decide if this batch has an attack
        inject_attack = (
            self.scenario == "attack"
            or (self.scenario == "mixed" and random.random() < 0.4)
        )

        if inject_attack:
            attack_logs = self._generate_attack(base_t + random.randint(10, max(11, limit - 10)))
            logs.extend(attack_logs)

        # Fill with normal traffic
        for i in range(limit - len(logs)):
            seg_name = random.choice(list(SEGMENTS.keys()))
            seg = SEGMENTS[seg_name]
            src = random.choice(seg["hosts"])
            dst = random.choice(seg["hosts"])

            # 20% chance of cross-segment traffic
            if random.random() < 0.2:
                other = random.choice(list(SEGMENTS.keys()))
                dst = random.choice(SEGMENTS[other]["hosts"])

            proto = random.choice(seg["protocols"])
            logs.append(LogEntry(
                timestamp=base_t + i,
                src_ip=src,
                dst_ip=dst,
                src_port=random.randint(49152, 65535),
                dst_port=PROTO_PORT.get(proto, random.randint(1024, 65535)),
                protocol=proto,
                action="ALLOW" if random.random() < 0.95 else "DENY",
                bytes_transferred=random.randint(64, 8192),
                duration=round(random.uniform(0.01, 2.0), 3),
                segment=seg_name,
            ))

        logs.sort(key=lambda x: x.timestamp)

        # Filter by since
        if since > 0:
            logs = [l for l in logs if l.timestamp > since]

        return logs[:limit]

    def get_topology(self) -> List[Dict]:
        """Return the synthetic topology."""
        devices = []
        for seg_name, seg in SEGMENTS.items():
            for ip in seg["hosts"]:
                devices.append({
                    "ip": ip,
                    "mac": "mock",
                    "segment": seg_name,
                    "source": "mock",
                })
        return devices

    def disconnect(self) -> None:
        self._connected = False

    def is_connected(self) -> bool:
        return self._connected

    @staticmethod
    def _generate_attack(t: float) -> List[LogEntry]:
        """Generate a random attack scenario."""
        scenario = random.choice(["lateral_movement", "modbus_injection", "port_scan"])

        if scenario == "lateral_movement":
            return [
                LogEntry(timestamp=t, src_ip="192.168.3.50", dst_ip="192.168.1.10",
                         src_port=random.randint(49152, 65535), dst_port=445,
                         protocol="SMB", action="ALLOW",
                         bytes_transferred=random.randint(1024, 32768),
                         segment="workstation_vlan>plc_network"),
                LogEntry(timestamp=t + 0.5, src_ip="192.168.3.50", dst_ip="192.168.1.11",
                         src_port=random.randint(49152, 65535), dst_port=445,
                         protocol="SMB", action="ALLOW",
                         bytes_transferred=random.randint(1024, 32768),
                         segment="workstation_vlan>plc_network"),
                LogEntry(timestamp=t + 1.0, src_ip="192.168.3.50", dst_ip="192.168.1.12",
                         src_port=random.randint(49152, 65535), dst_port=445,
                         protocol="SMB", action="DENY",
                         segment="workstation_vlan>plc_network"),
            ]
        elif scenario == "modbus_injection":
            return [
                LogEntry(timestamp=t, src_ip="10.0.0.5", dst_ip="192.168.1.10",
                         src_port=random.randint(49152, 65535), dst_port=502,
                         protocol="Modbus", action="ALLOW",
                         bytes_transferred=256, segment="dmz>plc_network"),
                LogEntry(timestamp=t + 2, src_ip="10.0.0.5", dst_ip="192.168.1.11",
                         src_port=random.randint(49152, 65535), dst_port=502,
                         protocol="Modbus", action="ALLOW",
                         bytes_transferred=256, segment="dmz>plc_network"),
            ]
        else:  # port_scan
            return [
                LogEntry(timestamp=t + i * 0.1, src_ip="192.168.3.51",
                         dst_ip="192.168.2.20",
                         src_port=random.randint(49152, 65535), dst_port=port,
                         protocol="TCP",
                         action=random.choice(["DENY", "DENY", "ALLOW"]),
                         bytes_transferred=64,
                         segment="workstation_vlan>scada_network")
                for i, port in enumerate([22, 23, 80, 443, 445, 502, 3389, 4840])
            ]