"""
app/connectors/ssh_connector.py
Connects to real network devices (Cisco, Juniper, etc) via SSH.

Uses Netmiko library — the standard tool for network automation.

What it does:
    1. SSH into the device
    2. Run "show" commands (read-only, safe)
    3. Parse the text output into LogEntry objects
    4. Feed to engine

Commands we run:
    show log          → security events (DENY, errors)
    show arp          → who's on the network (IP ↔ MAC)
    show ip route     → how traffic flows
    show interfaces   → traffic counters per port
    
All commands are READ-ONLY. We never change device config.
"""

import time
import re
from typing import List, Dict, Optional
from app.models.schemas import LogEntry
from connectors.base import BaseConnector


class SSHConnector(BaseConnector):
    """
    SSH connector for Cisco IOS / IOS-XE devices.
    Also works with: Juniper, Arista, Palo Alto (change device_type).
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        device_type: str = "cisco_ios",
        port: int = 22,
        enable_password: str = None,
    ):
        """
        Args:
            host: IP address of the device (e.g., "192.168.1.1")
            username: SSH username
            password: SSH password
            device_type: Netmiko device type
                "cisco_ios"     → Cisco IOS routers/switches
                "cisco_xe"      → Cisco IOS-XE (newer)
                "cisco_asa"     → Cisco ASA firewalls
                "juniper"       → Juniper JunOS
                "paloalto_panos" → Palo Alto firewalls
            port: SSH port (default 22)
            enable_password: Cisco enable password (if needed)
        """
        self.host = host
        self.username = username
        self.password = password
        self.device_type = device_type
        self.port = port
        self.enable_password = enable_password

        self._connection = None
        self._connected = False

    def connect(self) -> bool:
        """
        Establish SSH connection to the device.
        """
        try:
            from netmiko import ConnectHandler

            device_config = {
                'device_type': self.device_type,
                'host': self.host,
                'username': self.username,
                'password': self.password,
                'port': self.port,
                'timeout': 10,
                'conn_timeout': 10,
            }

            if self.enable_password:
                device_config['secret'] = self.enable_password

            self._connection = ConnectHandler(**device_config)

            # Enter enable mode if needed (Cisco privilege level 15)
            if self.enable_password:
                self._connection.enable()

            self._connected = True
            return True

        except ImportError:
            print("Netmiko not installed. Run: pip install netmiko")
            return False
        except Exception as e:
            print(f"SSH connection failed to {self.host}: {e}")
            self._connected = False
            return False

    def get_logs(
        self,
        since: float = 0,
        limit: int = 100,
    ) -> List[LogEntry]:
        """
        Fetch security logs from the device.
        
        Runs "show log" and parses DENY/permit entries
        into LogEntry objects.
        
        Example Cisco log line:
        *Mar 11 10:00:01: %SEC-6-IPACCESSLOGP: list 101 denied tcp 
            192.168.1.5(54321) -> 192.168.1.1(22), 3 packets
        """
        if not self._connected:
            return []

        try:
            raw_output = self._connection.send_command("show log")
            return self._parse_cisco_logs(raw_output, limit)
        except Exception as e:
            print(f"Failed to get logs from {self.host}: {e}")
            return []

    def get_topology(self) -> List[Dict]:
        """
        Get network topology from ARP table.
        
        Runs "show arp" and parses into device list.
        
        Example Cisco ARP output:
        Protocol  Address      Age  Hardware Addr   Type  Interface
        Internet  192.168.1.5  10   0050.7966.6800  ARPA  Gi0/0
        """
        if not self._connected:
            return []

        try:
            raw_output = self._connection.send_command("show arp")
            return self._parse_arp_table(raw_output)
        except Exception as e:
            print(f"Failed to get topology from {self.host}: {e}")
            return []

    def get_interface_stats(self) -> Dict:
        """
        Get traffic counters per interface.
        Useful for detecting traffic spikes.
        """
        if not self._connected:
            return {}

        try:
            raw_output = self._connection.send_command("show interfaces")
            return self._parse_interfaces(raw_output)
        except Exception as e:
            print(f"Failed to get interfaces from {self.host}: {e}")
            return {}

    def get_routes(self) -> List[Dict]:
        """
        Get routing table.
        Useful for understanding network segmentation.
        """
        if not self._connected:
            return []

        try:
            raw_output = self._connection.send_command("show ip route")
            return self._parse_routes(raw_output)
        except Exception as e:
            print(f"Failed to get routes from {self.host}: {e}")
            return []

    def disconnect(self) -> None:
        """Close SSH connection."""
        if self._connection:
            try:
                self._connection.disconnect()
            except Exception:
                pass
        self._connected = False

    def is_connected(self) -> bool:
        return self._connected

    # ── Parsers ──────────────────────────────────────────

    def _parse_cisco_logs(
        self,
        raw: str,
        limit: int = 100,
    ) -> List[LogEntry]:
        """
        Parse Cisco "show log" output into LogEntry objects.
        
        Patterns we look for:
        1. ACL deny: %SEC-6-IPACCESSLOGP: list X denied proto src → dst
        2. ACL permit: %SEC-6-IPACCESSLOGP: list X permitted ...
        3. Login failure: %SEC_LOGIN-5-LOGIN_FAILED
        4. Interface up/down: %LINK-3-UPDOWN
        """
        logs = []
        now = time.time()

        # Pattern: denied/permitted tcp/udp src(port) -> dst(port)
        acl_pattern = re.compile(
            r'(?:denied|permitted)\s+(\w+)\s+'
            r'([\d.]+)\((\d+)\)\s*->\s*([\d.]+)\((\d+)\)',
            re.IGNORECASE,
        )

        for line in raw.strip().split('\n'):
            if len(logs) >= limit:
                break

            match = acl_pattern.search(line)
            if match:
                protocol = match.group(1).upper()
                src_ip = match.group(2)
                src_port = int(match.group(3))
                dst_ip = match.group(4)
                dst_port = int(match.group(5))

                action = "DENY" if "denied" in line.lower() else "ALLOW"

                logs.append(LogEntry(
                    timestamp=now,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    action=action,
                    segment=f"device_{self.host}",
                ))

            # Login failures (brute force detection)
            elif 'LOGIN_FAILED' in line:
                logs.append(LogEntry(
                    timestamp=now,
                    src_ip=self._extract_ip(line) or "unknown",
                    dst_ip=self.host,
                    dst_port=22,
                    protocol="SSH",
                    action="DENY",
                    segment=f"device_{self.host}",
                ))

        return logs

    def _parse_arp_table(self, raw: str) -> List[Dict]:
        """
        Parse "show arp" output.
        
        Returns list of devices seen on the network.
        Each entry = one IP/MAC pair = one device.
        """
        devices = []

        # Pattern: Internet 192.168.1.5 10 0050.7966.6800 ARPA Gi0/0
        arp_pattern = re.compile(
            r'Internet\s+([\d.]+)\s+(\d+|-)\s+'
            r'([0-9a-fA-F.]+)\s+ARPA\s+(\S+)'
        )

        for line in raw.strip().split('\n'):
            match = arp_pattern.search(line)
            if match:
                devices.append({
                    'ip': match.group(1),
                    'age_min': match.group(2),
                    'mac': match.group(3),
                    'interface': match.group(4),
                    'source': f"arp_{self.host}",
                })

        return devices

    def _parse_interfaces(self, raw: str) -> Dict:
        """Parse "show interfaces" for traffic counters."""
        stats = {}
        current_iface = None

        for line in raw.strip().split('\n'):
            # Interface header: "GigabitEthernet0/0 is up, line protocol is up"
            iface_match = re.match(r'^(\S+) is (up|down)', line)
            if iface_match:
                current_iface = iface_match.group(1)
                stats[current_iface] = {
                    'status': iface_match.group(2),
                    'packets_in': 0,
                    'packets_out': 0,
                }

            # Packet counters
            if current_iface:
                in_match = re.search(r'(\d+) packets input', line)
                out_match = re.search(r'(\d+) packets output', line)
                if in_match:
                    stats[current_iface]['packets_in'] = int(in_match.group(1))
                if out_match:
                    stats[current_iface]['packets_out'] = int(out_match.group(1))

        return stats

    def _parse_routes(self, raw: str) -> List[Dict]:
        """Parse "show ip route" for routing table."""
        routes = []

        # Pattern: C 192.168.1.0/24 is directly connected, Gi0/0
        route_pattern = re.compile(
            r'([CSRO\*])\s+([\d.]+/\d+).*?(?:via\s+([\d.]+))?.*?(\S+)$'
        )

        for line in raw.strip().split('\n'):
            match = route_pattern.search(line)
            if match:
                routes.append({
                    'type': match.group(1),
                    'network': match.group(2),
                    'next_hop': match.group(3) or 'direct',
                    'interface': match.group(4),
                })

        return routes

    @staticmethod
    def _extract_ip(line: str) -> Optional[str]:
        """Extract first IP address from a log line."""
        match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        return match.group(1) if match else None

