"""
connectors/ssh_connector.py
Connects to real network devices via SSH and pulls read-only data.

Supported platforms:
    Cisco IOS / IOS-XE     — show log, show arp, show ip route, show interfaces
    Cisco ASA              — show log, show arp, show route, show interface
    Juniper JunOS          — show log messages, show arp, show route, show interfaces
    Palo Alto PAN-OS       — show log traffic, show arp, show routing route

All commands are READ-ONLY. We never change device configuration.

Usage:
    conn = SSHConnector("192.168.1.1", "admin", "cisco", device_type="cisco_ios")
    if conn.connect():
        logs = conn.get_logs()
        topology = conn.get_topology()
        routes = conn.get_routes()
        conn.disconnect()
"""

import logging
import time
import re
from typing import List, Dict, Optional
from app.models.schemas import LogEntry
from connectors.base import BaseConnector

logger = logging.getLogger(__name__)

# ── Per-platform command mappings ─────────────────────────
# Each platform uses different CLI syntax for the same data
PLATFORM_COMMANDS = {
    "cisco_ios": {
        "logs": "show log",
        "arp": "show arp",
        "routes": "show ip route",
        "interfaces": "show interfaces",
    },
    "cisco_xe": {
        "logs": "show log",
        "arp": "show arp",
        "routes": "show ip route",
        "interfaces": "show interfaces",
    },
    "cisco_asa": {
        "logs": "show log",
        "arp": "show arp",
        "routes": "show route",
        "interfaces": "show interface",
    },
    "juniper": {
        "logs": "show log messages",
        "arp": "show arp no-resolve",
        "routes": "show route",
        "interfaces": "show interfaces terse",
    },
    "juniper_junos": {
        "logs": "show log messages",
        "arp": "show arp no-resolve",
        "routes": "show route",
        "interfaces": "show interfaces terse",
    },
    "paloalto_panos": {
        "logs": "show log traffic direction equal backward",
        "arp": "show arp all",
        "routes": "show routing route",
        "interfaces": "show interface all",
    },
}


class SSHConnector(BaseConnector):
    """
    SSH connector for multi-vendor network devices.
    Uses Netmiko for SSH transport and command execution.
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
        self.host = host
        self.username = username
        self.password = password
        self.device_type = device_type
        self.port = port
        self.enable_password = enable_password

        self._connection = None
        self._connected = False
        self._last_error = ""
        self._commands = PLATFORM_COMMANDS.get(device_type, PLATFORM_COMMANDS["cisco_ios"])

    def connect(self) -> bool:
        """Establish SSH connection."""
        try:
            from netmiko import ConnectHandler
        except ImportError:
            self._last_error = (
                "Netmiko not installed. Run: pip install netmiko\n"
                "This is required for SSH device connections."
            )
            logger.error(self._last_error)
            return False

        try:
            device_config = {
                'device_type': self.device_type,
                'host': self.host,
                'username': self.username,
                'password': self.password,
                'port': self.port,
                'timeout': 15,
                'conn_timeout': 15,
                'banner_timeout': 15,
            }

            if self.enable_password:
                device_config['secret'] = self.enable_password

            logger.info(f"SSH connecting to {self.host}:{self.port} ({self.device_type})...")
            self._connection = ConnectHandler(**device_config)

            if self.enable_password:
                self._connection.enable()

            self._connected = True
            self._last_error = ""
            logger.info(f"SSH connected to {self.host}")
            return True

        except Exception as e:
            self._last_error = f"SSH connection failed to {self.host}:{self.port}: {e}"
            logger.error(self._last_error)
            self._connected = False
            return False

    def get_logs(self, since: float = 0, limit: int = 500) -> List[LogEntry]:
        """
        Fetch security logs from the device.
        Dispatches to platform-specific parser.
        """
        if not self._connected:
            self._last_error = "Not connected"
            return []

        try:
            cmd = self._commands["logs"]
            raw = self._connection.send_command(cmd, read_timeout=30)

            if self.device_type in ("cisco_ios", "cisco_xe", "cisco_asa"):
                logs = self._parse_cisco_logs(raw, limit)
            elif self.device_type in ("juniper", "juniper_junos"):
                logs = self._parse_juniper_logs(raw, limit)
            elif self.device_type == "paloalto_panos":
                logs = self._parse_panos_logs(raw, limit)
            else:
                logs = self._parse_cisco_logs(raw, limit)

            # Filter by timestamp
            if since > 0:
                logs = [l for l in logs if l.timestamp > since]

            logger.info(f"Parsed {len(logs)} logs from {self.host}")
            return logs

        except Exception as e:
            self._last_error = f"Failed to get logs from {self.host}: {e}"
            logger.error(self._last_error)
            return []

    def get_topology(self) -> List[Dict]:
        """Get network topology from ARP table."""
        if not self._connected:
            return []

        try:
            cmd = self._commands["arp"]
            raw = self._connection.send_command(cmd, read_timeout=15)

            if self.device_type in ("juniper", "juniper_junos"):
                return self._parse_juniper_arp(raw)
            elif self.device_type == "paloalto_panos":
                return self._parse_panos_arp(raw)
            else:
                return self._parse_cisco_arp(raw)

        except Exception as e:
            self._last_error = f"Failed to get topology from {self.host}: {e}"
            logger.error(self._last_error)
            return []

    def get_routes(self) -> List[Dict]:
        """Get routing table."""
        if not self._connected:
            return []

        try:
            cmd = self._commands["routes"]
            raw = self._connection.send_command(cmd, read_timeout=15)
            return self._parse_routes(raw)
        except Exception as e:
            self._last_error = f"Failed to get routes from {self.host}: {e}"
            logger.error(self._last_error)
            return []

    def get_interface_stats(self) -> Dict:
        """Get traffic counters per interface."""
        if not self._connected:
            return {}

        try:
            cmd = self._commands["interfaces"]
            raw = self._connection.send_command(cmd, read_timeout=15)
            return self._parse_interfaces(raw)
        except Exception as e:
            self._last_error = f"Failed to get interfaces: {e}"
            logger.error(self._last_error)
            return {}

    def disconnect(self) -> None:
        """Close SSH connection."""
        if self._connection:
            try:
                self._connection.disconnect()
            except Exception:
                pass
        self._connected = False
        logger.info(f"SSH disconnected from {self.host}")

    def is_connected(self) -> bool:
        return self._connected

    def get_last_error(self) -> str:
        return self._last_error

    # ══════════════════════════════════════════════════════
    # CISCO IOS / IOS-XE / ASA PARSERS
    # ══════════════════════════════════════════════════════

    def _parse_cisco_logs(self, raw: str, limit: int = 500) -> List[LogEntry]:
        """
        Parse Cisco "show log" output.

        Matches:
            %SEC-6-IPACCESSLOGP: list 101 denied tcp 192.168.1.5(54321) -> 192.168.1.1(22)
            %SEC_LOGIN-5-LOGIN_FAILED: ...
        Also extracts timestamps from Cisco log format:
            *Mar 11 10:00:01.123: %SEC-...
        """
        logs = []
        now = time.time()

        # ACL log pattern: denied/permitted proto src(port) -> dst(port)
        acl_pattern = re.compile(
            r'(?:denied|permitted)\s+(\w+)\s+'
            r'([\d.]+)\((\d+)\)\s*(?:->|→)\s*([\d.]+)\((\d+)\)',
            re.IGNORECASE,
        )

        # Timestamp pattern: *Mar 11 10:00:01 or Mar 11 10:00:01
        ts_pattern = re.compile(
            r'\*?(\w{3}\s+\d+\s+\d+:\d+:\d+)'
        )

        for line in raw.strip().split('\n'):
            if len(logs) >= limit:
                break

            # Extract timestamp
            ts_match = ts_pattern.search(line)
            timestamp = self._parse_cisco_timestamp(ts_match.group(1)) if ts_match else now

            # ACL entries
            acl_match = acl_pattern.search(line)
            if acl_match:
                action = "DENY" if "denied" in line.lower() else "ALLOW"
                logs.append(LogEntry(
                    timestamp=timestamp,
                    src_ip=acl_match.group(2),
                    dst_ip=acl_match.group(4),
                    src_port=int(acl_match.group(3)),
                    dst_port=int(acl_match.group(5)),
                    protocol=acl_match.group(1).upper(),
                    action=action,
                    segment=f"device_{self.host}",
                ))
                continue

            # Login failures
            if 'LOGIN_FAILED' in line or 'AUTHEN' in line:
                ip = self._extract_ip(line)
                if ip:
                    logs.append(LogEntry(
                        timestamp=timestamp,
                        src_ip=ip,
                        dst_ip=self.host,
                        dst_port=22,
                        protocol="SSH",
                        action="DENY",
                        segment=f"device_{self.host}",
                    ))

            # Interface state changes
            if '%LINK-' in line or '%LINEPROTO-' in line:
                logs.append(LogEntry(
                    timestamp=timestamp,
                    src_ip=self.host,
                    dst_ip=self.host,
                    protocol="SYSTEM",
                    action="ALLOW",
                    segment=f"device_{self.host}",
                ))

        return logs

    def _parse_cisco_arp(self, raw: str) -> List[Dict]:
        """Parse Cisco "show arp" output."""
        devices = []
        # Internet  192.168.1.5  10  0050.7966.6800  ARPA  Gi0/0
        pattern = re.compile(
            r'Internet\s+([\d.]+)\s+(\d+|-)\s+'
            r'([0-9a-fA-F.]+)\s+ARPA\s+(\S+)'
        )
        for line in raw.strip().split('\n'):
            match = pattern.search(line)
            if match:
                devices.append({
                    'ip': match.group(1),
                    'age_min': match.group(2),
                    'mac': match.group(3),
                    'interface': match.group(4),
                    'source': f"arp_{self.host}",
                })
        return devices

    # ══════════════════════════════════════════════════════
    # JUNIPER JUNOS PARSERS
    # ══════════════════════════════════════════════════════

    def _parse_juniper_logs(self, raw: str, limit: int = 500) -> List[LogEntry]:
        """
        Parse Juniper "show log messages" output.

        Example:
            Mar 11 10:00:01 router RT_FLOW: FLOW_SESSION_DENY 192.168.1.5/54321->192.168.1.1/22
        """
        logs = []
        now = time.time()

        # Juniper flow log pattern
        flow_pattern = re.compile(
            r'([\d.]+)/(\d+)\s*->\s*([\d.]+)/(\d+)\s+'
            r'(?:\S+\s+)?(\w+)',
            re.IGNORECASE,
        )
        ts_pattern = re.compile(r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)')

        for line in raw.strip().split('\n'):
            if len(logs) >= limit:
                break

            ts_match = ts_pattern.match(line)
            timestamp = self._parse_cisco_timestamp(ts_match.group(1)) if ts_match else now

            flow_match = flow_pattern.search(line)
            if flow_match:
                action = "DENY" if any(
                    x in line.upper() for x in ['DENY', 'DROP', 'REJECT', 'DISCARD']
                ) else "ALLOW"

                logs.append(LogEntry(
                    timestamp=timestamp,
                    src_ip=flow_match.group(1),
                    src_port=int(flow_match.group(2)),
                    dst_ip=flow_match.group(3),
                    dst_port=int(flow_match.group(4)),
                    protocol=flow_match.group(5).upper(),
                    action=action,
                    segment=f"device_{self.host}",
                ))

        return logs

    def _parse_juniper_arp(self, raw: str) -> List[Dict]:
        """Parse Juniper "show arp no-resolve" output."""
        devices = []
        # MAC Address       Address         Interface         Flags
        # 00:50:79:66:68:00 192.168.1.5     ge-0/0/0.0        none
        pattern = re.compile(
            r'([0-9a-fA-F:]+)\s+([\d.]+)\s+(\S+)'
        )
        for line in raw.strip().split('\n'):
            match = pattern.search(line)
            if match and not line.strip().startswith('MAC'):
                devices.append({
                    'ip': match.group(2),
                    'mac': match.group(1),
                    'interface': match.group(3),
                    'source': f"arp_{self.host}",
                })
        return devices

    # ══════════════════════════════════════════════════════
    # PALO ALTO PAN-OS PARSERS
    # ══════════════════════════════════════════════════════

    def _parse_panos_logs(self, raw: str, limit: int = 500) -> List[LogEntry]:
        """
        Parse Palo Alto "show log traffic" output.

        PAN-OS traffic logs are CSV-like with fields:
            src, dst, sport, dport, proto, action, bytes, ...
        """
        logs = []
        now = time.time()

        # PAN-OS log pattern — comma or space separated fields with IPs and ports
        ip_pair_pattern = re.compile(
            r'([\d.]+)\s+(?:→|->|to)\s+([\d.]+)'
        )

        for line in raw.strip().split('\n'):
            if len(logs) >= limit:
                break

            match = ip_pair_pattern.search(line)
            if match:
                action = "DENY" if any(
                    x in line.upper() for x in ['DENY', 'DROP', 'BLOCK', 'RESET']
                ) else "ALLOW"

                # Try to extract ports
                port_match = re.search(r'/(\d+)\s.*?/(\d+)', line)
                src_port = int(port_match.group(1)) if port_match else 0
                dst_port = int(port_match.group(2)) if port_match else 0

                logs.append(LogEntry(
                    timestamp=now,
                    src_ip=match.group(1),
                    dst_ip=match.group(2),
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol="TCP",
                    action=action,
                    segment=f"device_{self.host}",
                ))

        return logs

    def _parse_panos_arp(self, raw: str) -> List[Dict]:
        """Parse Palo Alto "show arp all" output."""
        devices = []
        pattern = re.compile(
            r'([\d.]+)\s+([0-9a-fA-F:]+)\s+\S+\s+(\S+)'
        )
        for line in raw.strip().split('\n'):
            match = pattern.search(line)
            if match:
                devices.append({
                    'ip': match.group(1),
                    'mac': match.group(2),
                    'interface': match.group(3),
                    'source': f"arp_{self.host}",
                })
        return devices

    # ══════════════════════════════════════════════════════
    # SHARED PARSERS
    # ══════════════════════════════════════════════════════

    def _parse_routes(self, raw: str) -> List[Dict]:
        """Parse routing table (works for Cisco and similar)."""
        routes = []
        route_pattern = re.compile(
            r'([CSROBDL\*])\s+([\d.]+(?:/\d+)?)\s+.*?'
            r'(?:via\s+([\d.]+)|directly connected).*?(\S+)\s*$'
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

    def _parse_interfaces(self, raw: str) -> Dict:
        """Parse interface status and traffic counters."""
        stats = {}
        current_iface = None

        for line in raw.strip().split('\n'):
            iface_match = re.match(r'^(\S+)\s+is\s+(up|down|administratively)', line)
            if iface_match:
                current_iface = iface_match.group(1)
                status = 'up' if 'up' in iface_match.group(2) else 'down'
                stats[current_iface] = {
                    'status': status,
                    'packets_in': 0,
                    'packets_out': 0,
                    'errors_in': 0,
                    'errors_out': 0,
                }

            if current_iface and current_iface in stats:
                for pattern, key in [
                    (r'(\d+) packets input', 'packets_in'),
                    (r'(\d+) packets output', 'packets_out'),
                    (r'(\d+) input errors', 'errors_in'),
                    (r'(\d+) output errors', 'errors_out'),
                ]:
                    match = re.search(pattern, line)
                    if match:
                        stats[current_iface][key] = int(match.group(1))

        return stats

    # ══════════════════════════════════════════════════════
    # HELPERS
    # ══════════════════════════════════════════════════════

    @staticmethod
    def _parse_cisco_timestamp(ts_str: str) -> float:
        """Parse Cisco/syslog timestamp: 'Mar 11 10:00:01' → Unix timestamp."""
        import datetime
        try:
            dt = datetime.datetime.strptime(ts_str.strip(), "%b %d %H:%M:%S")
            dt = dt.replace(year=datetime.datetime.now().year)
            return dt.timestamp()
        except (ValueError, AttributeError):
            return time.time()

    @staticmethod
    def _extract_ip(line: str) -> Optional[str]:
        """Extract first IP address from a log line."""
        match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        return match.group(1) if match else None