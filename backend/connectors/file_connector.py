"""
connectors/file_connector.py
Reads firewall/IDS log files and converts to LogEntry objects.

Supports:
    - CSV format (comma, semicolon, tab separated)
    - Syslog format (standard iptables/firewall text logs)
    - Palo Alto CSV export
    - Generic timestamp + src + dst + action format

Usage:
    conn = FileConnector("path/to/firewall_logs.csv")
    if conn.connect():
        logs = conn.get_logs()
        topology = conn.get_topology()
        conn.disconnect()
"""

import csv
import datetime
import logging
import re
import time
from pathlib import Path
from typing import List, Optional

from app.models.schemas import LogEntry
from connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class FileConnector(BaseConnector):
    """
    Reads log files from disk.
    Auto-detects format (CSV, syslog).
    """

    def __init__(self, file_path: str):
        """
        Args:
            file_path: path to log file or directory of log files
        """
        self.file_path = Path(file_path)
        self._logs: List[LogEntry] = []
        self._loaded = False
        self._last_error = ""

    def connect(self) -> bool:
        """Check that the file/directory exists."""
        if self.file_path.exists():
            self._loaded = False
            return True
        self._last_error = f"File not found: {self.file_path}"
        logger.warning(self._last_error)
        return False

    def get_logs(self, since: float = 0, limit: int = 100) -> List[LogEntry]:
        """Read and parse log file into LogEntry objects. Caches after first read."""
        if not self._loaded:
            self._load_file()

        filtered = [l for l in self._logs if l.timestamp > since]
        return filtered[:limit]

    def get_topology(self) -> List[dict]:
        """Extract unique IPs from logs as topology."""
        if not self._loaded:
            self._load_file()

        ips = set()
        for log in self._logs:
            if log.src_ip:
                ips.add(log.src_ip)
            if log.dst_ip:
                ips.add(log.dst_ip)

        return [
            {"ip": ip, "mac": "unknown", "source": "file_logs"}
            for ip in sorted(ips)
        ]

    def disconnect(self) -> None:
        self._logs = []
        self._loaded = False

    def is_connected(self) -> bool:
        return self.file_path.exists()

    def get_last_error(self) -> str:
        return self._last_error

    # ── File Loading ──────────────────────────────────────

    def _load_file(self) -> None:
        """Auto-detect format and parse."""
        self._logs = []

        try:
            if self.file_path.is_dir():
                for f in sorted(self.file_path.glob("*.csv")):
                    self._logs.extend(self._parse_csv(f))
            elif self.file_path.suffix == '.csv':
                self._logs = self._parse_csv(self.file_path)
            elif self.file_path.suffix in ('.log', '.txt'):
                self._logs = self._parse_syslog(self.file_path)
            else:
                try:
                    self._logs = self._parse_csv(self.file_path)
                except Exception:
                    self._logs = self._parse_syslog(self.file_path)
        except Exception as e:
            self._last_error = f"Failed to load {self.file_path}: {e}"
            logger.error(self._last_error)

        self._loaded = True
        logger.info(f"Loaded {len(self._logs)} logs from {self.file_path}")

    # ── CSV Parser ────────────────────────────────────────

    def _parse_csv(self, path: Path) -> List[LogEntry]:
        """Parse CSV log file with auto-detected separator and column names."""
        logs = []

        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            first_line = f.readline()
            if ';' in first_line and ',' not in first_line:
                delimiter = ';'
            elif '\t' in first_line:
                delimiter = '\t'
            else:
                delimiter = ','

        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f, delimiter=delimiter)
            if reader.fieldnames:
                reader.fieldnames = [
                    h.strip().lower().replace(' ', '_')
                    for h in reader.fieldnames
                ]

            for row in reader:
                try:
                    log = self._row_to_log_entry(row)
                    if log:
                        logs.append(log)
                except Exception:
                    continue

        return logs

    def _row_to_log_entry(self, row: dict) -> Optional[LogEntry]:
        """Convert a CSV row to LogEntry, trying multiple column name variations."""
        def get(names: list, default=""):
            for name in names:
                if name in row and row[name]:
                    return row[name].strip()
            return default

        ts_str = get(['timestamp', 'time', 'datetime', 'date',
                       'start_time', 'event_time'])
        timestamp = self._parse_timestamp(ts_str)

        src_ip = get(['src_ip', 'source', 'src', 'source_ip',
                       'sourceip', 'src_addr'])
        dst_ip = get(['dst_ip', 'dest', 'dst', 'destination_ip',
                       'destip', 'dst_addr', 'destination'])

        if not src_ip and not dst_ip:
            return None

        src_port = int(get(['src_port', 'source_port', 'sport'], '0') or 0)
        dst_port = int(get(['dst_port', 'dest_port', 'dport',
                            'destination_port'], '0') or 0)

        protocol = get(['protocol', 'proto', 'ip_protocol'], 'TCP').upper()

        action_raw = get(['action', 'policy_action', 'event_action',
                          'result'], 'ALLOW').upper()
        action = "DENY" if any(
            x in action_raw for x in ['DENY', 'DROP', 'BLOCK', 'REJECT']
        ) else "ALLOW"

        bytes_val = int(get(['bytes', 'bytes_sent', 'total_bytes',
                             'byte'], '0') or 0)

        return LogEntry(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            action=action,
            bytes_transferred=bytes_val,
            segment="file_import",
        )

    # ── Syslog Parser ─────────────────────────────────────

    def _parse_syslog(self, path: Path) -> List[LogEntry]:
        """Parse iptables/firewall syslog format."""
        logs = []

        pattern = re.compile(
            r'SRC=([\d.]+).*?DST=([\d.]+).*?'
            r'PROTO=(\w+).*?SPT=(\d+).*?DPT=(\d+)',
            re.IGNORECASE,
        )

        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    action = "DENY" if any(
                        x in line.upper()
                        for x in ['DROP', 'DENY', 'BLOCK', 'REJECT']
                    ) else "ALLOW"

                    logs.append(LogEntry(
                        timestamp=self._extract_syslog_timestamp(line),
                        src_ip=match.group(1),
                        dst_ip=match.group(2),
                        protocol=match.group(3).upper(),
                        src_port=int(match.group(4)),
                        dst_port=int(match.group(5)),
                        action=action,
                        segment="syslog_import",
                    ))

        return logs

    # ── Timestamp Helpers ─────────────────────────────────

    @staticmethod
    def _parse_timestamp(ts_str: str) -> float:
        """Parse timestamp string in common formats → Unix timestamp."""
        if not ts_str:
            return time.time()

        try:
            val = float(ts_str)
            if val > 1_000_000_000:
                return val
        except ValueError:
            pass

        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%d/%m/%Y %H:%M",
            "%d/%m/%Y %H:%M:%S",
            "%b %d %H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
        ]

        for fmt in formats:
            try:
                dt = datetime.datetime.strptime(ts_str.strip(), fmt)
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.datetime.now().year)
                return dt.timestamp()
            except ValueError:
                continue

        return time.time()

    @staticmethod
    def _extract_syslog_timestamp(line: str) -> float:
        """Extract timestamp from syslog line: 'Mar 11 10:00:01 ...'"""
        match = re.match(r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)', line)
        if match:
            try:
                dt = datetime.datetime.strptime(match.group(1), "%b %d %H:%M:%S")
                dt = dt.replace(year=datetime.datetime.now().year)
                return dt.timestamp()
            except ValueError:
                pass
        return time.time()