"""
connectors/base.py
Abstract base class for all data connectors.

Every connector — whether it reads files, SSHs into Cisco,
or generates mock data — must implement these methods.

The engine doesn't care WHERE data comes from.
It only cares WHAT the data looks like (LogEntry objects).
"""

from abc import ABC, abstractmethod
from typing import List, Dict
from app.models.schemas import LogEntry


class BaseConnector(ABC):
    """
    Interface that all connectors implement.

    Think of it as a "plug" — the engine has a socket,
    any connector that fits the socket works.
    """

    @abstractmethod
    def connect(self) -> bool:
        """
        Establish connection to data source.
        Returns True if successful.

        For files: check file exists and is readable
        For SSH: establish SSH session
        For mock: always True
        """
        pass

    @abstractmethod
    def get_logs(self, since: float = 0, limit: int = 100) -> List[LogEntry]:
        """
        Fetch log entries from the data source.

        Args:
            since: Unix timestamp — only return logs after this time
            limit: max number of logs to return

        Returns:
            List of LogEntry objects (same format regardless of source)
        """
        pass

    @abstractmethod
    def get_topology(self) -> List[Dict]:
        """
        Get network topology — what devices exist.

        Returns list of dicts:
            [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff",
              "type": "router", "interface": "Gi0/0"}, ...]
        """
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Clean up connection resources."""
        pass

    def is_connected(self) -> bool:
        """Override if connection state tracking is needed."""
        return False

    def get_last_error(self) -> str:
        """Override to return the last error message for UI feedback."""
        return ""