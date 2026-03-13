"""
app/connectors/mock_connector.py
Wraps the existing mock-api server as a connector.
Used for testing and development.
"""

import os
import requests
from typing import List
from app.models.schemas import LogEntry
from connectors.base import BaseConnector


class MockConnector(BaseConnector):
    """
    Connector that talks to the mock-api service.
    Same synthetic data as before, but now through
    the standard connector interface.
    """

    def __init__(self, dataset: str = "swat"):
        self.dataset = dataset
        self._mock_url = os.getenv(
            "MOCK_API_URL",
            "http://localhost:8000"
        )

    def connect(self) -> bool:
        """Check mock-api is running."""
        try:
            resp = requests.get(f"{self._mock_url}/health", timeout=3)
            return resp.status_code == 200
        except Exception:
            return False

    def get_logs(self, since: float = 0, limit: int = 100) -> List[LogEntry]:
        """Fetch from mock-api and convert to LogEntry."""
        try:
            resp = requests.get(
                f"{self._mock_url}/api/logs",
                params={"since": since, "limit": limit,
                        "dataset": self.dataset},
                timeout=5,
            )
            raw_logs = resp.json().get("logs", [])

            return [
                LogEntry(
                    timestamp=log.get("timestamp", 0),
                    src_ip=log.get("src_ip", ""),
                    dst_ip=log.get("dst_ip", ""),
                    src_port=log.get("src_port", 0),
                    dst_port=log.get("dst_port", 0),
                    protocol=log.get("protocol", ""),
                    action=log.get("action", "ALLOW"),
                    bytes_transferred=log.get("bytes", 0),
                    segment=log.get("segment", ""),
                )
                for log in raw_logs
            ]
        except Exception:
            return []

    def get_topology(self) -> List[dict]:
        """Extract IPs from mock logs."""
        logs = self.get_logs(limit=500)
        ips = set()
        for log in logs:
            if log.src_ip:
                ips.add(log.src_ip)
            if log.dst_ip:
                ips.add(log.dst_ip)

        return [
            {"ip": ip, "mac": "mock", "source": "mock_api"}
            for ip in sorted(ips)
        ]

    def disconnect(self) -> None:
        pass

    def is_connected(self) -> bool:
        return self.connect()

