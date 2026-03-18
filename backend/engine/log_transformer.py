"""
engine/log_transformer.py
Transforms discrete network logs into continuous time series.

This bridges the gap between the connector world (LogEntry objects from
SSH/file/mock sources) and the engine world (numpy arrays of sensor data).

Each IP becomes a "virtual sensor" with 5 channels:
    connection_count  — total connections involving this IP (in + out)
    unique_targets    — how many distinct IPs this IP talked to
    bytes_total       — total bytes transferred
    denied_count      — DENY/DROP events involving this IP
    unique_ports      — how many distinct destination ports this IP contacted

The output has shape (N_ips × 5_channels, T_windows) — same format as
the OT sensor datasets, so the topological engine works identically
on live network logs and pre-recorded sensor data.

Usage:
    from engine.log_transformer import LogTransformer

    transformer = LogTransformer(window_sec=10)
    sensor_data, sensor_names = transformer.transform(logs)
    # sensor_data shape: (N_virtual_sensors, T_windows)
    # Feed directly to scanner.scan(sensor_data=sensor_data, sensor_names=sensor_names)
"""

import logging
import numpy as np
from typing import List, Dict, Tuple, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


class LogTransformer:
    """
    Converts discrete log events into windowed time series.

    Each time window aggregates log events into per-IP behavioral features.
    The topological engine then analyzes correlations between these features
    across IPs to detect coordinated anomalies.
    """

    # Channel definitions — each IP gets one time series per channel
    CHANNELS = [
        'connection_count',
        'unique_targets',
        'bytes_total',
        'denied_count',
        'unique_ports',
    ]

    def __init__(self, window_sec: float = 10):
        """
        Args:
            window_sec: duration of each aggregation window in seconds.
                        Smaller = more temporal resolution but noisier.
                        10s is good for OT environments (aligns with PLC polling cycles).
        """
        self.window_sec = max(window_sec, 0.1)  # Floor to avoid division by zero

    def transform(
        self,
        logs: List[Dict],
        time_range: Tuple[float, float] = None,
    ) -> Tuple[np.ndarray, List[str]]:
        """
        Transform log events into (N_virtual_sensors, T_windows) array.

        Args:
            logs: list of log dicts, each with at minimum:
                  {timestamp, src_ip, dst_ip}
                  Optional: {action, bytes/bytes_transferred, dst_port, protocol}
            time_range: (start, end) timestamps. If None, inferred from logs.

        Returns:
            (sensor_data, sensor_names)
            sensor_data: (N_ips * 5, T_windows) float64 array
            sensor_names: list of "IP_channel" strings
        """
        if not logs:
            return np.zeros((0, 0), dtype=np.float64), []

        # ── Determine time range ──
        timestamps = [l.get('timestamp', 0) for l in logs]
        if time_range is None:
            t_start = min(timestamps)
            t_end = max(timestamps)
        else:
            t_start, t_end = time_range

        # Ensure we have at least one window
        duration = max(t_end - t_start, self.window_sec)
        n_windows = max(1, int(np.ceil(duration / self.window_sec)))

        # ── Collect all unique IPs ──
        all_ips: Set[str] = set()
        for log in logs:
            src = log.get('src_ip', '')
            dst = log.get('dst_ip', '')
            if src:
                all_ips.add(src)
            if dst:
                all_ips.add(dst)

        if not all_ips:
            return np.zeros((0, 0), dtype=np.float64), []

        ip_list = sorted(all_ips)

        # ── Initialize per-IP, per-channel accumulators ──
        # Using numpy arrays for the numeric channels, sets for unique counting
        data = {
            ip: {ch: np.zeros(n_windows, dtype=np.float64) for ch in self.CHANNELS}
            for ip in ip_list
        }
        # Track unique targets and ports per (IP, window) with sets
        targets_per_window: Dict[str, Dict[int, Set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )
        ports_per_window: Dict[str, Dict[int, Set[int]]] = defaultdict(
            lambda: defaultdict(set)
        )

        # ── Aggregate logs into windows ──
        for log in logs:
            t = log.get('timestamp', 0)
            w = int((t - t_start) / self.window_sec)
            w = max(0, min(w, n_windows - 1))  # Clamp to valid range

            src = log.get('src_ip', '')
            dst = log.get('dst_ip', '')
            action = log.get('action', 'ALLOW').upper()
            bytes_val = log.get('bytes', 0) or log.get('bytes_transferred', 0) or 0
            dst_port = log.get('dst_port', 0) or 0

            is_deny = action in ('DENY', 'DROP', 'BLOCK', 'REJECT')

            # ── Source IP contributions ──
            if src and src in data:
                data[src]['connection_count'][w] += 1
                data[src]['bytes_total'][w] += bytes_val
                if is_deny:
                    data[src]['denied_count'][w] += 1
                if dst:
                    targets_per_window[src][w].add(dst)
                if dst_port:
                    ports_per_window[src][w].add(dst_port)

            # ── Destination IP contributions ──
            if dst and dst in data:
                data[dst]['connection_count'][w] += 1
                data[dst]['bytes_total'][w] += bytes_val
                if is_deny:
                    data[dst]['denied_count'][w] += 1

        # ── Resolve set-based channels into counts ──
        for ip in ip_list:
            for w in range(n_windows):
                data[ip]['unique_targets'][w] = len(
                    targets_per_window.get(ip, {}).get(w, set())
                )
                data[ip]['unique_ports'][w] = len(
                    ports_per_window.get(ip, {}).get(w, set())
                )

        # ── Assemble into (N_virtual_sensors, T_windows) array ──
        sensor_data = []
        sensor_names = []

        for ip in ip_list:
            for ch in self.CHANNELS:
                sensor_data.append(data[ip][ch])
                sensor_names.append(f"{ip}_{ch}")

        result = np.array(sensor_data, dtype=np.float64)

        logger.info(
            f"Log transform: {len(logs)} events → "
            f"{len(ip_list)} IPs × {len(self.CHANNELS)} channels × "
            f"{n_windows} windows = {result.shape} matrix"
        )

        return result, sensor_names