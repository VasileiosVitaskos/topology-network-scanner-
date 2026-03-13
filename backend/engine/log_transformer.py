"""
app/engine/log_transformer.py
Transforms discrete network logs into continuous time series.
Each IP becomes a "virtual sensor" with multiple channels.
"""

import numpy as np
from typing import List, Dict, Tuple
from collections import defaultdict


class LogTransformer:

    def __init__(self, window_sec: int = 10):
        self.window_sec = window_sec
        self.channels = [
            'connection_count', 'unique_targets',
            'bytes_total', 'denied_count', 'unique_ports',
        ]

    def transform(self, logs: List[Dict], time_range: Tuple[float, float] = None) -> Tuple[np.ndarray, List[str]]:
        if not logs:
            return np.zeros((0, 0)), []

        timestamps = [l.get('timestamp', 0) for l in logs]
        if time_range is None:
            t_start, t_end = min(timestamps), max(timestamps)
        else:
            t_start, t_end = time_range

        n_windows = max(1, int((t_end - t_start) / self.window_sec))

        all_ips = set()
        for log in logs:
            all_ips.add(log.get('src_ip', ''))
            all_ips.add(log.get('dst_ip', ''))
        all_ips.discard('')
        ip_list = sorted(all_ips)
        if not ip_list:
            return np.zeros((0, 0)), []

        data = {ip: {ch: np.zeros(n_windows) for ch in self.channels} for ip in ip_list}
        targets_per_window = defaultdict(lambda: defaultdict(set))

        for log in logs:
            t = log.get('timestamp', 0)
            w = min(int((t - t_start) / self.window_sec), n_windows - 1)
            if w < 0:
                continue
            src = log.get('src_ip', '')
            dst = log.get('dst_ip', '')
            action = log.get('action', 'ALLOW')
            bytes_val = log.get('bytes', 0) or log.get('bytes_transferred', 0) or 0

            if src in data:
                data[src]['connection_count'][w] += 1
                data[src]['bytes_total'][w] += bytes_val
                data[src]['unique_ports'][w] += 1
                if action == 'DENY':
                    data[src]['denied_count'][w] += 1
                targets_per_window[src][w].add(dst)

            if dst in data:
                data[dst]['connection_count'][w] += 1
                data[dst]['bytes_total'][w] += bytes_val

        for ip in ip_list:
            for w in range(n_windows):
                data[ip]['unique_targets'][w] = len(targets_per_window.get(ip, {}).get(w, set()))

        sensor_data, sensor_names = [], []
        for ip in ip_list:
            for ch in self.channels:
                sensor_data.append(data[ip][ch])
                sensor_names.append(f"{ip}_{ch}")

        return np.array(sensor_data), sensor_names
