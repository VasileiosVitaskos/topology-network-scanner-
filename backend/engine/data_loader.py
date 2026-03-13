"""
app/engine/data_loader.py
Loads OT datasets into numpy arrays for the topological engine.

Supported datasets:
    HAI (23.05):    1-sec sampling, ~200 sensors, train/test split
    SWaT (A10):     1-sec sampling, ~50 sensors, normal only
    BATADAL:        1-hour sampling, 43 sensors, train/test split

Usage:
    loader = DataLoader(data_dir="backend/data")
    
    # Load for calibration (normal data only)
    data, names = loader.load_baseline("hai")
    scanner.calibrate(data, names)
    
    # Load for scanning (attack data, window by window)
    for window_data, window_names, window_idx in loader.iter_windows("hai", mode="test"):
        result = scanner.scan(sensor_data=window_data, sensor_names=window_names)
"""

import os
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Tuple, List, Iterator, Optional


class DataLoader:
    """
    Loads OT sensor datasets into the format the engine expects:
        (N_sensors, W_samples) numpy array
    """

    def __init__(self, data_dir: str = None):
        """
        Args:
            data_dir: path to backend/data/ directory
                      Contains subdirs: hai/, swat/, batadal/
        """
        if data_dir is None:
            data_dir = os.getenv("DATA_DIR", "/app/data")
        self.data_dir = Path(data_dir)

    # ══════════════════════════════════════════════════════
    # HAI DATASET
    # ══════════════════════════════════════════════════════

    def load_hai(
        self,
        mode: str = "train",
        file_index: int = 1,
        max_rows: int = None,
    ) -> Tuple[np.ndarray, List[str]]:
        """
        Load HAI dataset.
        
        Args:
            mode: "train" (normal) or "test" (with attacks)
            file_index: 1, 2, 3, 4 (train has 4 files, test has 2)
            max_rows: limit rows loaded (for speed during dev)
        
        Returns:
            (sensor_data, sensor_names)
            sensor_data: (N_sensors, T_samples) array
            sensor_names: list of sensor IDs
        
        HAI format:
            Timestamp, sensor1, sensor2, ..., sensorN
            2022-08-04 18:00:00, 0, 287.20, 3166.97, ...
        """
        filename = f"end-{mode}{file_index}.csv"
        filepath = self.data_dir / "hai" / filename

        if not filepath.exists():
            raise FileNotFoundError(f"HAI file not found: {filepath}")

        # Read CSV
        df = pd.read_csv(
            filepath,
            nrows=max_rows,
            low_memory=False,
        )

        # First column is Timestamp — drop it
        if 'Timestamp' in df.columns or 'timestamp' in df.columns:
            ts_col = 'Timestamp' if 'Timestamp' in df.columns else 'timestamp'
            df = df.drop(columns=[ts_col])

        # Remove any non-numeric columns
        df = df.select_dtypes(include=[np.number])

        # Fill NaN with 0 (some sensors have gaps)
        df = df.fillna(0.0)

        # Convert to numpy: (T_samples, N_sensors) → transpose to (N_sensors, T_samples)
        sensor_data = df.values.T.astype(np.float64)
        sensor_names = list(df.columns)

        return sensor_data, sensor_names

    def load_hai_labels(
        self,
        file_index: int = 1,
        max_rows: int = None,
    ) -> np.ndarray:
        """
        Load HAI attack labels for test data.
        
        Returns:
            1D array of 0 (normal) / 1 (attack) per timestamp
        """
        filename = f"label-test{file_index}.csv"
        filepath = self.data_dir / "hai" / filename

        if not filepath.exists():
            raise FileNotFoundError(f"HAI labels not found: {filepath}")

        df = pd.read_csv(filepath, nrows=max_rows)

        # Label column might be named 'attack' or last column
        if 'attack' in df.columns:
            return df['attack'].values
        else:
            # Last column is usually the label
            return df.iloc[:, -1].values

    # ══════════════════════════════════════════════════════
    # SWaT DATASET
    # ══════════════════════════════════════════════════════

    def load_swat(
        self,
        file_index: int = 1,
        max_rows: int = None,
    ) -> Tuple[np.ndarray, List[str]]:
        """
        Load SWaT A10 dataset (normal data only).
        
        SWaT A10 format:
            Timestamp, P1_STATE, MV101.Status, FIT101.Pv, ...
        """
        hai_dir = self.data_dir / "swat"
        
        # Find CSV files
        csv_files = sorted(hai_dir.glob("*.csv"))
        if not csv_files:
            raise FileNotFoundError(f"No SWaT CSV files in {hai_dir}")

        # Use file_index to pick which day
        idx = min(file_index - 1, len(csv_files) - 1)
        filepath = csv_files[idx]

        df = pd.read_csv(filepath, nrows=max_rows, low_memory=False)

        # Drop timestamp column
        for col in ['Timestamp', 'timestamp', 'Time', 'time']:
            if col in df.columns:
                df = df.drop(columns=[col])
                break

        # Drop non-numeric (like 'Normal/Attack' label column)
        df = df.select_dtypes(include=[np.number])
        df = df.fillna(0.0)

        sensor_data = df.values.T.astype(np.float64)
        sensor_names = list(df.columns)

        return sensor_data, sensor_names

    # ══════════════════════════════════════════════════════
    # BATADAL DATASET
    # ══════════════════════════════════════════════════════

    def load_batadal(
        self,
        mode: str = "train",
        max_rows: int = None,
    ) -> Tuple[np.ndarray, List[str]]:
        """
        Load BATADAL dataset.
        
        BATADAL format:
            DATETIME, S_PU1, ..., S_PU11, F_PU1, ..., ATT_FLAG
            
        Note: HOURLY sampling — window sizes must be adjusted.
        """
        batadal_dir = self.data_dir / "batadal"

        if mode == "train":
            # dataset03 = pure normal, dataset04 = partially labeled
            filepath = batadal_dir / "BATADAL_dataset03.csv"
            if not filepath.exists():
                filepath = batadal_dir / "BATADAL_dataset04.csv"
        else:
            filepath = batadal_dir / "BATADAL_test_dataset.csv"

        if not filepath.exists():
            raise FileNotFoundError(f"BATADAL file not found: {filepath}")

        # BATADAL uses space-separated or comma-separated
        try:
            df = pd.read_csv(filepath, nrows=max_rows, low_memory=False)
        except Exception:
            df = pd.read_csv(filepath, nrows=max_rows, sep=r'\s+', low_memory=False)

        # Drop datetime and label columns
        drop_cols = []
        for col in df.columns:
            col_lower = col.strip().lower()
            if col_lower in ['datetime', 'date', 'time', 'att_flag', 'att flag']:
                drop_cols.append(col)
        df = df.drop(columns=drop_cols, errors='ignore')

        df = df.select_dtypes(include=[np.number])
        df = df.fillna(0.0)

        sensor_data = df.values.T.astype(np.float64)
        sensor_names = [c.strip() for c in df.columns]

        return sensor_data, sensor_names

    # ══════════════════════════════════════════════════════
    # GENERIC LOADERS
    # ══════════════════════════════════════════════════════

    def load_baseline(
        self,
        dataset: str = "hai",
        max_rows: int = 50000,
    ) -> Tuple[np.ndarray, List[str]]:
        """
        Load baseline (normal) data for calibration.
        
        Args:
            dataset: "hai", "swat", "batadal"
            max_rows: limit for speed (50K = ~14 hours of HAI at 1sec)
        """
        if dataset == "hai":
            return self.load_hai(mode="train", file_index=1, max_rows=max_rows)
        elif dataset == "swat":
            return self.load_swat(file_index=1, max_rows=max_rows)
        elif dataset == "batadal":
            return self.load_batadal(mode="train", max_rows=max_rows)
        else:
            raise ValueError(f"Unknown dataset: {dataset}")

    def load_test(
        self,
        dataset: str = "hai",
        max_rows: int = None,
    ) -> Tuple[np.ndarray, List[str]]:
        """
        Load test data (with attacks) for scanning.
        """
        if dataset == "hai":
            return self.load_hai(mode="test", file_index=1, max_rows=max_rows)
        elif dataset == "swat":
            return self.load_swat(file_index=1, max_rows=max_rows)
        elif dataset == "batadal":
            return self.load_batadal(mode="test", max_rows=max_rows)
        else:
            raise ValueError(f"Unknown dataset: {dataset}")

    def iter_windows(
        self,
        dataset: str = "hai",
        mode: str = "test",
        window_size: int = 60,
        step_size: int = 10,
        max_windows: int = None,
    ) -> Iterator[Tuple[np.ndarray, List[str], int]]:
        """
        Iterate over data in sliding windows.
        
        This is how the scanner processes data in real-time:
        each call to scan() gets one window.
        
        Args:
            dataset: "hai", "swat", "batadal"
            mode: "train" or "test"
            window_size: samples per window (60 = 60 sec for HAI)
            step_size: samples between windows (10 = 10 sec for HAI)
            max_windows: limit number of windows (for demo speed)
        
        Yields:
            (window_data, sensor_names, window_index)
            window_data: (N_sensors, window_size) array
        """
        if mode == "train":
            data, names = self.load_baseline(dataset)
        else:
            data, names = self.load_test(dataset)

        n_sensors, total_samples = data.shape
        window_count = 0

        for start in range(0, total_samples - window_size, step_size):
            window = data[:, start:start + window_size]

            if window.shape[1] < window_size:
                break

            yield window, names, window_count
            window_count += 1

            if max_windows and window_count >= max_windows:
                break

    # ══════════════════════════════════════════════════════
    # DATASET INFO
    # ══════════════════════════════════════════════════════

    def get_dataset_info(self, dataset: str = "hai") -> dict:
        """
        Get info about a dataset without loading all data.
        """
        try:
            if dataset == "hai":
                filepath = self.data_dir / "hai" / "end-train1.csv"
                if not filepath.exists():
                    return {"status": "not_found", "dataset": dataset}
                # Read just header + 1 row
                df = pd.read_csv(filepath, nrows=1)
                n_sensors = len(df.columns) - 1  # minus Timestamp
                # Count rows without loading
                with open(filepath) as f:
                    n_rows = sum(1 for _ in f) - 1
                return {
                    "dataset": "hai",
                    "status": "available",
                    "sensors": n_sensors,
                    "samples": n_rows,
                    "sampling_sec": 1,
                    "duration_hours": round(n_rows / 3600, 1),
                    "files": {
                        "train": [f.name for f in (self.data_dir / "hai").glob("end-train*.csv")],
                        "test": [f.name for f in (self.data_dir / "hai").glob("end-test*.csv")],
                        "labels": [f.name for f in (self.data_dir / "hai").glob("label-*.csv")],
                    },
                }
            elif dataset == "swat":
                swat_dir = self.data_dir / "swat"
                csv_files = list(swat_dir.glob("*.csv"))
                if not csv_files:
                    return {"status": "not_found", "dataset": dataset}
                df = pd.read_csv(csv_files[0], nrows=1)
                return {
                    "dataset": "swat",
                    "status": "available",
                    "sensors": len(df.select_dtypes(include=[np.number]).columns),
                    "files": [f.name for f in csv_files],
                }
            elif dataset == "batadal":
                batadal_dir = self.data_dir / "batadal"
                csv_files = list(batadal_dir.glob("*.csv"))
                if not csv_files:
                    return {"status": "not_found", "dataset": dataset}
                return {
                    "dataset": "batadal",
                    "status": "available",
                    "sampling": "hourly",
                    "files": [f.name for f in csv_files],
                }
            else:
                return {"status": "unknown", "dataset": dataset}
        except Exception as e:
            return {"status": "error", "dataset": dataset, "error": str(e)}
