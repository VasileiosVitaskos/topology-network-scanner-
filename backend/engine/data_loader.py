"""
engine/data_loader.py
Loads OT datasets into numpy arrays for the topological engine.

Supported datasets:
    HAI (23.05):    1-sec sampling, ~86 sensors, train/test split with labels
    SWaT (A10):     1-sec sampling, ~51 sensors, normal + attack days
    BATADAL:        1-hour sampling, 43 sensors, train/test split with ATT_FLAG

All loaders return the same format:
    sensor_data: (N_sensors, T_samples) float64 array
    sensor_names: list of sensor ID strings

Usage:
    loader = DataLoader(data_dir="backend/data")

    # Calibration (normal data only)
    data, names = loader.load_baseline("hai")
    scanner.calibrate(data, names)

    # Scanning (attack data, window by window)
    for window_data, names, labels, idx in loader.iter_windows("hai", mode="test"):
        result = scanner.scan(sensor_data=window_data, sensor_names=names)
        actual_attack = labels.any()  # True if any sample in window is labeled attack
"""

import logging
import os
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Tuple, List, Iterator, Optional

logger = logging.getLogger(__name__)


class DataLoader:
    """
    Loads OT sensor datasets into (N_sensors, T_samples) numpy arrays.
    Handles format differences between HAI, SWaT, and BATADAL transparently.
    """

    def __init__(self, data_dir: str = None):
        """
        Args:
            data_dir: path to the data/ directory containing hai/, swat/, batadal/ subdirs.
                      Falls back to DATA_DIR env var, then /app/data (Docker default).
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

        HAI CSV format (1-second sampling):
            Timestamp, sensor1, sensor2, ..., sensorN
            2022-08-04 18:00:00, 0, 287.20, 3166.97, ...

        Args:
            mode: "train" (normal operation) or "test" (contains attacks)
            file_index: 1-4 for train, 1-2 for test
            max_rows: limit rows for speed during dev

        Returns:
            (sensor_data, sensor_names)
            sensor_data shape: (N_sensors, T_samples)
        """
        filename = f"end-{mode}{file_index}.csv"
        filepath = self.data_dir / "hai" / filename

        if not filepath.exists():
            raise FileNotFoundError(
                f"HAI file not found: {filepath}\n"
                f"Download from: https://github.com/icsdataset/hai\n"
                f"Place CSV files in: {self.data_dir / 'hai' / ''}"
            )

        df = pd.read_csv(filepath, nrows=max_rows, low_memory=False)

        # Drop timestamp column (multiple possible names)
        for col in list(df.columns):
            if col.strip().lower() in ('timestamp', 'time', 'datetime', 'date'):
                df = df.drop(columns=[col])
                break

        # Drop any 'attack' label column that might be in the data file
        for col in list(df.columns):
            if col.strip().lower() in ('attack', 'label', 'att_flag'):
                df = df.drop(columns=[col])
                break

        # Keep only numeric columns
        df = df.select_dtypes(include=[np.number])
        df = df.fillna(0.0)

        # Strip whitespace from column names
        df.columns = [c.strip() for c in df.columns]

        sensor_data = df.values.T.astype(np.float64)
        sensor_names = list(df.columns)

        logger.info(
            f"HAI {mode}{file_index}: {sensor_data.shape[0]} sensors × "
            f"{sensor_data.shape[1]} samples"
        )
        return sensor_data, sensor_names

    def load_hai_labels(
        self,
        file_index: int = 1,
        max_rows: int = None,
    ) -> np.ndarray:
        """
        Load HAI attack labels for test data.

        HAI label files have varying formats across versions:
            - Single column named 'attack' (0/1)
            - Multiple columns with the last being the attack label
            - Columns with trailing whitespace

        Returns:
            1D array of 0 (normal) / non-zero (attack) per timestamp.
            Length matches the corresponding end-testN.csv file.
        """
        filename = f"label-test{file_index}.csv"
        filepath = self.data_dir / "hai" / filename

        if not filepath.exists():
            raise FileNotFoundError(
                f"HAI labels not found: {filepath}\n"
                f"Download from: https://github.com/icsdataset/hai"
            )

        df = pd.read_csv(filepath, nrows=max_rows, low_memory=False)

        # Normalize column names
        df.columns = [c.strip().lower() for c in df.columns]

        # Try known column names in order of likelihood
        for col_name in ('attack', 'label', 'att_flag', 'anomaly'):
            if col_name in df.columns:
                labels = df[col_name].values
                logger.info(
                    f"HAI labels from '{col_name}': {len(labels)} rows, "
                    f"{int(np.sum(labels != 0))} attack samples"
                )
                return labels

        # Fallback: last column
        labels = df.iloc[:, -1].values
        logger.info(
            f"HAI labels from last column '{df.columns[-1]}': {len(labels)} rows, "
            f"{int(np.sum(labels != 0))} attack samples"
        )
        return labels

    # ══════════════════════════════════════════════════════
    # SWaT DATASET
    # ══════════════════════════════════════════════════════

    def load_swat(
        self,
        file_index: int = 1,
        max_rows: int = None,
    ) -> Tuple[np.ndarray, List[str]]:
        """
        Load SWaT dataset.

        SWaT A10 format (1-second sampling):
            Timestamp, P1_STATE, MV101.Status, FIT101.Pv, ..., Normal/Attack
        """
        swat_dir = self.data_dir / "swat"

        csv_files = sorted(swat_dir.glob("*.csv"))
        if not csv_files:
            raise FileNotFoundError(
                f"No SWaT CSV files in {swat_dir}\n"
                f"Place SWaT CSV files in: {swat_dir}"
            )

        idx = min(file_index - 1, len(csv_files) - 1)
        filepath = csv_files[idx]

        df = pd.read_csv(filepath, nrows=max_rows, low_memory=False)

        # Drop timestamp columns
        for col in list(df.columns):
            if col.strip().lower() in ('timestamp', 'time', 'datetime', 'date', ' timestamp'):
                df = df.drop(columns=[col])

        # Drop label column (SWaT has "Normal/Attack" column)
        for col in list(df.columns):
            col_lower = col.strip().lower()
            if col_lower in ('normal/attack', 'attack', 'label'):
                df = df.drop(columns=[col])

        df = df.select_dtypes(include=[np.number])
        df = df.fillna(0.0)
        df.columns = [c.strip() for c in df.columns]

        sensor_data = df.values.T.astype(np.float64)
        sensor_names = list(df.columns)

        logger.info(
            f"SWaT file {filepath.name}: {sensor_data.shape[0]} sensors × "
            f"{sensor_data.shape[1]} samples"
        )
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

        BATADAL format (HOURLY sampling):
            DATETIME, S_PU1, ..., S_PU11, F_PU1, ..., ATT_FLAG

        Note: 1-hour sampling means window sizes from domains.yaml
        represent hours, not seconds.
        """
        batadal_dir = self.data_dir / "batadal"

        if mode == "train":
            filepath = batadal_dir / "BATADAL_dataset03.csv"
            if not filepath.exists():
                filepath = batadal_dir / "BATADAL_dataset04.csv"
        else:
            filepath = batadal_dir / "BATADAL_test_dataset.csv"

        if not filepath.exists():
            raise FileNotFoundError(
                f"BATADAL file not found: {filepath}\n"
                f"Download from: https://www.batadal.net/data.html\n"
                f"Place CSV files in: {batadal_dir}"
            )

        # BATADAL files may use comma, semicolon, or whitespace separators
        df = None
        for sep in [',', ';', r'\s+']:
            try:
                df = pd.read_csv(filepath, nrows=max_rows, sep=sep, low_memory=False)
                # Check if we got more than 1 column (separator worked)
                if len(df.columns) > 1:
                    break
            except Exception:
                continue

        if df is None or len(df.columns) <= 1:
            raise ValueError(f"Could not parse BATADAL file: {filepath}")

        # Drop datetime and label columns
        drop_cols = []
        for col in df.columns:
            col_lower = col.strip().lower()
            if col_lower in ('datetime', 'date', 'time', 'att_flag', 'att flag', 'label'):
                drop_cols.append(col)
        df = df.drop(columns=drop_cols, errors='ignore')

        df = df.select_dtypes(include=[np.number])
        df = df.fillna(0.0)
        df.columns = [c.strip() for c in df.columns]

        sensor_data = df.values.T.astype(np.float64)
        sensor_names = list(df.columns)

        logger.info(
            f"BATADAL {mode}: {sensor_data.shape[0]} sensors × "
            f"{sensor_data.shape[1]} samples (hourly)"
        )
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
            max_rows: limit for speed (50K HAI = ~14 hours at 1sec)
        """
        loaders = {
            "hai": lambda: self.load_hai(mode="train", file_index=1, max_rows=max_rows),
            "swat": lambda: self.load_swat(file_index=1, max_rows=max_rows),
            "batadal": lambda: self.load_batadal(mode="train", max_rows=max_rows),
        }
        loader = loaders.get(dataset)
        if loader is None:
            raise ValueError(
                f"Unknown dataset: '{dataset}'. "
                f"Available: {', '.join(loaders.keys())}"
            )
        return loader()

    def load_test(
        self,
        dataset: str = "hai",
        max_rows: int = None,
    ) -> Tuple[np.ndarray, List[str]]:
        """Load test data (with attacks) for scanning."""
        loaders = {
            "hai": lambda: self.load_hai(mode="test", file_index=1, max_rows=max_rows),
            "swat": lambda: self.load_swat(file_index=1, max_rows=max_rows),
            "batadal": lambda: self.load_batadal(mode="test", max_rows=max_rows),
        }
        loader = loaders.get(dataset)
        if loader is None:
            raise ValueError(
                f"Unknown dataset: '{dataset}'. "
                f"Available: {', '.join(loaders.keys())}"
            )
        return loader()

    def load_labels(
        self,
        dataset: str = "hai",
        max_rows: int = None,
    ) -> Optional[np.ndarray]:
        """
        Load attack labels for test data.

        Returns:
            1D array of 0/1 per timestamp, or None if labels unavailable.
        """
        try:
            if dataset == "hai":
                return self.load_hai_labels(file_index=1, max_rows=max_rows)
            elif dataset == "batadal":
                # BATADAL labels are in the ATT_FLAG column of the test file
                filepath = self.data_dir / "batadal" / "BATADAL_test_dataset.csv"
                if filepath.exists():
                    df = pd.read_csv(filepath, nrows=max_rows, low_memory=False)
                    for col in df.columns:
                        if col.strip().lower() in ('att_flag', 'att flag'):
                            labels = df[col].values
                            # BATADAL uses -1/1 encoding in some versions
                            return (labels != 0).astype(int)
                return None
            else:
                return None
        except Exception as e:
            logger.warning(f"Could not load labels for {dataset}: {e}")
            return None

    def iter_windows(
        self,
        dataset: str = "hai",
        mode: str = "test",
        window_size: int = 60,
        step_size: int = 10,
        max_windows: int = None,
        load_labels: bool = False,
    ) -> Iterator[Tuple[np.ndarray, List[str], Optional[np.ndarray], int]]:
        """
        Iterate over data in sliding windows.

        This is the primary interface for scanning: each iteration
        yields one window of sensor data ready for scanner.scan().

        Args:
            dataset: "hai", "swat", "batadal"
            mode: "train" or "test"
            window_size: samples per window (60 = 60 sec for HAI)
            step_size: samples between windows (10 = 10 sec for HAI)
            max_windows: limit number of windows (for demo/dev speed)
            load_labels: if True, also yield per-sample labels for each window

        Yields:
            (window_data, sensor_names, window_labels, window_index)
            window_data: (N_sensors, window_size) array
            window_labels: (window_size,) array of 0/1 or None if labels unavailable
        """
        if mode == "train":
            data, names = self.load_baseline(dataset)
        else:
            data, names = self.load_test(dataset)

        # Load labels if requested
        labels = None
        if load_labels and mode == "test":
            labels = self.load_labels(dataset)
            if labels is not None:
                # Ensure labels align with data length
                min_len = min(len(labels), data.shape[1])
                labels = labels[:min_len]
                data = data[:, :min_len]

        n_sensors, total_samples = data.shape
        window_count = 0

        for start in range(0, total_samples - window_size + 1, step_size):
            end = start + window_size
            window = data[:, start:end]

            if window.shape[1] < window_size:
                break

            # Extract labels for this window
            window_labels = None
            if labels is not None and end <= len(labels):
                window_labels = labels[start:end]

            yield window, names, window_labels, window_count
            window_count += 1

            if max_windows and window_count >= max_windows:
                break

        logger.info(
            f"Iterated {window_count} windows over {dataset} {mode} "
            f"({total_samples} samples, window={window_size}, step={step_size})"
        )

    # ══════════════════════════════════════════════════════
    # DATASET INFO
    # ══════════════════════════════════════════════════════

    def get_dataset_info(self, dataset: str = "hai") -> dict:
        """Get metadata about a dataset without loading all data."""
        try:
            if dataset == "hai":
                return self._hai_info()
            elif dataset == "swat":
                return self._swat_info()
            elif dataset == "batadal":
                return self._batadal_info()
            else:
                return {"status": "unknown", "dataset": dataset}
        except Exception as e:
            return {"status": "error", "dataset": dataset, "error": str(e)}

    def get_all_dataset_info(self) -> dict:
        """Get info for all supported datasets."""
        return {
            ds: self.get_dataset_info(ds)
            for ds in ("hai", "swat", "batadal")
        }

    def _hai_info(self) -> dict:
        hai_dir = self.data_dir / "hai"
        filepath = hai_dir / "end-train1.csv"
        if not filepath.exists():
            return {"status": "not_found", "dataset": "hai",
                    "expected_path": str(hai_dir)}

        # Read just header
        df = pd.read_csv(filepath, nrows=0)
        n_sensors = len(df.select_dtypes(include=[np.number]).columns)

        # Count rows efficiently
        n_rows = self._count_lines(filepath) - 1  # minus header

        return {
            "dataset": "hai",
            "status": "available",
            "sensors": n_sensors,
            "samples": n_rows,
            "sampling_sec": 1,
            "duration_hours": round(n_rows / 3600, 1),
            "files": {
                "train": sorted(f.name for f in hai_dir.glob("end-train*.csv")),
                "test": sorted(f.name for f in hai_dir.glob("end-test*.csv")),
                "labels": sorted(f.name for f in hai_dir.glob("label-*.csv")),
            },
        }

    def _swat_info(self) -> dict:
        swat_dir = self.data_dir / "swat"
        csv_files = sorted(swat_dir.glob("*.csv"))
        if not csv_files:
            return {"status": "not_found", "dataset": "swat",
                    "expected_path": str(swat_dir)}

        df = pd.read_csv(csv_files[0], nrows=0)
        return {
            "dataset": "swat",
            "status": "available",
            "sensors": len(df.select_dtypes(include=[np.number]).columns),
            "sampling_sec": 1,
            "files": [f.name for f in csv_files],
        }

    def _batadal_info(self) -> dict:
        batadal_dir = self.data_dir / "batadal"
        csv_files = sorted(batadal_dir.glob("*.csv"))
        if not csv_files:
            return {"status": "not_found", "dataset": "batadal",
                    "expected_path": str(batadal_dir)}

        return {
            "dataset": "batadal",
            "status": "available",
            "sampling": "hourly",
            "sampling_sec": 3600,
            "files": [f.name for f in csv_files],
        }

    @staticmethod
    def _count_lines(filepath: Path) -> int:
        """Count lines in a file efficiently without loading it all into memory."""
        count = 0
        with open(filepath, 'rb') as f:
            for _ in f:
                count += 1
        return count