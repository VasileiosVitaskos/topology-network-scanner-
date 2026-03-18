"""
scripts/validate_engine.py
Offline validation of the topological detection engine against HAI dataset.

Tests the three-gate cascade (Sheaf + Ricci + Homology) on real industrial
attack data and reports precision, recall, F1, and per-gate performance.

Usage:
    cd topo-scanner-v7
    pip install -r backend/requirements.txt
    python scripts/validate_engine.py

Requirements:
    - HAI dataset files in backend/data/hai/
      Download from: https://github.com/icsdataset/hai
    - Required files: end-train1.csv, end-test1.csv, label-test1.csv
"""

import sys
import os
import time
import numpy as np
from pathlib import Path

# ── Path setup ──
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
BACKEND_DIR = PROJECT_ROOT / "backend"

sys.path.insert(0, str(BACKEND_DIR))
os.environ.setdefault("DB_PATH", str(PROJECT_ROOT / "db" / "validate.db"))
os.environ.setdefault("DATA_DIR", str(BACKEND_DIR / "data"))

# ── Dependency check ──
REQUIRED = {
    "yaml": "pyyaml", "scipy": "scipy", "gudhi": "gudhi",
    "dtaidistance": "dtaidistance", "statsmodels": "statsmodels",
    "networkx": "networkx", "dotenv": "python-dotenv",
}
missing = []
for mod, pkg in REQUIRED.items():
    try:
        __import__(mod)
    except ImportError:
        missing.append(pkg)
if missing:
    print(f"Missing packages: {', '.join(missing)}")
    print(f"Fix: pip install -r backend/requirements.txt")
    sys.exit(1)

from config.settings import load_config
from engine.data_loader import DataLoader
from engine.scanner import TopologicalScanner
from app.models.schemas import AlertLevel

# ── Configuration ──
TRAIN_ROWS = 5000       # Calibration data size (normal operation)
MAX_SENSORS = 20        # Subsample for performance
WINDOW_SIZE = 60        # Samples per window (60s at 1Hz)
STEP_SIZE = 30          # Step between windows (30s)
TEST_ROWS = 50000       # Max test rows to load
DOMAIN = "manufacturing"  # HAI domain preset


def subsample(data, names, n):
    """Keep top-N sensors by variance (most informative)."""
    if n is None or data.shape[0] <= n:
        return data, names
    variances = np.var(data, axis=1)
    idx = np.sort(np.argsort(variances)[-n:])
    return data[idx], [names[i] for i in idx]


def print_header(text):
    """Print a section header."""
    print(f"\n{'─' * 56}")
    print(f"  {text}")
    print(f"{'─' * 56}")


def main():
    print("╔══════════════════════════════════════════════════════╗")
    print("║        Topo Scanner — Engine Validation             ║")
    print("║        HAI Dataset · Three-Gate Cascade             ║")
    print("╚══════════════════════════════════════════════════════╝")

    # ── Check dataset ──
    config = load_config(DOMAIN)
    loader = DataLoader(data_dir=os.environ["DATA_DIR"])
    info = loader.get_dataset_info("hai")

    if info.get("status") != "available":
        print(f"\n  HAI dataset not found at: {os.environ['DATA_DIR']}/hai/")
        print(f"  Download from: https://github.com/icsdataset/hai")
        print(f"  Required files: end-train1.csv, end-test1.csv, label-test1.csv")
        return

    print(f"\n  Dataset: HAI ({info.get('sensors', '?')} sensors, "
          f"{info.get('duration_hours', '?')}h)")
    print(f"  Domain:  {DOMAIN} (α={config.domain.weights.alpha}, "
          f"β={config.domain.weights.beta}, γ={config.domain.weights.gamma})")

    # ── Load labels to find attack region ──
    print_header("Loading labels")
    labels_full = loader.load_hai_labels(file_index=1, max_rows=TEST_ROWS)
    attack_indices = np.where(labels_full != 0)[0]

    if len(attack_indices) == 0:
        print("  No attacks found in label file — nothing to validate against.")
        return

    # Center test range around attack region
    attack_start = attack_indices[0]
    attack_end = attack_indices[-1]
    center = (attack_start + attack_end) // 2
    half = TEST_ROWS // 4  # Use middle portion
    range_start = max(0, center - half)
    range_end = min(len(labels_full), center + half)
    # Ensure we don't exceed loaded data
    range_end = min(range_end, TEST_ROWS)
    range_start = max(0, range_end - (half * 2))

    labels = labels_full[range_start:range_end]
    n_attack_samples = int(np.sum(labels != 0))

    print(f"  Total labels: {len(labels_full)}")
    print(f"  Attack samples: {len(attack_indices)} "
          f"(rows {attack_start}-{attack_end})")
    print(f"  Test range: {range_start}-{range_end} "
          f"({n_attack_samples} attack samples in range)")

    # ── Calibrate on normal data ──
    print_header("Calibration (Phase 0)")
    t_cal = time.time()

    train_data, train_names = loader.load_hai(
        mode="train", file_index=1, max_rows=TRAIN_ROWS
    )
    train_data, train_names = subsample(train_data, train_names, MAX_SENSORS)

    scanner = TopologicalScanner(config=config)
    scanner.calibrate(train_data, train_names)

    cal_time = time.time() - t_cal
    print(f"  Sensors: {train_data.shape[0]} (subsampled from {info.get('sensors', '?')})")
    print(f"  Sheaf maps: {len(scanner._sheaf_maps)}")
    print(f"  Calibration time: {cal_time:.1f}s")

    # ── Load test data ──
    print_header("Loading test data")
    test_full, test_names = loader.load_hai(
        mode="test", file_index=1, max_rows=range_end
    )
    test_data = test_full[:, range_start:range_end]
    test_data, test_names = subsample(test_data, test_names, MAX_SENSORS)

    total_windows = (test_data.shape[1] - WINDOW_SIZE) // STEP_SIZE
    print(f"  Test shape: {test_data.shape}")
    print(f"  Windows to scan: {total_windows}")

    # ── Run validation ──
    print_header(f"Scanning ({total_windows} windows)")

    # Counters
    tp = tn = fp = fn = 0
    gate_tp = {"sheaf": 0, "ricci": 0, "homology": 0}
    gate_fp = {"sheaf": 0, "ricci": 0, "homology": 0}
    gate_fn = {"sheaf": 0, "ricci": 0, "homology": 0}
    gate_tn = {"sheaf": 0, "ricci": 0, "homology": 0}
    scan_times = []

    t0 = time.time()

    for i in range(total_windows):
        s = i * STEP_SIZE
        e = s + WINDOW_SIZE
        window = test_data[:, s:e]
        window_labels = labels[s:e]
        actual = bool(np.any(window_labels != 0))

        # Time this scan
        t_scan = time.time()
        result = scanner.scan(
            data_source="hai",
            sensor_data=window,
            sensor_names=test_names,
            window_index=i,
        )
        scan_times.append(time.time() - t_scan)

        # Overall prediction
        pred = result.status in (AlertLevel.MID_ALERT, AlertLevel.HIGH_ALERT)

        if actual and pred:
            tp += 1
        elif not actual and not pred:
            tn += 1
        elif actual and not pred:
            fn += 1
        else:
            fp += 1

        # Per-gate metrics
        for gate in result.gate_results:
            gname = gate.gate_name
            if gname not in gate_tp:
                continue
            gate_pred = gate.triggered
            if actual and gate_pred:
                gate_tp[gname] += 1
            elif not actual and not gate_pred:
                gate_tn[gname] += 1
            elif actual and not gate_pred:
                gate_fn[gname] += 1
            else:
                gate_fp[gname] += 1

        # Progress
        if i % 20 == 0 or i == total_windows - 1:
            elapsed = time.time() - t0
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            eta = (total_windows - i - 1) / rate if rate > 0 else 0
            pct = 100 * (i + 1) / total_windows
            print(
                f"  [{pct:5.1f}%] "
                f"TP={tp} FP={fp} FN={fn} TN={tn} | "
                f"{rate:.1f} win/s | ETA {eta:.0f}s"
            )

    total_time = time.time() - t0

    # ── Results ──
    print_header("Overall Results")

    total = tp + tn + fp + fn
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
    acc = (tp + tn) / total if total > 0 else 0

    print(f"  Confusion Matrix:")
    print(f"                Predicted")
    print(f"                ALERT    CLEAN")
    print(f"  Actual ATTACK  {tp:5d}    {fn:5d}")
    print(f"  Actual CLEAN   {fp:5d}    {tn:5d}")
    print()
    print(f"  Precision:  {prec * 100:6.1f}%  (of alerts, how many are real)")
    print(f"  Recall:     {rec * 100:6.1f}%  (of attacks, how many caught)")
    print(f"  F1 Score:   {f1 * 100:6.1f}%")
    print(f"  Accuracy:   {acc * 100:6.1f}%")

    # ── Per-gate breakdown ──
    print_header("Per-Gate Performance")

    for gname in ["sheaf", "ricci", "homology"]:
        g_tp = gate_tp[gname]
        g_fp = gate_fp[gname]
        g_fn = gate_fn[gname]
        g_tn = gate_tn[gname]
        g_prec = g_tp / (g_tp + g_fp) if (g_tp + g_fp) > 0 else 0
        g_rec = g_tp / (g_tp + g_fn) if (g_tp + g_fn) > 0 else 0
        g_f1 = 2 * g_prec * g_rec / (g_prec + g_rec) if (g_prec + g_rec) > 0 else 0

        label = {
            "sheaf": "Gate 1 (Sheaf Consistency)",
            "ricci": "Gate 2 (Ollivier-Ricci)",
            "homology": "Gate 3 (Persistent Homology)",
        }[gname]

        print(f"\n  {label}")
        print(f"    TP={g_tp:4d}  FP={g_fp:4d}  FN={g_fn:4d}  TN={g_tn:4d}")
        print(f"    Precision: {g_prec * 100:5.1f}%  Recall: {g_rec * 100:5.1f}%  F1: {g_f1 * 100:5.1f}%")

    # ── Timing ──
    print_header("Performance")

    scan_arr = np.array(scan_times) * 1000  # to ms
    print(f"  Total time:    {total_time:.1f}s")
    print(f"  Windows:       {total_windows}")
    print(f"  Avg scan:      {np.mean(scan_arr):.0f}ms")
    print(f"  Median scan:   {np.median(scan_arr):.0f}ms")
    print(f"  P95 scan:      {np.percentile(scan_arr, 95):.0f}ms")
    print(f"  Max scan:      {np.max(scan_arr):.0f}ms")
    print(f"  Throughput:    {total_windows / total_time:.1f} windows/sec")

    print(f"\n{'═' * 56}")
    print(f"  Validation complete.")
    print(f"{'═' * 56}\n")


if __name__ == "__main__":
    main()