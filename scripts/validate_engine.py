"""
scripts/validate_engine.py
Offline validation against HAI dataset.

Usage:
    cd topo-scanner-v7
    pip install -r backend/requirements.txt
    python scripts/validate_engine.py
"""

import sys, os, time
import numpy as np
import pandas as pd
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
BACKEND_DIR = PROJECT_ROOT / "backend"

sys.path.insert(0, str(BACKEND_DIR))
os.environ.setdefault("DB_PATH", str(PROJECT_ROOT / "db" / "topo_scanner.db"))
os.environ.setdefault("DATA_DIR", str(BACKEND_DIR / "data"))

# Dependency check
missing = []
for pkg in ["yaml", "scipy", "gudhi", "dtaidistance", "statsmodels", "networkx", "dotenv"]:
    try: __import__(pkg)
    except ImportError: missing.append({"yaml":"pyyaml","dotenv":"python-dotenv"}.get(pkg, pkg))
if missing:
    print(f"Missing: {', '.join(missing)}\nFix: pip install -r backend/requirements.txt")
    sys.exit(1)

from config.settings import load_config
from engine.data_loader import DataLoader
from engine.scanner import TopologicalScanner
from app.models.schemas import AlertLevel

TRAIN_ROWS  = 5000
WINDOW_SIZE = 60
STEP_SIZE   = 30
DOMAIN      = "manufacturing"
MAX_SENSORS = 20
TEST_RANGE  = 5000


def subsample(data, names, n):
    if n is None or data.shape[0] <= n: return data, names
    idx = np.sort(np.argsort(np.var(data, axis=1))[-n:])
    return data[idx], [names[i] for i in idx]


def find_attacks(label_path, scan_range):
    df = pd.read_csv(label_path, low_memory=False)
    labels = df['attack'].values if 'attack' in df.columns else df.iloc[:,-1].values
    attacks = np.where(labels != 0)[0]
    if len(attacks) == 0: return 0, min(scan_range, len(labels)), labels
    center = (attacks[0] + attacks[-1]) // 2
    half = scan_range // 2
    start = max(0, center - half)
    end = min(len(labels), start + scan_range)
    start = max(0, end - scan_range)
    n_att = int(np.sum(labels[start:end] != 0))
    print(f"  Labels: {len(labels)} total, {len(attacks)} attack rows")
    print(f"  Test range: {start}-{end}, contains {n_att} attack rows")
    return start, end, labels


def main():
    print("Topo Scanner - Validation\n")
    config = load_config(DOMAIN)
    loader = DataLoader(data_dir=os.environ["DATA_DIR"])
    info = loader.get_dataset_info("hai")
    if info.get("status") != "available":
        print(f"HAI not found at {os.environ['DATA_DIR']}/hai/"); return

    label_path = Path(os.environ["DATA_DIR"]) / "hai" / "label-test1.csv"
    start, end, all_labels = find_attacks(label_path, TEST_RANGE)

    print("\nCalibrating...")
    train, names = loader.load_hai(mode="train", file_index=1, max_rows=TRAIN_ROWS)
    train, names = subsample(train, names, MAX_SENSORS)
    scanner = TopologicalScanner(config=config)
    scanner.calibrate(train, names)
    print(f"  {len(scanner._sheaf_maps)} sheaf maps, {train.shape[0]} sensors")

    print("\nLoading test data...")
    test_full, tnames = loader.load_hai(mode="test", file_index=1, max_rows=end)
    test = test_full[:, start:end]
    test, tnames = subsample(test, tnames, MAX_SENSORS)
    labels = all_labels[start:end]

    total_win = (test.shape[1] - WINDOW_SIZE) // STEP_SIZE
    print(f"\nScanning {total_win} windows...")
    tp = tn = fp = fn = 0
    t0 = time.time()

    for i, s in enumerate(range(0, test.shape[1] - WINDOW_SIZE, STEP_SIZE)):
        w = test[:, s:s+WINDOW_SIZE]
        actual = bool(np.any(labels[s:s+WINDOW_SIZE] != 0))
        r = scanner.scan(data_source="hai", sensor_data=w, sensor_names=tnames, window_index=i)
        pred = r.status in [AlertLevel.MID_ALERT, AlertLevel.HIGH_ALERT]
        if actual and pred: tp += 1
        elif not actual and not pred: tn += 1
        elif actual and not pred: fn += 1
        else: fp += 1
        if i % 30 == 0:
            elapsed = time.time() - t0
            eta = (total_win - i) / ((i+1)/elapsed) if elapsed > 0 else 0
            print(f"  [{100*(i+1)/total_win:5.1f}%] TP={tp} FP={fp} FN={fn} TN={tn} | ETA {eta:.0f}s")

    total = tp+tn+fp+fn
    prec = tp/(tp+fp) if tp+fp else 0
    rec = tp/(tp+fn) if tp+fn else 0
    f1 = 2*prec*rec/(prec+rec) if prec+rec else 0

    print(f"\n{'='*50}")
    print(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"  Precision: {prec*100:.1f}%")
    print(f"  Recall:    {rec*100:.1f}%")
    print(f"  F1:        {f1*100:.1f}%")
    print(f"  Time:      {time.time()-t0:.1f}s")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()
