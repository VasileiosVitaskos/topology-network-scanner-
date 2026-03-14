# Topo Scanner

**OT Network Security — Topological Anomaly Detection**
Netcompany Hackathon Thessaloniki 2026

---

## What It Does

Topo Scanner detects coordinated cyberattacks on industrial control networks (OT/ICS). It catches threats that conventional security tools miss: attackers who compromise multiple devices simultaneously while keeping each individual sensor within its "normal" range.

**How it works in plain terms:**

The system watches all sensors in your industrial network simultaneously and builds a map of how they normally relate to each other. When an attacker manipulates multiple devices in a coordinated way, the *shape* of these relationships changes — even if each sensor individually looks fine. Topo Scanner detects this shape change using three independent checks:

1. **Physical Consistency Check** — Do sensors that should track each other (like a valve and a flow meter) still agree? If the attacker spoofs one, the relationship breaks.

2. **Bridge Detection** — Is there suspicious traffic bridging between network segments that are normally isolated? This is how lateral movement looks from a topology perspective.

3. **Coordination Proof** — Are four or more nodes behaving in a coordinated pattern that cannot happen by accident? This is the definitive signal — if this check fires, there is mathematically guaranteed coordination happening.

Each check runs independently. Zero triggers means clean. One or two means investigate. All three means confirmed coordinated attack.

---

## Quick Start

### 1. Install

```
cd topo-scanner-v7
pip install -r backend/requirements.txt
```

If `gudhi` fails on Windows, use: `conda install -c conda-forge gudhi`

### 2. Run with Docker

```
docker-compose up --build
```

Open http://localhost:3000

### 3. Run without Docker

Terminal 1 (backend):
```
cd backend
python -m flask run --host=0.0.0.0 --port=5000
```

Terminal 2 (frontend):
```
cd frontend
npm install
npm start
```

Open http://localhost:3000

### 4. Run the offline validation

```
python scripts/validate_engine.py
```

This tests the detection engine against the HAI dataset (real industrial attacks) and shows precision, recall, and F1-score.

---

## Connecting a Device

### From the UI

1. Click **"Connect Device"** in the top bar
2. Enter the device IP, SSH credentials, and select device type
3. Click Connect

Supported: Cisco IOS, Cisco IOS-XE, Cisco ASA, Juniper JunOS, Palo Alto PAN-OS.

All commands are **read-only** (`show log`, `show arp`, `show ip route`, `show interfaces`). The system never changes device configuration.

### From code (GNS3 / EVE-NG lab)

```python
from connectors.ssh_connector import SSHConnector

conn = SSHConnector(host="192.168.1.1", username="admin", password="cisco", device_type="cisco_ios")
conn.connect()
logs = conn.get_logs()
conn.disconnect()
```

### From file

```python
from connectors.file_connector import FileConnector

conn = FileConnector(file_path="firewall_export.csv")
logs = conn.get_logs()
```

---

## Project Structure

```
topo-scanner-v7/
├── backend/
│   ├── engine/           # Detection engine
│   │   ├── scanner.py    #   Three-check orchestrator
│   │   ├── graph_builder.py  # Sensor relationship mapping
│   │   ├── detector.py   #   Alert classification
│   │   └── data_loader.py    # Dataset loading
│   ├── app/models/       # Data models
│   ├── config/           # Settings and domain configs
│   ├── connectors/       # SSH, file, and mock connectors
│   └── data/hai/         # HAI dataset (CSV files)
├── frontend/src/         # React dashboard
├── scripts/              # Validation scripts
└── docker-compose.yml
```

---

## The HAI Dataset

The engine is validated against the **HAI dataset** — real sensor data from an industrial testbed with injected coordinated attacks. The test set contains labeled attack windows that manipulate multiple sensors simultaneously, which is exactly what Topo Scanner is designed to detect.

Required files in `backend/data/hai/`:
- `end-train1.csv` — Normal operation (for calibration)
- `end-test1.csv` — Contains attacks
- `label-test1.csv` — Ground truth labels

Download from: https://github.com/icsdataset/hai

---

## Performance

The engine automatically limits the number of sensors it processes simultaneously to avoid high CPU usage. Default is 30 sensors (configurable in `backend/config/domains.yaml` via `max_sensors`). This keeps scan times under 1 second per window on a standard laptop.

| Sensors | Time per scan | RAM needed |
|---------|--------------|------------|
| 20      | ~200ms       | 2 GB       |
| 30      | ~500ms       | 4 GB       |
| 86 (all)| ~3s          | 8+ GB      |

---

## Tech Stack

- **Backend:** Python, Flask, GUDHI, NetworkX, SciPy
- **Frontend:** React, D3.js
- **AI:** OpenAI GPT-4.1 (quick scan and chat)
- **Connectivity:** Netmiko (SSH)
- **Deployment:** Docker Compose
