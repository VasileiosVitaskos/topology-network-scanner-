# Topo Scanner v7

**OT Network Security — Topological Anomaly Detection**
Netcompany Hackathon Thessaloniki 2026

---

## What It Does

Topo Scanner detects coordinated cyberattacks on industrial control networks (OT/ICS). It catches threats that conventional security tools miss: attackers who compromise multiple devices simultaneously while keeping each individual sensor within its "normal" range.

The system watches all sensors simultaneously and builds a map of how they normally relate to each other. When an attacker manipulates multiple devices in a coordinated way, the *shape* of these relationships changes — even if each sensor individually looks fine. Topo Scanner detects this shape change using three independent mathematical gates:

| Gate | Method | What it detects | Speed |
|------|--------|----------------|-------|
| **Gate 1** | Sheaf Consistency | Physical relationship violations (e.g., valve vs flow mismatch) | ~1ms |
| **Gate 2** | Ollivier-Ricci Curvature | Network bridges / lateral movement between segments | ~50ms |
| **Gate 3** | Persistent Homology (GUDHI) | Coordinated multi-node attacks (β₂ > 0 = mathematical proof) | ~200ms |

Zero gates triggered = clean. One or two = investigate. All three = confirmed coordinated attack.

---

## Quick Start (Docker — recommended)

```bash
# 1. Clone and enter the project
cd topo-scanner-v7

# 2. Create your .env file
cp .env.example .env
# Edit .env and add your OpenAI API key (optional — engine works without it)

# 3. Build and run
docker-compose up --build

# 4. Open the dashboard
# http://localhost:3000
```

The backend runs on port 5000, the frontend on port 3000.

---

## Setup Without Docker

### Prerequisites

- **Python 3.10+** (3.11 recommended)
- **Node.js 18+** (for the React frontend)
- **pip** or **conda** (for Python packages)

### Linux / WSL

```bash
# 1. System dependencies (needed for GUDHI C++ compilation)
sudo apt update
sudo apt install -y python3-dev python3-pip gcc g++ cmake libboost-all-dev

# 2. Clone and enter
cd topo-scanner-v7

# 3. Create .env
cp .env.example .env
# Edit .env — set OPENAI_API_KEY if you want AI analysis
# Set local paths:
#   DB_PATH=./db/topo_scanner.db
#   DATA_DIR=./backend/data

# 4. Install Python dependencies
pip install -r backend/requirements.txt

# 5. Create the db directory
mkdir -p db

# 6. Start the backend
cd backend
python server.py
# Backend running on http://localhost:5000

# 7. In a new terminal — start the frontend
cd frontend
npm install
npm start
# Frontend running on http://localhost:3000
```

### Windows (native, no WSL)

```powershell
# 1. Install Python 3.11 from python.org (check "Add to PATH")
# 2. Install Node.js 18+ from nodejs.org

# 3. Clone and enter
cd topo-scanner-v7

# 4. Create .env
copy .env.example .env
# Edit .env with notepad — set paths:
#   DB_PATH=./db/topo_scanner.db
#   DATA_DIR=./backend/data

# 5. Install Python packages
pip install -r backend/requirements.txt

# If GUDHI fails (common on Windows without C++ build tools):
#   Option A: Install Visual Studio Build Tools, then retry pip install gudhi
#   Option B: Use conda instead:
#     conda install -c conda-forge gudhi
#     pip install -r backend/requirements.txt  (will skip gudhi, install rest)

# 6. Create db directory
mkdir db

# 7. Start backend
cd backend
python server.py

# 8. New terminal — start frontend
cd frontend
npm install
npm start
```

### macOS

```bash
# 1. Install Homebrew dependencies
brew install cmake boost python@3.11 node

# 2. Follow the Linux/WSL steps above (same commands)
```

---

## Getting the Datasets

The engine is validated against real industrial security datasets. You need at least the HAI dataset to run the validation.

### HAI Dataset (required for validation)

The HAI (HIL-based Augmented ICS) dataset contains real sensor data from an industrial testbed with injected coordinated attacks.

```bash
# 1. Download from GitHub
git clone https://github.com/icsdataset/hai.git /tmp/hai-dataset

# 2. Copy the needed files to your project
mkdir -p backend/data/hai
cp /tmp/hai-dataset/hai-22.04/end-train1.csv backend/data/hai/
cp /tmp/hai-dataset/hai-22.04/end-test1.csv backend/data/hai/
cp /tmp/hai-dataset/hai-22.04/label-test1.csv backend/data/hai/

# 3. Verify
ls -la backend/data/hai/
# Should show: end-train1.csv, end-test1.csv, label-test1.csv
```

**Note:** The HAI repo contains multiple versions (hai-21.03, hai-22.04, etc.). Any version works — the loader auto-detects the format. The 22.04 version has ~86 sensors at 1-second sampling.

### BATADAL Dataset (optional)

Water distribution network attack dataset.

```bash
# Download from: https://www.batadal.net/data.html
mkdir -p backend/data/batadal
# Place files: BATADAL_dataset03.csv, BATADAL_dataset04.csv, BATADAL_test_dataset.csv
```

### SWaT Dataset (optional)

Secure Water Treatment testbed data. Requires registration.

```bash
# Register at: https://itrust.sutd.edu.sg/itrust-labs_datasets/
mkdir -p backend/data/swat
# Place CSV files in backend/data/swat/
```

---

## Running the Validation

The validation script tests the three-gate engine against labeled attack data and reports precision, recall, F1 score, and per-gate performance.

```bash
# From the project root
cd topo-scanner-v7
python scripts/validate_engine.py
```

Example output:
```
╔══════════════════════════════════════════════════════╗
║        Topo Scanner — Engine Validation             ║
╚══════════════════════════════════════════════════════╝

  Dataset: HAI (86 sensors, 13.9h)
  Domain:  manufacturing (α=0.2, β=0.3, γ=0.5)

──────────────────────────────────────────────────────
  Calibration (Phase 0)
──────────────────────────────────────────────────────
  Sensors: 20 (subsampled from 86)
  Sheaf maps: 47
  Calibration time: 3.2s

──────────────────────────────────────────────────────
  Overall Results
──────────────────────────────────────────────────────
  Precision:   72.3%
  Recall:      68.1%
  F1 Score:    70.1%

──────────────────────────────────────────────────────
  Per-Gate Performance
──────────────────────────────────────────────────────
  Gate 1 (Sheaf Consistency)  — Precision: 65% Recall: 78% F1: 71%
  Gate 2 (Ollivier-Ricci)    — Precision: 45% Recall: 32% F1: 37%
  Gate 3 (Persistent Homology)— Precision: 80% Recall: 55% F1: 65%
```

---

## Connecting a Real Device

### From the UI

1. Click **"+ Device"** in the header
2. Enter the device IP, port, SSH credentials
3. Select device type (Cisco IOS, Juniper, Palo Alto, etc.)
4. Click **Connect**

The system will SSH into the device, run read-only commands, pull logs and ARP tables, and automatically add discovered nodes to the topology. Select "Live / Simulation" dataset and run a scan to analyze the collected data.

### Supported Platforms

| Platform | device_type | Commands |
|----------|------------|----------|
| Cisco IOS | `cisco_ios` | show log, show arp, show ip route, show interfaces |
| Cisco IOS-XE | `cisco_xe` | show log, show arp, show ip route, show interfaces |
| Cisco ASA | `cisco_asa` | show log, show arp, show route, show interface |
| Juniper JunOS | `juniper` | show log messages, show arp, show route, show interfaces terse |
| Palo Alto PAN-OS | `paloalto_panos` | show log traffic, show arp all, show routing route |

All commands are **read-only**. The system never changes device configuration.

### From Code (GNS3 / EVE-NG Lab)

```python
from connectors.ssh_connector import SSHConnector

conn = SSHConnector("192.168.1.1", "admin", "cisco", device_type="cisco_ios")
if conn.connect():
    logs = conn.get_logs()        # LogEntry objects
    topology = conn.get_topology() # ARP table
    routes = conn.get_routes()     # Routing table
    conn.disconnect()
```

---

## Project Structure

```
topo-scanner-v7/
├── backend/
│   ├── server.py              # Flask API (all routes)
│   ├── engine/                # Detection engine
│   │   ├── scanner.py         #   Three-gate orchestrator
│   │   ├── graph_builder.py   #   Distance matrix (Pearson + DTW + Granger)
│   │   ├── detector.py        #   Alert classification + temporal buffer
│   │   ├── data_loader.py     #   Dataset loading (HAI, SWaT, BATADAL)
│   │   └── log_transformer.py #   Network logs → time series
│   ├── connectors/            # Data source adapters
│   │   ├── ssh_connector.py   #   SSH to Cisco/Juniper/PAN-OS
│   │   ├── file_connector.py  #   CSV/syslog file import
│   │   └── mock_connector.py  #   Synthetic data generator
│   ├── app/models/            # Data models
│   │   ├── schemas.py         #   ScanResult, GateResult, LogEntry, etc.
│   │   └── database.py        #   SQLite utilities
│   ├── config/                # Configuration
│   │   ├── settings.py        #   Config loader (.env + domains.yaml)
│   │   └── domains.yaml       #   Physics-informed domain presets
│   └── data/                  # Datasets (not committed to git)
│       ├── hai/               #   HAI CSV files
│       ├── swat/              #   SWaT CSV files
│       └── batadal/           #   BATADAL CSV files
├── frontend/
│   ├── src/
│   │   ├── App.js             #   Main layout + scan controls
│   │   ├── App.css            #   Monochrome blue theme
│   │   ├── components/        #   UI components
│   │   └── services/api.js    #   Backend API client
│   └── public/index.html
├── scripts/
│   └── validate_engine.py     #   Offline validation against HAI
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## Configuration

All configuration is in two files:

**`.env`** — Secrets and paths (copy from `.env.example`):
- `OPENAI_API_KEY` — Optional. Powers Quick Scan AI analysis and Chat.
- `DB_PATH` — SQLite database location
- `DATA_DIR` — Where dataset CSVs live
- `TOPO_DEFAULT_DOMAIN` — Default domain preset

**`backend/config/domains.yaml`** — Domain-specific engine parameters:
- Distance metric weights (α=Pearson, β=DTW, γ=Granger)
- Sliding window size and step
- Max sensors to process
- Detection thresholds

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Detection Engine** | Python, GUDHI, NetworkX, SciPy, dtaidistance |
| **Backend API** | Flask, Gunicorn, SQLite |
| **Frontend** | React 18, D3.js |
| **AI Analysis** | OpenAI GPT-4.1 (optional) |
| **Device Connectivity** | Netmiko (SSH) |
| **Deployment** | Docker Compose |

---

## Performance

The engine automatically subsamples sensors to stay within performance bounds. Configurable via `max_sensors` in `domains.yaml`.

| Sensors | Avg scan time | RAM |
|---------|--------------|-----|
| 20 | ~100ms | 2 GB |
| 30 | ~300ms | 4 GB |
| 50 | ~800ms | 6 GB |
| 86 (all) | ~3s | 8+ GB |