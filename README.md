# Topo Scanner — OT Network Security

**Netcompany Hackathon Thessaloniki 2026**
AI-Powered Cybersecurity Control Center for OT/ICS Networks

## Architecture

Two-mode scanning system:

| Mode | Engine | Speed | Use Case |
|------|--------|-------|----------|
| **Quick Scan** | GPT-4.1 log analysis | ~3s | Default — finds all common threats |
| **Deep Scan** | Topological 3-Gate Cascade + GPT | ~10s | On-demand — mathematical proof of coordinated attacks |

### Quick Scan (Default)
GPT analyzes network logs against OT-specific rules:
- Cross-segment violations (DMZ→PLC = CRITICAL)
- Unauthorized protocol access (Modbus from non-SCADA)
- Reconnaissance patterns (port scans, brute force)
- Lateral movement indicators

### Deep Scan (On-Demand)
Three-gate topological cascade:
1. **Sheaf Laplacian** — Physical consistency check (sensor relationships)
2. **Ollivier-Ricci Curvature** — Bridge/bottleneck detection
3. **Persistent Homology** — Mathematical proof of coordinated multi-node attacks

## Quick Start

```bash
# Docker
docker-compose up --build

# Local dev
cd backend && pip install -r requirements.txt && python server.py
cd frontend && npm install && npm start
```

## Stack
- **Backend**: Flask + OpenAI + GUDHI + NetworkX + SciPy
- **Frontend**: React + D3.js
- **Detection**: Persistent Homology, Sheaf Laplacian, Ollivier-Ricci Curvature
- **Connectivity**: SSH (Netmiko) for Cisco/Juniper/Palo Alto
