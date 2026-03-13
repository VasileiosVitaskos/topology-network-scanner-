"""
Topo Scanner v7 — Self-contained Flask Backend
================================================
Two-mode architecture:
  1. QUICK SCAN (default): GPT analyzes network logs → human-readable findings
  2. DEEP SCAN (on-demand): Topological 3-gate cascade → mathematical proof

All routes in one file for hackathon simplicity.
"""

import os
import sys
import time
import json
import random
import sqlite3
import traceback
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager
from typing import List, Dict, Optional, Any

from flask import Flask, request, jsonify, Response
from flask_cors import CORS

# ── OpenAI ──
from openai import OpenAI

# ══════════════════════════════════════════════════════════════
# APP FACTORY
# ══════════════════════════════════════════════════════════════

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ── Config ──
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1")
DB_PATH = os.getenv("DB_PATH", "/app/db/topo_scanner.db")
DATA_DIR = os.getenv("DATA_DIR", "/app/data")
MOCK_API_URL = os.getenv("MOCK_API_URL", "http://topo-mock-api:8000")

# ── OpenAI Client ──
ai_client = None
if OPENAI_API_KEY:
    ai_client = OpenAI(api_key=OPENAI_API_KEY)

# ── In-memory scan state ──
_scan_history: List[Dict] = []
_scan_counter = 0
_last_logs: List[Dict] = []
_topology_nodes: List[Dict] = []
_scanner_instance = None
_scanner_calibrated_for: str = ""  # which dataset we calibrated for
_chat_histories: Dict[str, List] = {}

# ── Live device state (SSH-pulled logs from real hardware) ──
_live_device_logs: List[Dict] = []
_live_device_info: Dict = {}

# ══════════════════════════════════════════════════════════════
# OT NETWORK SIMULATION (for demo)
# ══════════════════════════════════════════════════════════════

OT_SEGMENTS = {
    "plc_network": {
        "hosts": ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"],
        "protocols": ["Modbus", "Ethernet/IP"],
        "names": {"192.168.1.10": "PLC-Stage1", "192.168.1.11": "PLC-Stage2",
                  "192.168.1.12": "PLC-Stage3", "192.168.1.13": "PLC-Stage4"}
    },
    "scada_network": {
        "hosts": ["192.168.2.20", "192.168.2.21"],
        "protocols": ["OPC-UA", "SMB"],
        "names": {"192.168.2.20": "HMI-Main", "192.168.2.21": "Historian"}
    },
    "workstation_vlan": {
        "hosts": ["192.168.3.50", "192.168.3.51", "192.168.3.52"],
        "protocols": ["HTTP", "DNS", "SSH"],
        "names": {"192.168.3.50": "WS-Eng1", "192.168.3.51": "WS-Eng2", "192.168.3.52": "WS-Ops1"}
    },
    "dmz": {
        "hosts": ["10.0.0.5", "10.0.0.6"],
        "protocols": ["HTTPS", "DNS"],
        "names": {"10.0.0.5": "FW-External", "10.0.0.6": "DNS-Public"}
    },
}

PROTO_PORT = {
    "HTTP": 80, "HTTPS": 443, "DNS": 53, "SSH": 22, "SMB": 445,
    "SMTP": 25, "Modbus": 502, "OPC-UA": 4840, "Ethernet/IP": 44818,
    "RDP": 3389, "Telnet": 23
}

# ── Attack Scenarios for Demo ──
ATTACK_SCENARIOS = [
    {
        "name": "Lateral Movement via SMB",
        "description": "Workstation WS-Eng1 scanning PLC network using SMB protocol",
        "logs": lambda t: [
            {"timestamp": t, "src_ip": "192.168.3.50", "dst_ip": "192.168.1.10",
             "src_port": random.randint(49152, 65535), "dst_port": 445,
             "protocol": "SMB", "action": "ALLOW", "bytes": random.randint(1024, 32768),
             "duration": round(random.uniform(0.1, 2.0), 3), "segment": "workstation_vlan>plc_network"},
            {"timestamp": t + 0.5, "src_ip": "192.168.3.50", "dst_ip": "192.168.1.11",
             "src_port": random.randint(49152, 65535), "dst_port": 445,
             "protocol": "SMB", "action": "ALLOW", "bytes": random.randint(1024, 32768),
             "duration": round(random.uniform(0.1, 2.0), 3), "segment": "workstation_vlan>plc_network"},
            {"timestamp": t + 1.0, "src_ip": "192.168.3.50", "dst_ip": "192.168.1.12",
             "src_port": random.randint(49152, 65535), "dst_port": 445,
             "protocol": "SMB", "action": "DENY", "bytes": 0,
             "duration": 0.01, "segment": "workstation_vlan>plc_network"},
        ]
    },
    {
        "name": "Modbus Injection Attempt",
        "description": "External host attempting Modbus write commands to PLCs",
        "logs": lambda t: [
            {"timestamp": t, "src_ip": "10.0.0.5", "dst_ip": "192.168.1.10",
             "src_port": random.randint(49152, 65535), "dst_port": 502,
             "protocol": "Modbus", "action": "ALLOW", "bytes": 256,
             "duration": 0.05, "segment": "dmz>plc_network"},
            {"timestamp": t + 2, "src_ip": "10.0.0.5", "dst_ip": "192.168.1.11",
             "src_port": random.randint(49152, 65535), "dst_port": 502,
             "protocol": "Modbus", "action": "ALLOW", "bytes": 256,
             "duration": 0.05, "segment": "dmz>plc_network"},
            {"timestamp": t + 4, "src_ip": "10.0.0.5", "dst_ip": "192.168.1.10",
             "src_port": random.randint(49152, 65535), "dst_port": 502,
             "protocol": "Modbus", "action": "ALLOW", "bytes": 512,
             "duration": 0.08, "segment": "dmz>plc_network"},
        ]
    },
    {
        "name": "Port Scan Reconnaissance",
        "description": "Sequential port scanning from workstation targeting SCADA network",
        "logs": lambda t: [
            {"timestamp": t + i * 0.1, "src_ip": "192.168.3.51", "dst_ip": "192.168.2.20",
             "src_port": random.randint(49152, 65535), "dst_port": port,
             "protocol": "TCP", "action": random.choice(["DENY", "DENY", "ALLOW"]),
             "bytes": 64, "duration": 0.01, "segment": "workstation_vlan>scada_network"}
            for i, port in enumerate([22, 23, 80, 443, 445, 502, 3389, 4840, 8080, 8443])
        ]
    },
    {
        "name": "Normal OT Traffic",
        "description": "Routine sensor polling and SCADA communications",
        "logs": lambda t: [
            {"timestamp": t + i, "src_ip": "192.168.2.20", "dst_ip": f"192.168.1.{10+i}",
             "src_port": random.randint(49152, 65535), "dst_port": 502,
             "protocol": "Modbus", "action": "ALLOW",
             "bytes": random.randint(64, 256), "duration": round(random.uniform(0.01, 0.1), 3),
             "segment": "scada_network>plc_network"}
            for i in range(4)
        ] + [
            {"timestamp": t + 5, "src_ip": "192.168.2.21", "dst_ip": "192.168.2.20",
             "src_port": random.randint(49152, 65535), "dst_port": 4840,
             "protocol": "OPC-UA", "action": "ALLOW",
             "bytes": random.randint(512, 2048), "duration": round(random.uniform(0.05, 0.3), 3),
             "segment": "scada_network"}
        ]
    },
]


def generate_logs(count: int = 50, inject_attack: bool = None) -> List[Dict]:
    """Generate a batch of realistic OT network logs."""
    logs = []
    base_t = time.time() - count

    # Decide if this batch has an attack
    if inject_attack is None:
        inject_attack = random.random() < 0.4  # 40% chance

    if inject_attack:
        # Pick attack scenario (not the last one which is normal)
        scenario = random.choice(ATTACK_SCENARIOS[:-1])
        attack_start = base_t + random.randint(10, count - 10)
        attack_logs = scenario["logs"](attack_start)
        for log in attack_logs:
            log["_scenario"] = scenario["name"]
            log["_label"] = "Attack"
        logs.extend(attack_logs)

    # Fill rest with normal traffic
    for i in range(count - len(logs)):
        seg_name = random.choice(list(OT_SEGMENTS.keys()))
        seg = OT_SEGMENTS[seg_name]
        src = random.choice(seg["hosts"])
        dst = random.choice(seg["hosts"])
        if random.random() < 0.2:
            other_seg = random.choice(list(OT_SEGMENTS.keys()))
            dst = random.choice(OT_SEGMENTS[other_seg]["hosts"])
        proto = random.choice(seg["protocols"])
        logs.append({
            "timestamp": base_t + i,
            "src_ip": src, "dst_ip": dst,
            "src_port": random.randint(49152, 65535),
            "dst_port": PROTO_PORT.get(proto, random.randint(1024, 65535)),
            "protocol": proto,
            "action": "ALLOW" if random.random() < 0.95 else "DENY",
            "bytes": random.randint(64, 8192),
            "duration": round(random.uniform(0.01, 2.0), 3),
            "segment": seg_name,
            "_label": "Normal",
        })

    logs.sort(key=lambda x: x["timestamp"])
    return logs


# ══════════════════════════════════════════════════════════════
# GPT LOG ANALYSIS — The "Quick Scan" brain
# ══════════════════════════════════════════════════════════════

SYSTEM_PROMPT_ANALYSIS = """You are an OT/ICS Cybersecurity Analyst AI embedded in the Topo Scanner system.
You analyze firewall and network logs from Operational Technology (OT) environments: SCADA systems, PLCs, HMIs, Historians.

Your job:
1. Analyze the provided network logs for security anomalies
2. Focus on OT-specific threats: unauthorized Modbus/OPC-UA traffic, cross-segment violations, lateral movement, reconnaissance
3. Provide a CLEAR, ACTIONABLE report

IMPORTANT CONTEXT:
- PLC network (192.168.1.x): PLCs controlling physical processes. Only SCADA should talk to them.
- SCADA network (192.168.2.x): HMI and Historian. Authorized to poll PLCs.
- Workstation VLAN (192.168.3.x): Engineering workstations. Should NOT directly access PLCs.
- DMZ (10.0.0.x): External-facing. Should NEVER reach PLCs directly.

CROSS-SEGMENT RULES:
- Workstation → PLC: VIOLATION (should go through SCADA)
- DMZ → PLC: CRITICAL VIOLATION
- DMZ → SCADA: SUSPICIOUS
- SCADA → PLC: NORMAL (polling)
- Any → port 502 (Modbus): Only from SCADA network
- Any → port 4840 (OPC-UA): Only from SCADA network

Report format — respond in this JSON structure:
{
  "threat_level": "CLEAN" | "SUSPICIOUS" | "CRITICAL",
  "summary": "One sentence executive summary",
  "findings": [
    {
      "severity": "info" | "warning" | "critical",
      "title": "Short title",
      "detail": "What happened, why it matters, what to do",
      "involved_ips": ["ip1", "ip2"],
      "evidence": "Key log entries that prove this"
    }
  ],
  "network_health": {
    "total_events": <int>,
    "denied_events": <int>,
    "cross_segment_events": <int>,
    "protocols_seen": ["proto1", "proto2"],
    "active_hosts": <int>
  },
  "recommendations": ["Action 1", "Action 2"]
}"""

SYSTEM_PROMPT_CHAT = """You are the AI Security Analyst for Topo Scanner — an OT/ICS cybersecurity system.
You help operators understand network security findings, explain threats, and recommend actions.

You have access to the latest scan results and network context. Be concise, technical when needed, 
but always explain the "so what" — why does this matter for the physical process?

Remember: in OT environments, a compromised PLC can cause physical damage (think Stuxnet).
Cross-segment violations are not just IT security issues — they're safety issues.

When asked about the topological analysis (Deep Scan), explain:
- Sheaf Laplacian: checks if sensor readings are physically consistent (like checking if valve position matches flow rate)
- Ollivier-Ricci Curvature: finds network bridges/bottlenecks that an attacker might exploit
- Persistent Homology: mathematically proves coordinated multi-node attacks (H₂ > 0 = 4+ nodes acting together)

Keep responses focused and actionable. You're talking to a SOC operator, not a math professor."""


def gpt_analyze_logs(logs: List[Dict]) -> Dict:
    """Send logs to GPT for analysis. Returns structured findings."""
    if not ai_client:
        return _fallback_analysis(logs)

    # Prepare log summary for GPT (not all logs, just the interesting ones)
    log_summary = _prepare_log_summary(logs)

    try:
        response = ai_client.chat.completions.create(
            model=OPENAI_MODEL,
            temperature=0.1,
            max_tokens=2000,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT_ANALYSIS},
                {"role": "user", "content": f"Analyze these OT network logs:\n\n{log_summary}\n\nRespond ONLY with the JSON structure specified."}
            ],
            response_format={"type": "json_object"},
        )

        content = response.choices[0].message.content
        return json.loads(content)

    except Exception as e:
        print(f"GPT analysis failed: {e}")
        return _fallback_analysis(logs)


def gpt_chat(user_message: str, context: Dict = None, history: List = None) -> str:
    """Chat with GPT about network security. Returns response text."""
    if not ai_client:
        return "AI analysis unavailable — API key not configured. The topological engine is still fully operational."

    messages = [{"role": "system", "content": SYSTEM_PROMPT_CHAT}]

    # Add scan context
    if context:
        ctx_str = json.dumps(context, indent=2, default=str)[:3000]
        messages.append({"role": "system", "content": f"Latest scan context:\n{ctx_str}"})

    # Add chat history
    if history:
        for h in history[-8:]:  # Last 8 messages
            messages.append({"role": h["role"], "content": h["content"]})

    messages.append({"role": "user", "content": user_message})

    try:
        response = ai_client.chat.completions.create(
            model=OPENAI_MODEL,
            temperature=0.3,
            max_tokens=1000,
            messages=messages,
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"AI temporarily unavailable: {str(e)}"


def _prepare_log_summary(logs: List[Dict]) -> str:
    """Prepare a concise log summary for GPT (not raw dump)."""
    lines = []
    lines.append(f"Total events: {len(logs)}")

    # Count by action
    deny_count = sum(1 for l in logs if l.get("action") == "DENY")
    lines.append(f"DENY events: {deny_count}")

    # Cross-segment events
    cross = [l for l in logs if ">" in l.get("segment", "")]
    lines.append(f"Cross-segment events: {len(cross)}")

    # Unique source/dest pairs
    pairs = set()
    for l in logs:
        pairs.add(f"{l.get('src_ip', '?')} → {l.get('dst_ip', '?')}:{l.get('dst_port', '?')}")
    lines.append(f"Unique flows: {len(pairs)}")
    lines.append("")

    # Show the most interesting logs (cross-segment, denies, unusual ports)
    interesting = [l for l in logs if (
        ">" in l.get("segment", "") or
        l.get("action") == "DENY" or
        l.get("dst_port") in [502, 4840, 22, 3389, 445, 23]
    )]

    # Also show a sample of normal traffic
    normal = [l for l in logs if l not in interesting][:5]

    lines.append("=== FLAGGED EVENTS ===")
    for l in interesting[:30]:
        lines.append(
            f"[{l.get('action', '?')}] {l.get('src_ip', '?')}:{l.get('src_port', '?')} → "
            f"{l.get('dst_ip', '?')}:{l.get('dst_port', '?')} "
            f"proto={l.get('protocol', '?')} bytes={l.get('bytes', 0)} "
            f"segment={l.get('segment', '?')}"
        )

    lines.append("\n=== NORMAL TRAFFIC SAMPLE ===")
    for l in normal:
        lines.append(
            f"[{l.get('action', '?')}] {l.get('src_ip', '?')} → "
            f"{l.get('dst_ip', '?')}:{l.get('dst_port', '?')} "
            f"proto={l.get('protocol', '?')} segment={l.get('segment', '?')}"
        )

    return "\n".join(lines)


def _fallback_analysis(logs: List[Dict]) -> Dict:
    """Rule-based fallback when GPT is unavailable."""
    deny_count = sum(1 for l in logs if l.get("action") == "DENY")
    cross = [l for l in logs if ">" in l.get("segment", "")]
    modbus_external = [l for l in logs if l.get("dst_port") == 502 and not l.get("src_ip", "").startswith("192.168.2.")]

    findings = []
    threat = "CLEAN"

    if modbus_external:
        threat = "CRITICAL"
        findings.append({
            "severity": "critical",
            "title": "Unauthorized Modbus Access",
            "detail": f"{len(modbus_external)} Modbus connections from non-SCADA sources",
            "involved_ips": list(set(l["src_ip"] for l in modbus_external)),
            "evidence": f"Port 502 access from outside 192.168.2.x"
        })

    if cross:
        if threat == "CLEAN":
            threat = "SUSPICIOUS"
        src_segments = set(l.get("segment", "").split(">")[0] for l in cross)
        findings.append({
            "severity": "warning",
            "title": "Cross-Segment Traffic Detected",
            "detail": f"{len(cross)} events crossing network boundaries from {', '.join(src_segments)}",
            "involved_ips": list(set(l["src_ip"] for l in cross))[:5],
            "evidence": f"Segments involved: {', '.join(set(l.get('segment','') for l in cross))}"
        })

    if deny_count > 5:
        findings.append({
            "severity": "warning",
            "title": "Elevated DENY Events",
            "detail": f"{deny_count} blocked connections — possible reconnaissance or misconfiguration",
            "involved_ips": list(set(l["src_ip"] for l in logs if l.get("action") == "DENY"))[:5],
            "evidence": f"{deny_count}/{len(logs)} events denied"
        })

    if not findings:
        findings.append({
            "severity": "info",
            "title": "Normal Operations",
            "detail": "All traffic follows expected OT communication patterns",
            "involved_ips": [],
            "evidence": f"{len(logs)} events, {deny_count} denies — within normal range"
        })

    protocols_seen = list(set(l.get("protocol", "?") for l in logs))
    active_hosts = len(set(l.get("src_ip") for l in logs) | set(l.get("dst_ip") for l in logs))

    return {
        "threat_level": threat,
        "summary": findings[0]["detail"] if findings else "Network operating normally",
        "findings": findings,
        "network_health": {
            "total_events": len(logs),
            "denied_events": deny_count,
            "cross_segment_events": len(cross),
            "protocols_seen": protocols_seen,
            "active_hosts": active_hosts,
        },
        "recommendations": [
            "Review cross-segment firewall rules" if cross else "Continue monitoring",
            "Investigate Modbus sources" if modbus_external else "OT protocols within expected patterns"
        ]
    }


# ══════════════════════════════════════════════════════════════
# DATABASE (SQLite)
# ══════════════════════════════════════════════════════════════

@contextmanager
def get_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                timestamp_iso TEXT NOT NULL,
                scan_type TEXT NOT NULL DEFAULT 'quick',
                dataset TEXT NOT NULL DEFAULT 'live',
                status TEXT NOT NULL,
                summary TEXT NOT NULL DEFAULT '',
                findings TEXT NOT NULL DEFAULT '[]',
                network_health TEXT NOT NULL DEFAULT '{}',
                recommendations TEXT NOT NULL DEFAULT '[]',
                gate_results TEXT NOT NULL DEFAULT '[]',
                involved_sensors TEXT NOT NULL DEFAULT '[]',
                betti_h0 INTEGER DEFAULT 0,
                betti_h1 INTEGER DEFAULT 0,
                betti_h2 INTEGER DEFAULT 0,
                betti_h3 INTEGER DEFAULT 0,
                raw_result TEXT NOT NULL DEFAULT '{}'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS network_nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id TEXT NOT NULL UNIQUE,
                label TEXT NOT NULL,
                segment TEXT NOT NULL DEFAULT 'unknown',
                node_type TEXT NOT NULL DEFAULT 'sensor',
                status TEXT NOT NULL DEFAULT 'confirmed',
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                added_by TEXT NOT NULL DEFAULT 'auto',
                metadata TEXT NOT NULL DEFAULT '{}'
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_ts ON scan_history(timestamp DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_node_id ON network_nodes(node_id)")


# Initialize DB on import
try:
    init_db()
except Exception as e:
    print(f"DB init warning: {e}")


# ══════════════════════════════════════════════════════════════
# API ROUTES
# ══════════════════════════════════════════════════════════════

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "topo-scanner-v7",
        "ai_available": ai_client is not None,
        "timestamp": time.time(),
    })


# ── SCAN ──────────────────────────────────────────────────────

@app.route("/scan/", methods=["POST"])
@app.route("/scan", methods=["POST"])
def run_scan():
    """
    Run a network scan.
    
    Data sources:
        dataset="live" + no device  → generate_logs() simulation
        dataset="live" + device     → SSH-pulled logs from connected hardware
        dataset="hai/swat/batadal"  → real CSV datasets via data_loader
    
    Scan modes:
        scan_type="quick" → GPT analyzes logs/sensor summary
        scan_type="deep"  → Topological 3-gate cascade + GPT interpretation
    """
    global _scan_counter, _last_logs

    data = request.get_json(silent=True) or {}
    scan_type = data.get("scan_type", "quick")
    dataset = data.get("dataset", "live")
    log_count = data.get("log_count", 50)

    _scan_counter += 1
    now = time.time()
    iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()

    result = {
        "scan_id": _scan_counter,
        "timestamp": now,
        "timestamp_iso": iso,
        "scan_type": scan_type,
        "dataset": dataset,
    }

    # ══════════════════════════════════════════════════════════
    # ROUTE 1: LIVE (simulation or real device)
    # ══════════════════════════════════════════════════════════
    if dataset == "live":
        # Use real device logs if available, else simulate
        if _live_device_logs:
            logs = _live_device_logs[-log_count:]
            result["data_source"] = f"live_device ({_live_device_info.get('host', '?')})"
        else:
            inject = data.get("inject_attack", None)
            logs = generate_logs(count=log_count, inject_attack=inject)
            result["data_source"] = "simulation"

        _last_logs = logs
        result["logs_analyzed"] = len(logs)

        if scan_type == "quick":
            analysis = gpt_analyze_logs(logs)
            result.update({
                "status": analysis.get("threat_level", "CLEAN"),
                "summary": analysis.get("summary", ""),
                "findings": analysis.get("findings", []),
                "network_health": analysis.get("network_health", {}),
                "recommendations": analysis.get("recommendations", []),
                "gate_results": [],
                "betti_h0": 0, "betti_h1": 0, "betti_h2": 0, "betti_h3": 0,
            })
        else:  # deep
            topo_result = _run_topological_scan_from_logs(logs, dataset)
            analysis = gpt_analyze_logs(logs)
            result.update(_merge_deep_result(topo_result, analysis))

    # ══════════════════════════════════════════════════════════
    # ROUTE 2: REAL DATASETS (HAI, SWaT, BATADAL)
    # ══════════════════════════════════════════════════════════
    elif dataset in ("hai", "swat", "batadal"):
        try:
            from engine.data_loader import DataLoader
            loader = DataLoader(data_dir=DATA_DIR)

            # Window parameters
            window_idx = data.get("window_index", _scan_counter - 1)
            window_size = data.get("window_size", 60)
            step_size = data.get("step_size", 10)

            if scan_type == "quick":
                # Quick Scan on real data: load a window, compute stats, send to GPT
                sensor_data, sensor_names, stats = _load_dataset_window(
                    loader, dataset, window_idx, window_size, step_size
                )
                result["logs_analyzed"] = sensor_data.shape[1] if sensor_data is not None else 0
                result["data_source"] = f"{dataset} (window {window_idx})"
                result["sensor_count"] = len(sensor_names)

                # Build summary for GPT
                analysis = _gpt_analyze_sensor_data(sensor_data, sensor_names, stats, dataset)
                result.update({
                    "status": analysis.get("threat_level", "CLEAN"),
                    "summary": analysis.get("summary", ""),
                    "findings": analysis.get("findings", []),
                    "network_health": analysis.get("network_health", {}),
                    "recommendations": analysis.get("recommendations", []),
                    "gate_results": [],
                    "betti_h0": 0, "betti_h1": 0, "betti_h2": 0, "betti_h3": 0,
                })

            else:  # deep
                sensor_data, sensor_names, stats = _load_dataset_window(
                    loader, dataset, window_idx, window_size, step_size
                )
                result["logs_analyzed"] = sensor_data.shape[1] if sensor_data is not None else 0
                result["data_source"] = f"{dataset} (window {window_idx})"
                result["sensor_count"] = len(sensor_names)

                # Run topological engine directly on sensor time series
                topo_result = _run_topological_scan_from_sensors(
                    sensor_data, sensor_names, dataset
                )

                # GPT interprets the topo + sensor results
                analysis = _gpt_analyze_sensor_data(
                    sensor_data, sensor_names, stats, dataset, topo_result
                )
                result.update(_merge_deep_result(topo_result, analysis))

        except FileNotFoundError as e:
            result.update({
                "status": "CLEAN",
                "summary": f"Dataset '{dataset}' not found: {e}. Place CSV files in backend/data/{dataset}/",
                "findings": [{"severity": "info", "title": "Dataset Not Found",
                             "detail": str(e), "involved_ips": [], "evidence": ""}],
                "network_health": {}, "recommendations": [f"Download {dataset} dataset"],
                "gate_results": [],
                "betti_h0": 0, "betti_h1": 0, "betti_h2": 0, "betti_h3": 0,
            })
        except Exception as e:
            print(f"Dataset scan error: {e}")
            traceback.print_exc()
            result.update({
                "status": "CLEAN",
                "summary": f"Error loading {dataset}: {e}",
                "findings": [{"severity": "warning", "title": "Data Error",
                             "detail": str(e), "involved_ips": [], "evidence": ""}],
                "network_health": {}, "recommendations": [],
                "gate_results": [],
                "betti_h0": 0, "betti_h1": 0, "betti_h2": 0, "betti_h3": 0,
            })
    else:
        result.update({
            "status": "CLEAN", "summary": f"Unknown dataset: {dataset}",
            "findings": [], "network_health": {}, "recommendations": [],
            "gate_results": [],
            "betti_h0": 0, "betti_h1": 0, "betti_h2": 0, "betti_h3": 0,
        })

    # ── Save to DB ──
    try:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO scan_history 
                (timestamp, timestamp_iso, scan_type, dataset, status,
                 summary, findings, network_health, recommendations,
                 gate_results, involved_sensors,
                 betti_h0, betti_h1, betti_h2, betti_h3, raw_result)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                now, iso, scan_type, dataset,
                result.get("status", "CLEAN"),
                result.get("summary", ""),
                json.dumps(result.get("findings", [])),
                json.dumps(result.get("network_health", {})),
                json.dumps(result.get("recommendations", [])),
                json.dumps(result.get("gate_results", [])),
                json.dumps(result.get("involved_sensors", [])),
                result.get("betti_h0", 0), result.get("betti_h1", 0),
                result.get("betti_h2", 0), result.get("betti_h3", 0),
                json.dumps(result),
            ))
            result["scan_id"] = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    except Exception as e:
        print(f"DB save error: {e}")

    return jsonify(result)


# ══════════════════════════════════════════════════════════════
# DATA LOADING HELPERS
# ══════════════════════════════════════════════════════════════

def _load_dataset_window(loader, dataset: str, window_idx: int,
                         window_size: int = 60, step_size: int = 10):
    """Load one window of sensor data from a real dataset."""
    import numpy as np

    if dataset == "hai":
        data, names = loader.load_hai(mode="test", file_index=1, max_rows=50000)
    elif dataset == "swat":
        data, names = loader.load_swat(file_index=1, max_rows=50000)
    elif dataset == "batadal":
        data, names = loader.load_batadal(mode="test", max_rows=50000)
    else:
        raise ValueError(f"Unknown dataset: {dataset}")

    n_sensors, total_samples = data.shape
    start = window_idx * step_size
    end = start + window_size

    if end > total_samples:
        start = max(0, total_samples - window_size)
        end = total_samples

    window = data[:, start:end]

    # Compute basic stats for GPT
    stats = {
        "dataset": dataset,
        "window_index": window_idx,
        "window_range": f"{start}:{end}",
        "total_sensors": n_sensors,
        "total_samples": total_samples,
        "window_samples": window.shape[1],
    }

    # Find sensors with unusual variance in this window
    variances = np.var(window, axis=1)
    mean_var = np.mean(variances)
    std_var = np.std(variances)

    anomalous_sensors = []
    for i, (var, name) in enumerate(zip(variances, names)):
        if std_var > 0 and var > mean_var + 2 * std_var:
            anomalous_sensors.append({"name": name, "variance": round(float(var), 4)})

    stats["anomalous_sensors"] = anomalous_sensors[:10]
    stats["mean_variance"] = round(float(mean_var), 4)

    # Check for constant/dead sensors
    dead_sensors = [names[i] for i in range(n_sensors) if np.std(window[i]) < 1e-10]
    stats["dead_sensors"] = dead_sensors[:5]
    stats["dead_count"] = len(dead_sensors)

    return window, names, stats


def _gpt_analyze_sensor_data(sensor_data, sensor_names: list, stats: dict,
                             dataset: str, topo_result: dict = None) -> Dict:
    """Ask GPT to interpret sensor data stats (for real datasets)."""
    if not ai_client:
        return _fallback_sensor_analysis(stats, topo_result)

    summary_lines = [
        f"Dataset: {dataset.upper()}",
        f"Window: {stats.get('window_range', '?')} ({stats.get('window_samples', 0)} samples)",
        f"Sensors: {stats.get('total_sensors', 0)} total, {stats.get('dead_count', 0)} dead/constant",
        f"Mean variance: {stats.get('mean_variance', 0)}",
    ]

    anomalous = stats.get("anomalous_sensors", [])
    if anomalous:
        summary_lines.append(f"\nHigh-variance sensors (possible anomalies):")
        for s in anomalous:
            summary_lines.append(f"  {s['name']}: variance={s['variance']}")

    if topo_result:
        summary_lines.append(f"\nTopological analysis results:")
        summary_lines.append(f"  Gates triggered: {topo_result.get('gates_triggered', 0)}/3")
        summary_lines.append(f"  Status: {topo_result.get('status', 'CLEAN')}")
        summary_lines.append(f"  Betti: H0={topo_result.get('betti_h0',0)} H1={topo_result.get('betti_h1',0)} "
                           f"H2={topo_result.get('betti_h2',0)} H3={topo_result.get('betti_h3',0)}")
        for g in topo_result.get("gate_results", []):
            gate_name = g.get("gate", g.get("gate_name", "?"))
            summary_lines.append(f"  Gate {gate_name}: {'TRIGGERED' if g.get('triggered') else 'PASS'}")
            for f in g.get("findings", [])[:2]:
                summary_lines.append(f"    → {f}")

    sensor_summary = "\n".join(summary_lines)

    system_prompt = """You are an OT/ICS Cybersecurity Analyst. You are analyzing real sensor data from an industrial control system dataset.

For HAI: This is a HIL-based Augmented ICS testbed with boiler, turbine, and water treatment processes.
For SWaT: This is a Secure Water Treatment testbed with 6 process stages.
For BATADAL: This is a water distribution network.

Analyze the sensor statistics and topological analysis results. Look for:
- Sensors with unusually high variance (could indicate manipulation)
- Dead/constant sensors (could indicate sensor failure or spoofing)
- Topological findings: H2 > 0 means mathematically proven coordinated multi-sensor attack
- Cross-process anomalies (sensors in different stages behaving together unusually)

Respond ONLY with JSON:
{
  "threat_level": "CLEAN" | "SUSPICIOUS" | "CRITICAL",
  "summary": "One sentence executive summary",
  "findings": [{"severity":"info|warning|critical", "title":"...", "detail":"...", "involved_ips":[], "evidence":"..."}],
  "network_health": {"total_events": <sensors>, "denied_events": 0, "cross_segment_events": <anomalous_count>, "protocols_seen": ["sensor_data"], "active_hosts": <sensor_count>},
  "recommendations": ["action1", "action2"]
}"""

    try:
        response = ai_client.chat.completions.create(
            model=OPENAI_MODEL,
            temperature=0.1,
            max_tokens=2000,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Analyze this OT sensor window:\n\n{sensor_summary}"}
            ],
            response_format={"type": "json_object"},
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        print(f"GPT sensor analysis failed: {e}")
        return _fallback_sensor_analysis(stats, topo_result)


def _fallback_sensor_analysis(stats: dict, topo_result: dict = None) -> Dict:
    """Rule-based fallback for sensor data analysis."""
    anomalous = stats.get("anomalous_sensors", [])
    dead = stats.get("dead_count", 0)
    findings = []
    threat = "CLEAN"

    if topo_result and topo_result.get("gates_triggered", 0) >= 3:
        threat = "CRITICAL"
        findings.append({
            "severity": "critical",
            "title": "All 3 topological gates triggered",
            "detail": f"Mathematical proof of coordinated sensor manipulation. "
                     f"H2={topo_result.get('betti_h2', 0)} indicates multi-sensor coordination.",
            "involved_ips": topo_result.get("involved_sensors", []),
            "evidence": f"Gates: {topo_result.get('gates_triggered', 0)}/3"
        })
    elif topo_result and topo_result.get("gates_triggered", 0) >= 1:
        threat = "SUSPICIOUS"
        findings.append({
            "severity": "warning",
            "title": f"{topo_result.get('gates_triggered', 0)}/3 topological gates triggered",
            "detail": "Partial anomaly detected in sensor relationships",
            "involved_ips": topo_result.get("involved_sensors", []),
            "evidence": f"Betti: H0={topo_result.get('betti_h0',0)} H1={topo_result.get('betti_h1',0)} H2={topo_result.get('betti_h2',0)}"
        })

    if anomalous:
        if threat == "CLEAN":
            threat = "SUSPICIOUS"
        findings.append({
            "severity": "warning",
            "title": f"{len(anomalous)} sensors with unusual variance",
            "detail": "These sensors show significantly higher variance than the baseline",
            "involved_ips": [s["name"] for s in anomalous],
            "evidence": ", ".join(f"{s['name']}={s['variance']}" for s in anomalous[:5])
        })

    if dead > 5:
        findings.append({
            "severity": "info",
            "title": f"{dead} dead/constant sensors",
            "detail": "Sensors with zero variance — could be normal (discrete state) or sensor failure",
            "involved_ips": stats.get("dead_sensors", []),
            "evidence": f"{dead}/{stats.get('total_sensors', 0)} sensors constant"
        })

    if not findings:
        findings.append({
            "severity": "info",
            "title": "Normal sensor readings",
            "detail": "All sensors within expected variance range",
            "involved_ips": [], "evidence": ""
        })

    return {
        "threat_level": threat,
        "summary": findings[0]["detail"],
        "findings": findings,
        "network_health": {
            "total_events": stats.get("total_sensors", 0),
            "denied_events": 0,
            "cross_segment_events": len(anomalous),
            "protocols_seen": ["sensor_data"],
            "active_hosts": stats.get("total_sensors", 0) - dead,
        },
        "recommendations": [
            "Investigate high-variance sensors" if anomalous else "Continue monitoring",
            "Run Deep Scan for topological proof" if not topo_result else "Review gate details"
        ]
    }


def _merge_deep_result(topo_result: Dict, analysis: Dict) -> Dict:
    """Merge topological scan results with GPT analysis."""
    return {
        "status": topo_result.get("status", analysis.get("threat_level", "CLEAN")),
        "summary": analysis.get("summary", ""),
        "findings": analysis.get("findings", []),
        "network_health": analysis.get("network_health", {}),
        "recommendations": analysis.get("recommendations", []),
        "gate_results": topo_result.get("gate_results", []),
        "involved_sensors": topo_result.get("involved_sensors", []),
        "betti_h0": topo_result.get("betti_h0", 0),
        "betti_h1": topo_result.get("betti_h1", 0),
        "betti_h2": topo_result.get("betti_h2", 0),
        "betti_h3": topo_result.get("betti_h3", 0),
        "epsilon": topo_result.get("epsilon", 0),
        "gates_triggered": topo_result.get("gates_triggered", 0),
        "confidence": topo_result.get("confidence", "none"),
    }


# ══════════════════════════════════════════════════════════════
# TOPOLOGICAL SCAN RUNNERS
# ══════════════════════════════════════════════════════════════

def _run_topological_scan_from_logs(logs: List[Dict], dataset: str) -> Dict:
    """Run topo engine on network logs (live/SSH). Logs → time series → topo."""
    try:
        from engine.log_transformer import LogTransformer
        transformer = LogTransformer(window_sec=10)
        sensor_data, sensor_names = transformer.transform(logs)

        if sensor_data.shape[0] == 0 or sensor_data.shape[1] < 10:
            return {"status": "CLEAN", "gate_results": [],
                    "betti_h0": 0, "betti_h1": 0, "betti_h2": 0, "betti_h3": 0}

        return _run_topological_scan_from_sensors(sensor_data, sensor_names, dataset)

    except Exception as e:
        print(f"Topological scan (logs) error: {e}")
        traceback.print_exc()
        return _empty_topo_result(str(e))


def _run_topological_scan_from_sensors(sensor_data, sensor_names: list,
                                        dataset: str) -> Dict:
    """Run topo engine directly on sensor time series (HAI/SWaT/BATADAL or transformed logs)."""
    try:
        from engine.scanner import TopologicalScanner
        from config.settings import get_config
        import numpy as np

        global _scanner_instance, _scanner_calibrated_for

        # Initialize/recalibrate scanner if needed
        if _scanner_instance is None or _scanner_calibrated_for != dataset:
            config = get_config()
            _scanner_instance = TopologicalScanner(config)
            _scanner_calibrated_for = dataset

            # Calibrate with this window's data (simplified for demo)
            if sensor_data.shape[1] >= 30:
                cal_data = sensor_data[:, :min(sensor_data.shape[1], 500)]
                try:
                    _scanner_instance.calibrate(cal_data, sensor_names)
                    print(f"Scanner calibrated for {dataset} ({len(sensor_names)} sensors)")
                except Exception as e:
                    print(f"Calibration warning: {e}")

        # Limit sensors for performance (topological engine is O(N²))
        max_sensors = 50
        if sensor_data.shape[0] > max_sensors:
            # Pick sensors with highest variance (most interesting)
            variances = np.var(sensor_data, axis=1)
            top_idx = np.argsort(variances)[-max_sensors:]
            sensor_data = sensor_data[top_idx]
            sensor_names = [sensor_names[i] for i in top_idx]

        result = _scanner_instance.scan(
            data_source=dataset,
            sensor_data=sensor_data,
            sensor_names=sensor_names,
        )
        return result.to_dict()

    except Exception as e:
        print(f"Topological scan (sensors) error: {e}")
        traceback.print_exc()
        return _empty_topo_result(str(e))


def _empty_topo_result(error: str = "") -> Dict:
    return {
        "status": "CLEAN", "gate_results": [], "involved_sensors": [],
        "betti_h0": 0, "betti_h1": 0, "betti_h2": 0, "betti_h3": 0,
        "gates_triggered": 0, "confidence": "none", "error": error,
    }


@app.route("/scan/status")
def scan_status():
    return jsonify({
        "total_scans": _scan_counter,
        "ai_available": ai_client is not None,
        "last_scan_logs": len(_last_logs),
    })


# ── CHAT ──────────────────────────────────────────────────────

@app.route("/chat/", methods=["POST"])
@app.route("/chat", methods=["POST"])
def chat():
    """Chat with AI about network security."""
    data = request.get_json(silent=True) or {}
    user_message = data.get("message", "").strip()
    session_id = data.get("session_id", "default")

    if not user_message:
        return jsonify({"error": "Empty message"}), 400

    # Get or create chat history
    if session_id not in _chat_histories:
        _chat_histories[session_id] = []

    # Build context from latest scan
    context = {}
    try:
        with get_db() as conn:
            row = conn.execute(
                "SELECT raw_result FROM scan_history ORDER BY timestamp DESC LIMIT 1"
            ).fetchone()
            if row:
                context = json.loads(row["raw_result"])
    except Exception:
        pass

    # Add to history
    _chat_histories[session_id].append({"role": "user", "content": user_message})

    # Get response
    response_text = gpt_chat(user_message, context=context, history=_chat_histories[session_id])

    _chat_histories[session_id].append({"role": "assistant", "content": response_text})

    # Keep history manageable
    if len(_chat_histories[session_id]) > 20:
        _chat_histories[session_id] = _chat_histories[session_id][-16:]

    return jsonify({"response": response_text})


# ── ALSO support old /assistant/ route for backwards compat ──

@app.route("/assistant/", methods=["POST"])
@app.route("/assistant", methods=["POST"])
def assistant_compat():
    """Backwards-compatible assistant endpoint."""
    data = request.get_json(silent=True) or {}
    prompt = data.get("prompt", "").strip()
    if not prompt:
        return jsonify({"error": "Empty prompt"}), 400

    context = {}
    try:
        with get_db() as conn:
            row = conn.execute(
                "SELECT raw_result FROM scan_history ORDER BY timestamp DESC LIMIT 1"
            ).fetchone()
            if row:
                context = json.loads(row["raw_result"])
    except Exception:
        pass

    response_text = gpt_chat(prompt, context=context)
    return jsonify({"response": response_text})


# ── HISTORY ───────────────────────────────────────────────────

@app.route("/history/", methods=["GET"])
@app.route("/history", methods=["GET"])
def get_history():
    limit = request.args.get("limit", 50, type=int)
    offset = request.args.get("offset", 0, type=int)
    status = request.args.get("status", None)

    try:
        with get_db() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM scan_history WHERE status=? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    (status, limit, offset)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scan_history ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    (limit, offset)
                ).fetchall()

            scans = []
            for row in rows:
                scan = dict(row)
                # Parse JSON fields
                for field in ["findings", "network_health", "recommendations", "gate_results", "involved_sensors"]:
                    try:
                        scan[field] = json.loads(scan.get(field, "[]"))
                    except (json.JSONDecodeError, TypeError):
                        pass
                scans.append(scan)

            return jsonify({"scans": scans, "total": len(scans)})
    except Exception as e:
        return jsonify({"scans": [], "error": str(e)})


@app.route("/history/<int:scan_id>")
def get_scan(scan_id):
    try:
        with get_db() as conn:
            row = conn.execute("SELECT * FROM scan_history WHERE id=?", (scan_id,)).fetchone()
            if row:
                scan = dict(row)
                for field in ["findings", "network_health", "recommendations", "gate_results", "involved_sensors"]:
                    try:
                        scan[field] = json.loads(scan.get(field, "[]"))
                    except:
                        pass
                return jsonify(scan)
            return jsonify({"error": "Not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/history/stats")
def get_stats():
    try:
        with get_db() as conn:
            total = conn.execute("SELECT COUNT(*) as c FROM scan_history").fetchone()["c"]
            critical = conn.execute("SELECT COUNT(*) as c FROM scan_history WHERE status='CRITICAL'").fetchone()["c"]
            suspicious = conn.execute("SELECT COUNT(*) as c FROM scan_history WHERE status IN ('SUSPICIOUS','MID_ALERT','HIGH_ALERT')").fetchone()["c"]
            return jsonify({"total": total, "critical": critical, "suspicious": suspicious, "clean": total - critical - suspicious})
    except:
        return jsonify({"total": 0, "critical": 0, "suspicious": 0, "clean": 0})


@app.route("/history/export")
def export_history():
    try:
        with get_db() as conn:
            rows = conn.execute("SELECT id, timestamp_iso, scan_type, status, summary FROM scan_history ORDER BY timestamp ASC").fetchall()
        if not rows:
            return Response("No scans recorded", mimetype="text/csv")
        lines = ["id,timestamp,scan_type,status,summary"]
        for r in rows:
            lines.append(f'{r["id"]},{r["timestamp_iso"]},{r["scan_type"]},{r["status"]},"{r["summary"]}"')
        return Response("\n".join(lines), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=scan_history.csv"})
    except Exception as e:
        return Response(f"Error: {e}", mimetype="text/plain")


# ── LOGS ──────────────────────────────────────────────────────

@app.route("/logs/", methods=["GET"])
@app.route("/logs", methods=["GET"])
def get_logs():
    """Get the latest batch of network logs."""
    limit = request.args.get("limit", 100, type=int)
    if _last_logs:
        return jsonify({"logs": _last_logs[-limit:], "count": len(_last_logs)})
    # Generate fresh
    logs = generate_logs(count=limit)
    return jsonify({"logs": logs, "count": len(logs)})


# ── TOPOLOGY ──────────────────────────────────────────────────

@app.route("/topology/nodes", methods=["GET"])
def get_nodes():
    try:
        with get_db() as conn:
            rows = conn.execute(
                "SELECT * FROM network_nodes WHERE status != 'removed' ORDER BY segment, node_id"
            ).fetchall()
            return jsonify({"nodes": [dict(r) for r in rows]})
    except:
        return jsonify({"nodes": []})


@app.route("/topology/nodes/pending")
def get_pending():
    try:
        with get_db() as conn:
            rows = conn.execute(
                "SELECT * FROM network_nodes WHERE status='pending' ORDER BY first_seen DESC"
            ).fetchall()
            return jsonify({"pending": [dict(r) for r in rows]})
    except:
        return jsonify({"pending": []})


@app.route("/topology/nodes", methods=["POST"])
def add_node():
    data = request.get_json(silent=True) or {}
    node_id = data.get("node_id", "")
    label = data.get("label", node_id)
    segment = data.get("segment", "unknown")
    node_type = data.get("node_type", "sensor")

    if not node_id:
        return jsonify({"error": "node_id required"}), 400

    now = time.time()
    try:
        with get_db() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO network_nodes (node_id, label, segment, node_type, status, first_seen, last_seen, added_by)
                VALUES (?, ?, ?, ?, 'confirmed', ?, ?, 'manual')
            """, (node_id, label, segment, node_type, now, now))
        return jsonify({"message": f"Node {node_id} added", "node_id": node_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/topology/nodes/<node_id>/confirm", methods=["PUT"])
def confirm_node(node_id):
    data = request.get_json(silent=True) or {}
    try:
        with get_db() as conn:
            updates = ["status='confirmed'"]
            params = []
            for field in ["label", "segment", "node_type"]:
                if data.get(field):
                    updates.append(f"{field}=?")
                    params.append(data[field])
            params.append(node_id)
            conn.execute(f"UPDATE network_nodes SET {', '.join(updates)} WHERE node_id=?", params)
        return jsonify({"message": f"Node {node_id} confirmed"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/topology/nodes/<node_id>/deny", methods=["PUT"])
def deny_node(node_id):
    try:
        with get_db() as conn:
            conn.execute("UPDATE network_nodes SET status='removed' WHERE node_id=?", (node_id,))
        return jsonify({"message": f"Node {node_id} denied"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/topology/connect_live", methods=["POST"])
def connect_live():
    """Connect to a live device via SSH. Logs are stored for subsequent scans."""
    global _live_device_logs, _live_device_info

    data = request.get_json(silent=True) or {}
    host = data.get("host", "")
    username = data.get("username", "")
    password = data.get("password", "")
    device_type = data.get("device_type", "cisco_ios")

    if not host or not username:
        return jsonify({"error": "host and username required"}), 400

    try:
        from connectors.ssh_connector import SSHConnector
        connector = SSHConnector(host, username, password, device_type)

        if not connector.connect():
            return jsonify({"error": f"SSH connection to {host} failed"}), 500

        # Pull data
        logs = connector.get_logs(limit=500)
        topology = connector.get_topology()
        routes = connector.get_routes()
        connector.disconnect()

        # Store logs for scanning — convert LogEntry objects to dicts
        _live_device_logs = [
            {
                "timestamp": l.timestamp, "src_ip": l.src_ip, "dst_ip": l.dst_ip,
                "src_port": l.src_port, "dst_port": l.dst_port,
                "protocol": l.protocol, "action": l.action,
                "bytes": l.bytes_transferred, "duration": l.duration,
                "segment": l.segment, "_label": "Live",
            }
            for l in logs
        ]
        _live_device_info = {
            "host": host, "device_type": device_type,
            "devices_found": len(topology), "logs_parsed": len(logs),
            "routes_found": len(routes),
        }

        # Auto-add discovered nodes as pending
        now = time.time()
        for device in topology:
            try:
                with get_db() as conn:
                    conn.execute("""
                        INSERT OR IGNORE INTO network_nodes 
                        (node_id, label, segment, node_type, status, first_seen, last_seen, added_by, metadata)
                        VALUES (?, ?, 'unknown', 'unknown', 'pending', ?, ?, 'ssh_discovery', ?)
                    """, (device["ip"], device["ip"], now, now, json.dumps(device)))
            except Exception:
                pass

        return jsonify({
            "message": f"Connected to {host} — logs stored for scanning",
            "logs_parsed": len(logs),
            "devices_found": len(topology),
            "routes_found": len(routes),
            "hint": "Select 'Live Simulation' and run Quick/Deep Scan to analyze these logs"
        })

    except ImportError:
        return jsonify({"error": "Netmiko not installed — SSH connector unavailable"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── DATASETS ──────────────────────────────────────────────────

@app.route("/datasets")
def list_datasets():
    return jsonify({
        "datasets": [
            {"name": "live", "description": "Real-time OT network simulation", "available": True},
            {"name": "hai", "description": "HIL-based Augmented ICS Dataset", "available": Path(DATA_DIR, "hai").exists()},
            {"name": "swat", "description": "Secure Water Treatment A10", "available": Path(DATA_DIR, "swat").exists()},
            {"name": "batadal", "description": "Battle of the Attack Detection Algorithms", "available": Path(DATA_DIR, "batadal").exists()},
        ]
    })


# ══════════════════════════════════════════════════════════════
# RUN
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    print(f"Topo Scanner v7 on {host}:{port} | AI: {'✓' if ai_client else '✗'}")
    app.run(host=host, port=port, debug=debug)
