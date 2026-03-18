"""
Topo Scanner v7 — Flask Backend
=================================
Two-mode architecture:
  1. QUICK SCAN:  GPT analyzes network logs → human-readable findings
  2. DEEP SCAN:   Topological 3-gate cascade → mathematical proof + GPT interpretation

All routes in one file for hackathon simplicity.
"""

import os
import sys
import time
import json
import logging
import traceback
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager
from typing import List, Dict, Optional, Any

from flask import Flask, request, jsonify, Response
from flask_cors import CORS

# ── Safe OpenAI import (doesn't crash if not installed) ──
try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

# ── Setup logging ──
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("topo-scanner")

# ══════════════════════════════════════════════════════════════
# APP SETUP
# ══════════════════════════════════════════════════════════════

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ── Config ──
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1")
DB_PATH = os.getenv("DB_PATH", "/app/db/topo_scanner.db")
DATA_DIR = os.getenv("DATA_DIR", "/app/data")

# ── OpenAI Client (None if key missing or library not installed) ──
ai_client = None
if OPENAI_API_KEY and OPENAI_API_KEY.startswith("sk-") and OpenAI is not None:
    try:
        ai_client = OpenAI(api_key=OPENAI_API_KEY)
        logger.info(f"OpenAI client initialized (model: {OPENAI_MODEL})")
    except Exception as e:
        logger.warning(f"OpenAI init failed: {e}")

# ── In-memory state ──
_scan_counter = 0
_last_logs: List[Dict] = []
_scanner_instance = None
_scanner_calibrated_for: str = ""
_chat_histories: Dict[str, List] = {}

# ── Live device state ──
_live_device_logs: List[Dict] = []
_live_device_info: Dict = {}


# ══════════════════════════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════════════════════════

@contextmanager
def get_db():
    """SQLite connection with WAL mode, auto-commit, auto-rollback."""
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
    """Create tables if they don't exist. Called once at startup."""
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
                epsilon REAL DEFAULT 0.0,
                gates_triggered INTEGER DEFAULT 0,
                confidence TEXT DEFAULT 'none',
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
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_status ON scan_history(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_node_id ON network_nodes(node_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_node_status ON network_nodes(status)")


try:
    init_db()
    logger.info(f"Database initialized at {DB_PATH}")
except Exception as e:
    logger.warning(f"DB init warning: {e}")


# ══════════════════════════════════════════════════════════════
# GPT ANALYSIS
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
    "total_events": 0,
    "denied_events": 0,
    "cross_segment_events": 0,
    "protocols_seen": [],
    "active_hosts": 0
  },
  "recommendations": ["Action 1", "Action 2"]
}"""

SYSTEM_PROMPT_CHAT = """You are the AI Security Analyst for Topo Scanner — an OT/ICS cybersecurity system.
You help operators understand network security findings, explain threats, and recommend actions.

You have access to the latest scan results and network context. Be concise, technical when needed,
but always explain the "so what" — why does this matter for the physical process?

When asked about the topological analysis (Deep Scan), explain:
- Sheaf Consistency: checks if sensor readings are physically consistent (like checking if valve position matches flow rate)
- Ollivier-Ricci Curvature: finds network bridges/bottlenecks that an attacker might exploit for lateral movement
- Persistent Homology: mathematically proves coordinated multi-node attacks (β₂ > 0 = 4+ nodes acting together)

Keep responses focused and actionable. You're talking to a SOC operator, not a math professor."""


def gpt_analyze_logs(logs: List[Dict]) -> Dict:
    """Send logs to GPT for analysis. Returns structured findings."""
    if not ai_client:
        return _fallback_analysis(logs)

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
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        logger.warning(f"GPT analysis failed: {e}")
        return _fallback_analysis(logs)


def gpt_chat(user_message: str, context: Dict = None, history: List = None) -> str:
    """Chat with GPT about network security."""
    if not ai_client:
        return "AI analysis unavailable — API key not configured. The topological engine (Deep Scan) is still fully operational."

    messages = [{"role": "system", "content": SYSTEM_PROMPT_CHAT}]

    if context:
        ctx_str = json.dumps(context, indent=2, default=str)[:3000]
        messages.append({"role": "system", "content": f"Latest scan context:\n{ctx_str}"})

    if history:
        for h in history[-8:]:
            messages.append({"role": h["role"], "content": h["content"]})

    messages.append({"role": "user", "content": user_message})

    try:
        response = ai_client.chat.completions.create(
            model=OPENAI_MODEL, temperature=0.3, max_tokens=1000, messages=messages,
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"AI temporarily unavailable: {str(e)}"


def _prepare_log_summary(logs: List[Dict]) -> str:
    """Prepare concise log summary for GPT."""
    lines = [f"Total events: {len(logs)}"]
    deny_count = sum(1 for l in logs if l.get("action") == "DENY")
    cross = [l for l in logs if ">" in l.get("segment", "")]
    lines.append(f"DENY events: {deny_count}")
    lines.append(f"Cross-segment events: {len(cross)}")

    pairs = set()
    for l in logs:
        pairs.add(f"{l.get('src_ip', '?')} → {l.get('dst_ip', '?')}:{l.get('dst_port', '?')}")
    lines.append(f"Unique flows: {len(pairs)}")
    lines.append("")

    interesting = [l for l in logs if (
        ">" in l.get("segment", "") or l.get("action") == "DENY"
        or l.get("dst_port") in [502, 4840, 22, 3389, 445, 23]
    )]
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
    modbus_ext = [l for l in logs if l.get("dst_port") == 502
                  and not l.get("src_ip", "").startswith("192.168.2.")]

    findings = []
    threat = "CLEAN"

    if modbus_ext:
        threat = "CRITICAL"
        findings.append({
            "severity": "critical", "title": "Unauthorized Modbus Access",
            "detail": f"{len(modbus_ext)} Modbus connections from non-SCADA sources",
            "involved_ips": list(set(l["src_ip"] for l in modbus_ext))[:5],
            "evidence": "Port 502 access from outside 192.168.2.x"
        })

    if cross:
        if threat == "CLEAN":
            threat = "SUSPICIOUS"
        findings.append({
            "severity": "warning", "title": "Cross-Segment Traffic Detected",
            "detail": f"{len(cross)} events crossing network boundaries",
            "involved_ips": list(set(l["src_ip"] for l in cross))[:5],
            "evidence": f"Segments: {', '.join(set(l.get('segment', '') for l in cross))}"
        })

    if deny_count > 5:
        findings.append({
            "severity": "warning", "title": "Elevated DENY Events",
            "detail": f"{deny_count} blocked connections — possible reconnaissance",
            "involved_ips": list(set(l["src_ip"] for l in logs if l.get("action") == "DENY"))[:5],
            "evidence": f"{deny_count}/{len(logs)} events denied"
        })

    if not findings:
        findings.append({
            "severity": "info", "title": "Normal Operations",
            "detail": "All traffic follows expected OT communication patterns",
            "involved_ips": [], "evidence": f"{len(logs)} events, {deny_count} denies"
        })

    return {
        "threat_level": threat,
        "summary": findings[0]["detail"],
        "findings": findings,
        "network_health": {
            "total_events": len(logs), "denied_events": deny_count,
            "cross_segment_events": len(cross),
            "protocols_seen": list(set(l.get("protocol", "?") for l in logs)),
            "active_hosts": len(set(l.get("src_ip") for l in logs) | set(l.get("dst_ip") for l in logs)),
        },
        "recommendations": [
            "Review cross-segment firewall rules" if cross else "Continue monitoring",
            "Investigate Modbus sources" if modbus_ext else "OT protocols within expected patterns",
        ],
    }


def _gpt_analyze_sensor_data(sensor_data, sensor_names: list, stats: dict,
                              dataset: str, topo_result: dict = None) -> Dict:
    """GPT interpretation of sensor data + topo results."""
    if not ai_client:
        return _fallback_sensor_analysis(stats, topo_result)

    summary_lines = [
        f"Dataset: {dataset.upper()}",
        f"Window: {stats.get('window_range', '?')} ({stats.get('window_samples', 0)} samples)",
        f"Sensors: {stats.get('total_sensors', 0)} total, {stats.get('dead_count', 0)} dead/constant",
    ]

    anomalous = stats.get("anomalous_sensors", [])
    if anomalous:
        summary_lines.append("High-variance sensors:")
        for s in anomalous[:5]:
            summary_lines.append(f"  {s['name']}: variance={s['variance']}")

    if topo_result:
        summary_lines.append(f"\nTopological analysis: {topo_result.get('gates_triggered', 0)}/3 gates triggered")
        summary_lines.append(f"Status: {topo_result.get('status', 'CLEAN')}")
        summary_lines.append(
            f"Betti: β₀={topo_result.get('betti_h0', 0)} β₁={topo_result.get('betti_h1', 0)} "
            f"β₂={topo_result.get('betti_h2', 0)} β₃={topo_result.get('betti_h3', 0)}"
        )
        for g in topo_result.get("gate_results", []):
            gname = g.get("gate", g.get("gate_name", "?"))
            summary_lines.append(f"  Gate {gname}: {'TRIGGERED' if g.get('triggered') else 'PASS'}")
            for f in g.get("findings", [])[:2]:
                summary_lines.append(f"    → {f}")

    try:
        response = ai_client.chat.completions.create(
            model=OPENAI_MODEL, temperature=0.1, max_tokens=2000,
            messages=[
                {"role": "system", "content": "You are an OT/ICS Cybersecurity Analyst analyzing real sensor data. Respond ONLY with JSON: {\"threat_level\": \"CLEAN|SUSPICIOUS|CRITICAL\", \"summary\": \"...\", \"findings\": [...], \"network_health\": {...}, \"recommendations\": [...]}"},
                {"role": "user", "content": "\n".join(summary_lines)},
            ],
            response_format={"type": "json_object"},
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        logger.warning(f"GPT sensor analysis failed: {e}")
        return _fallback_sensor_analysis(stats, topo_result)


def _fallback_sensor_analysis(stats: dict, topo_result: dict = None) -> Dict:
    """Rule-based fallback for sensor data."""
    anomalous = stats.get("anomalous_sensors", [])
    dead = stats.get("dead_count", 0)
    findings = []
    threat = "CLEAN"

    if topo_result and topo_result.get("gates_triggered", 0) >= 3:
        threat = "CRITICAL"
        findings.append({
            "severity": "critical", "title": "All 3 topological gates triggered",
            "detail": f"Mathematical proof of coordinated sensor manipulation. β₂={topo_result.get('betti_h2', 0)}",
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
            "evidence": f"β₀={topo_result.get('betti_h0', 0)} β₁={topo_result.get('betti_h1', 0)} β₂={topo_result.get('betti_h2', 0)}"
        })

    if anomalous:
        if threat == "CLEAN":
            threat = "SUSPICIOUS"
        findings.append({
            "severity": "warning",
            "title": f"{len(anomalous)} sensors with unusual variance",
            "detail": "Significantly higher variance than baseline",
            "involved_ips": [s["name"] for s in anomalous],
            "evidence": ", ".join(f"{s['name']}={s['variance']}" for s in anomalous[:5])
        })

    if not findings:
        findings.append({
            "severity": "info", "title": "Normal sensor readings",
            "detail": "All sensors within expected variance range",
            "involved_ips": [], "evidence": ""
        })

    return {
        "threat_level": threat, "summary": findings[0]["detail"],
        "findings": findings,
        "network_health": {
            "total_events": stats.get("total_sensors", 0), "denied_events": 0,
            "cross_segment_events": len(anomalous),
            "protocols_seen": ["sensor_data"],
            "active_hosts": stats.get("total_sensors", 0) - dead,
        },
        "recommendations": [
            "Investigate high-variance sensors" if anomalous else "Continue monitoring",
            "Run Deep Scan for topological proof" if not topo_result else "Review gate details",
        ],
    }


# ══════════════════════════════════════════════════════════════
# TOPOLOGICAL SCAN HELPERS
# ══════════════════════════════════════════════════════════════

def _generate_mock_logs(count: int = 50, inject_attack: bool = None) -> List[Dict]:
    """Generate mock OT logs using the mock connector."""
    from connectors.mock_connector import MockConnector
    scenario = "attack" if inject_attack else ("normal" if inject_attack is False else "mixed")
    conn = MockConnector(scenario=scenario)
    conn.connect()
    logs = conn.get_logs(limit=count)
    return [
        {
            "timestamp": l.timestamp, "src_ip": l.src_ip, "dst_ip": l.dst_ip,
            "src_port": l.src_port, "dst_port": l.dst_port,
            "protocol": l.protocol, "action": l.action,
            "bytes": l.bytes_transferred, "duration": l.duration,
            "segment": l.segment,
        }
        for l in logs
    ]


def _run_topological_scan_from_logs(logs: List[Dict], dataset: str) -> Dict:
    """Run topo engine on network logs (live/SSH). Logs → time series → topo."""
    try:
        from engine.log_transformer import LogTransformer
        import numpy as np

        transformer = LogTransformer(window_sec=10)
        sensor_data, sensor_names = transformer.transform(logs)

        if sensor_data.shape[0] == 0 or sensor_data.shape[1] < 10:
            return _empty_topo_result("Insufficient data for topological analysis")

        return _run_topological_scan_from_sensors(sensor_data, sensor_names, dataset)

    except Exception as e:
        logger.error(f"Topological scan (logs) error: {e}")
        traceback.print_exc()
        return _empty_topo_result(str(e))


def _run_topological_scan_from_sensors(sensor_data, sensor_names: list, dataset: str) -> Dict:
    """Run topo engine on sensor time series (HAI/SWaT/BATADAL or transformed logs)."""
    try:
        from engine.scanner import TopologicalScanner
        from config.settings import get_config
        import numpy as np

        global _scanner_instance, _scanner_calibrated_for

        # Initialize or recalibrate scanner
        max_sensors = 30  # Hard cap — 30 sensors keeps DTW under 1s and RAM under 2GB

        if _scanner_instance is None or _scanner_calibrated_for != dataset:
            config = get_config()
            _scanner_instance = TopologicalScanner(config)
            _scanner_calibrated_for = dataset

            # Calibrate with baseline data if available, NOT the test window
            try:
                from engine.data_loader import DataLoader
                loader = DataLoader(data_dir=DATA_DIR)
                baseline_data, baseline_names = loader.load_baseline(dataset, max_rows=5000)

                # CRITICAL: subsample BEFORE calibration to avoid OOM
                # 225 sensors × 225 sensors = 25K DTW pairs → OOM in Docker
                if baseline_data.shape[0] > max_sensors:
                    variances = np.var(baseline_data, axis=1)
                    top_idx = np.sort(np.argsort(variances)[-max_sensors:])
                    baseline_data = baseline_data[top_idx]
                    baseline_names = [baseline_names[i] for i in top_idx]

                _scanner_instance.calibrate(baseline_data, baseline_names)
                logger.info(
                    f"Scanner calibrated for {dataset}: "
                    f"{baseline_data.shape[0]} sensors, "
                    f"{len(_scanner_instance._sheaf_maps)} sheaf maps"
                )
            except Exception as cal_err:
                # Fallback: calibrate with the current window (not ideal but better than nothing)
                logger.warning(f"Baseline calibration failed ({cal_err}), using window data")
                if sensor_data.shape[1] >= 30:
                    cal_data = sensor_data[:, :min(sensor_data.shape[1], 500)]
                    _scanner_instance.calibrate(cal_data, sensor_names)

        # Subsample scan data to same cap
        if sensor_data.shape[0] > max_sensors:
            variances = np.var(sensor_data, axis=1)
            top_idx = np.sort(np.argsort(variances)[-max_sensors:])
            sensor_data = sensor_data[top_idx]
            sensor_names = [sensor_names[i] for i in top_idx]

        result = _scanner_instance.scan(
            data_source=dataset,
            sensor_data=sensor_data,
            sensor_names=sensor_names,
        )
        return result.to_dict()

    except Exception as e:
        logger.error(f"Topological scan error: {e}")
        traceback.print_exc()
        return _empty_topo_result(str(e))


def _load_dataset_window(loader, dataset: str, window_idx: int,
                          window_size: int = 60, step_size: int = 10):
    """Load one window of sensor data from a real dataset."""
    import numpy as np

    # Only load enough rows to reach the requested window
    # (not 50000 every time — that's 80MB of RAM for one window)
    rows_needed = window_idx * step_size + window_size + 100  # small buffer
    max_rows = max(rows_needed, 1000)  # minimum 1000 for stats

    if dataset == "hai":
        data, names = loader.load_hai(mode="test", file_index=1, max_rows=max_rows)
    elif dataset == "swat":
        data, names = loader.load_swat(file_index=1, max_rows=max_rows)
    elif dataset == "batadal":
        data, names = loader.load_batadal(mode="test", max_rows=max_rows)
    else:
        raise ValueError(f"Unknown dataset: {dataset}")

    n_sensors, total_samples = data.shape
    start = window_idx * step_size
    end = start + window_size

    if end > total_samples:
        start = max(0, total_samples - window_size)
        end = total_samples

    window = data[:, start:end]

    variances = np.var(window, axis=1)
    mean_var = np.mean(variances)
    std_var = np.std(variances)

    anomalous_sensors = []
    for i, (var, name) in enumerate(zip(variances, names)):
        if std_var > 0 and var > mean_var + 2 * std_var:
            anomalous_sensors.append({"name": name, "variance": round(float(var), 4)})

    dead_sensors = [names[i] for i in range(n_sensors) if np.std(window[i]) < 1e-10]

    stats = {
        "dataset": dataset, "window_index": window_idx,
        "window_range": f"{start}:{end}",
        "total_sensors": n_sensors, "total_samples": total_samples,
        "window_samples": window.shape[1],
        "anomalous_sensors": anomalous_sensors[:10],
        "mean_variance": round(float(mean_var), 4),
        "dead_sensors": dead_sensors[:5],
        "dead_count": len(dead_sensors),
    }

    return window, names, stats


def _merge_deep_result(topo_result: Dict, analysis: Dict) -> Dict:
    """Merge topological results with GPT analysis."""
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


def _empty_topo_result(error: str = "") -> Dict:
    return {
        "status": "CLEAN", "gate_results": [], "involved_sensors": [],
        "betti_h0": 0, "betti_h1": 0, "betti_h2": 0, "betti_h3": 0,
        "gates_triggered": 0, "confidence": "none", "error": error,
    }


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

    Body JSON:
        dataset: "live" | "hai" | "swat" | "batadal"
        scan_type: "quick" (GPT) | "deep" (topological engine)
        log_count: number of logs to generate for live mode (default 50)
        window_index: which window to analyze for real datasets
        inject_attack: true/false for live mode (null = random)
    """
    global _scan_counter, _last_logs

    data = request.get_json(silent=True) or {}
    scan_type = data.get("scan_type", "deep")  # Default to deep — this is the value proposition
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

    try:
        # ══════════════════════════════════════════════════
        # ROUTE 1: LIVE (simulation or real device)
        # ══════════════════════════════════════════════════
        if dataset == "live":
            if _live_device_logs:
                logs = _live_device_logs[-log_count:]
                result["data_source"] = f"live_device ({_live_device_info.get('host', '?')})"
            else:
                inject = data.get("inject_attack", None)
                logs = _generate_mock_logs(count=log_count, inject_attack=inject)
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
                    "gate_results": [], "involved_sensors": [],
                    "betti_h0": 0, "betti_h1": 0, "betti_h2": 0, "betti_h3": 0,
                    "gates_triggered": 0, "confidence": "none",
                })
            else:  # deep
                topo_result = _run_topological_scan_from_logs(logs, dataset)
                analysis = gpt_analyze_logs(logs)
                result.update(_merge_deep_result(topo_result, analysis))

        # ══════════════════════════════════════════════════
        # ROUTE 2: REAL DATASETS (HAI, SWaT, BATADAL)
        # ══════════════════════════════════════════════════
        elif dataset in ("hai", "swat", "batadal"):
            from engine.data_loader import DataLoader
            loader = DataLoader(data_dir=DATA_DIR)

            window_idx = data.get("window_index", _scan_counter - 1)
            window_size = data.get("window_size", 60)
            step_size = data.get("step_size", 10)

            sensor_data, sensor_names, stats = _load_dataset_window(
                loader, dataset, window_idx, window_size, step_size
            )
            result["logs_analyzed"] = sensor_data.shape[1] if sensor_data is not None else 0
            result["data_source"] = f"{dataset} (window {window_idx})"
            result["sensor_count"] = len(sensor_names)

            if scan_type == "quick":
                analysis = _gpt_analyze_sensor_data(sensor_data, sensor_names, stats, dataset)
                result.update({
                    "status": analysis.get("threat_level", "CLEAN"),
                    "summary": analysis.get("summary", ""),
                    "findings": analysis.get("findings", []),
                    "network_health": analysis.get("network_health", {}),
                    "recommendations": analysis.get("recommendations", []),
                    "gate_results": [], "involved_sensors": [],
                    "betti_h0": 0, "betti_h1": 0, "betti_h2": 0, "betti_h3": 0,
                    "gates_triggered": 0, "confidence": "none",
                })
            else:  # deep
                topo_result = _run_topological_scan_from_sensors(sensor_data, sensor_names, dataset)
                analysis = _gpt_analyze_sensor_data(sensor_data, sensor_names, stats, dataset, topo_result)
                result.update(_merge_deep_result(topo_result, analysis))

        else:
            result.update({
                "status": "CLEAN", "summary": f"Unknown dataset: {dataset}",
                "findings": [], "network_health": {}, "recommendations": [],
                "gate_results": [], "involved_sensors": [],
                "betti_h0": 0, "betti_h1": 0, "betti_h2": 0, "betti_h3": 0,
                "gates_triggered": 0, "confidence": "none",
            })

    except FileNotFoundError as e:
        result.update({
            "status": "CLEAN",
            "summary": f"Dataset '{dataset}' not found: {e}",
            "findings": [{"severity": "info", "title": "Dataset Not Found",
                          "detail": str(e), "involved_ips": [], "evidence": ""}],
            "network_health": {}, "recommendations": [f"Download {dataset} dataset"],
            "gate_results": [], "involved_sensors": [],
            "betti_h0": 0, "betti_h1": 0, "betti_h2": 0, "betti_h3": 0,
            "gates_triggered": 0, "confidence": "none",
        })
    except Exception as e:
        logger.error(f"Scan error: {e}")
        traceback.print_exc()
        result.update({
            "status": "CLEAN", "summary": f"Error: {e}",
            "findings": [{"severity": "warning", "title": "Scan Error",
                          "detail": str(e), "involved_ips": [], "evidence": ""}],
            "network_health": {}, "recommendations": [],
            "gate_results": [], "involved_sensors": [],
            "betti_h0": 0, "betti_h1": 0, "betti_h2": 0, "betti_h3": 0,
            "gates_triggered": 0, "confidence": "none",
        })

    # ── Save to DB ──
    try:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO scan_history
                (timestamp, timestamp_iso, scan_type, dataset, status,
                 summary, findings, network_health, recommendations,
                 gate_results, involved_sensors,
                 betti_h0, betti_h1, betti_h2, betti_h3,
                 epsilon, gates_triggered, confidence, raw_result)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
                result.get("epsilon", 0.0),
                result.get("gates_triggered", 0),
                result.get("confidence", "none"),
                json.dumps(result),
            ))
            result["scan_id"] = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    except Exception as e:
        logger.error(f"DB save error: {e}")

    return jsonify(result)


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
    data = request.get_json(silent=True) or {}
    user_message = data.get("message", "").strip()
    session_id = data.get("session_id", "default")

    if not user_message:
        return jsonify({"error": "Empty message"}), 400

    if session_id not in _chat_histories:
        _chat_histories[session_id] = []

    context = {}
    try:
        with get_db() as conn:
            row = conn.execute("SELECT raw_result FROM scan_history ORDER BY timestamp DESC LIMIT 1").fetchone()
            if row:
                context = json.loads(row["raw_result"])
    except Exception:
        pass

    _chat_histories[session_id].append({"role": "user", "content": user_message})
    response_text = gpt_chat(user_message, context=context, history=_chat_histories[session_id])
    _chat_histories[session_id].append({"role": "assistant", "content": response_text})

    if len(_chat_histories[session_id]) > 20:
        _chat_histories[session_id] = _chat_histories[session_id][-16:]

    return jsonify({"response": response_text})


@app.route("/assistant/", methods=["POST"])
@app.route("/assistant", methods=["POST"])
def assistant_compat():
    """Backwards-compatible assistant endpoint (frontend uses this)."""
    data = request.get_json(silent=True) or {}
    prompt = data.get("prompt", "").strip()
    if not prompt:
        return jsonify({"error": "Empty prompt"}), 400

    context = {}
    try:
        with get_db() as conn:
            row = conn.execute("SELECT raw_result FROM scan_history ORDER BY timestamp DESC LIMIT 1").fetchone()
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
                for field in ["findings", "network_health", "recommendations", "gate_results", "involved_sensors"]:
                    try:
                        scan[field] = json.loads(scan.get(field, "[]"))
                    except (json.JSONDecodeError, TypeError):
                        pass
                scans.append(scan)

            return jsonify({"scans": scans, "total": len(scans)})
    except Exception as e:
        logger.error(f"History error: {e}")
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
                    except (json.JSONDecodeError, TypeError):
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
            critical = conn.execute("SELECT COUNT(*) as c FROM scan_history WHERE status IN ('CRITICAL','HIGH_ALERT')").fetchone()["c"]
            suspicious = conn.execute("SELECT COUNT(*) as c FROM scan_history WHERE status IN ('SUSPICIOUS','MID_ALERT')").fetchone()["c"]
            return jsonify({"total": total, "critical": critical, "suspicious": suspicious, "clean": total - critical - suspicious})
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return jsonify({"total": 0, "critical": 0, "suspicious": 0, "clean": 0})


@app.route("/history/export")
def export_history():
    try:
        with get_db() as conn:
            rows = conn.execute(
                "SELECT id, timestamp_iso, scan_type, dataset, status, summary, "
                "betti_h0, betti_h1, betti_h2, betti_h3, gates_triggered, confidence "
                "FROM scan_history ORDER BY timestamp ASC"
            ).fetchall()
        if not rows:
            return Response("No scans recorded", mimetype="text/csv")
        cols = rows[0].keys()
        lines = [",".join(cols)]
        for r in rows:
            vals = []
            for c in cols:
                v = r[c]
                if isinstance(v, str) and ("," in v or '"' in v):
                    v = f'"{v}"'
                vals.append(str(v if v is not None else ""))
            lines.append(",".join(vals))
        return Response("\n".join(lines), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=scan_history.csv"})
    except Exception as e:
        return Response(f"Error: {e}", mimetype="text/plain")


# ── LOGS ──────────────────────────────────────────────────────

@app.route("/logs/", methods=["GET"])
@app.route("/logs", methods=["GET"])
def get_logs_route():
    limit = request.args.get("limit", 100, type=int)
    if _last_logs:
        return jsonify({"logs": _last_logs[-limit:], "count": len(_last_logs)})
    logs = _generate_mock_logs(count=limit)
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
    except Exception as e:
        logger.error(f"Get nodes error: {e}")
        return jsonify({"nodes": []})


@app.route("/topology/nodes/pending")
def get_pending():
    try:
        with get_db() as conn:
            rows = conn.execute(
                "SELECT * FROM network_nodes WHERE status='pending' ORDER BY first_seen DESC"
            ).fetchall()
            return jsonify({"pending": [dict(r) for r in rows]})
    except Exception as e:
        logger.error(f"Get pending error: {e}")
        return jsonify({"pending": []})


@app.route("/topology/nodes", methods=["POST"])
def add_node_route():
    data = request.get_json(silent=True) or {}
    node_id = data.get("node_id", "")
    if not node_id:
        return jsonify({"error": "node_id required"}), 400

    label = data.get("label", node_id)
    segment = data.get("segment", "unknown")
    node_type = data.get("node_type", "sensor")
    now = time.time()

    try:
        with get_db() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO network_nodes
                (node_id, label, segment, node_type, status, first_seen, last_seen, added_by)
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
    """Connect to a live device via SSH."""
    global _live_device_logs, _live_device_info

    data = request.get_json(silent=True) or {}
    host = data.get("host", "")
    username = data.get("username", "")
    password = data.get("password", "")
    device_type = data.get("device_type", "cisco_ios")
    port = data.get("port", 22)

    if not host or not username:
        return jsonify({"error": "host and username are required"}), 400

    try:
        from connectors.ssh_connector import SSHConnector
    except ImportError:
        return jsonify({"error": "Netmiko not installed. Run: pip install netmiko"}), 500

    connector = SSHConnector(host, username, password, device_type, port=int(port))

    if not connector.connect():
        error_msg = connector.get_last_error() or f"SSH connection to {host} failed"
        return jsonify({"error": error_msg}), 500

    try:
        logs = connector.get_logs(limit=500)
        topology = connector.get_topology()
        routes = connector.get_routes()
    except Exception as e:
        connector.disconnect()
        return jsonify({"error": f"Failed to pull data from {host}: {e}"}), 500
    finally:
        connector.disconnect()

    # Store for subsequent scans
    _live_device_logs = [
        {
            "timestamp": l.timestamp, "src_ip": l.src_ip, "dst_ip": l.dst_ip,
            "src_port": l.src_port, "dst_port": l.dst_port,
            "protocol": l.protocol, "action": l.action,
            "bytes": l.bytes_transferred, "duration": l.duration,
            "segment": l.segment,
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
        "message": f"Connected to {host}",
        "logs_parsed": len(logs),
        "devices_found": len(topology),
        "routes_found": len(routes),
    })


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
    logger.info(f"Topo Scanner v7 on {host}:{port} | AI: {'enabled' if ai_client else 'disabled'}")
    app.run(host=host, port=port, debug=debug)