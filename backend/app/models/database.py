"""
app/models/database.py
SQLite persistence layer — standalone utility module.

This module provides DB access for tools running OUTSIDE the Flask server:
    - validate_engine.py (save/read validation results)
    - CLI tools
    - Data export scripts

The Flask server (server.py) has its own get_db()/init_db() with the same
schema. Both use the same DB file and the same table structure.

Schema (two tables):
    scan_history   — every scan result, exportable to CSV
    network_nodes  — known network topology, operator-managed
"""

import os
import json
import logging
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# ── Database path from env or default ────────────────────────
DB_PATH = os.getenv("DB_PATH", "/app/db/topo_scanner.db")


@contextmanager
def get_db(db_path: str = None):
    """
    Context manager for DB connections.
    Auto-commits on success, rolls back on error.

    Args:
        db_path: override DB path (useful for tests)
    """
    path = db_path or DB_PATH
    Path(path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(path)
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


def init_db(db_path: str = None):
    """
    Create tables if they don't exist.
    Schema matches server.py exactly.
    """
    with get_db(db_path) as conn:
        # ── Scan History (matches server.py schema) ──
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                timestamp_iso TEXT NOT NULL,
                scan_type TEXT NOT NULL DEFAULT 'deep',
                dataset TEXT NOT NULL DEFAULT 'unknown',
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

        # ── Network Nodes ──
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

        # ── Indexes ──
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scan_history(timestamp DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_status ON scan_history(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_node_id ON network_nodes(node_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_node_status ON network_nodes(status)")


# ══════════════════════════════════════════════════════════════
# SCAN HISTORY OPERATIONS
# ══════════════════════════════════════════════════════════════

def save_scan(scan_result: Dict[str, Any], db_path: str = None) -> int:
    """
    Save a scan result to history. Returns the new scan ID.
    Accepts the dict from ScanResult.to_dict() or server.py's result dict.
    """
    now = time.time()
    iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()

    with get_db(db_path) as conn:
        cursor = conn.execute("""
            INSERT INTO scan_history
            (timestamp, timestamp_iso, scan_type, dataset, status,
             summary, findings, network_health, recommendations,
             gate_results, involved_sensors,
             betti_h0, betti_h1, betti_h2, betti_h3,
             epsilon, gates_triggered, confidence, raw_result)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            now, iso,
            scan_result.get("scan_type", "deep"),
            scan_result.get("data_source", scan_result.get("dataset", "unknown")),
            scan_result.get("status", "CLEAN"),
            scan_result.get("summary", scan_result.get("pattern", "")),
            json.dumps(scan_result.get("findings", [])),
            json.dumps(scan_result.get("network_health", {})),
            json.dumps(scan_result.get("recommendations", [])),
            json.dumps(scan_result.get("gate_results", [])),
            json.dumps(scan_result.get("involved_sensors", [])),
            scan_result.get("betti_h0", 0),
            scan_result.get("betti_h1", 0),
            scan_result.get("betti_h2", 0),
            scan_result.get("betti_h3", 0),
            scan_result.get("epsilon", 0.0),
            scan_result.get("gates_triggered", 0),
            scan_result.get("confidence", "none"),
            json.dumps(scan_result),
        ))
        return cursor.lastrowid


def get_scan_history(
    limit: int = 100,
    offset: int = 0,
    status_filter: Optional[str] = None,
    db_path: str = None,
) -> List[Dict[str, Any]]:
    """Fetch scan history, newest first."""
    with get_db(db_path) as conn:
        if status_filter:
            rows = conn.execute(
                "SELECT * FROM scan_history WHERE status=? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                (status_filter, limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scan_history ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()

        results = []
        for row in rows:
            scan = dict(row)
            for field in ["findings", "network_health", "recommendations", "gate_results", "involved_sensors"]:
                try:
                    scan[field] = json.loads(scan.get(field, "[]"))
                except (json.JSONDecodeError, TypeError):
                    pass
            results.append(scan)
        return results


def get_scan_by_id(scan_id: int, db_path: str = None) -> Optional[Dict[str, Any]]:
    """Fetch a single scan by ID."""
    with get_db(db_path) as conn:
        row = conn.execute("SELECT * FROM scan_history WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None


def get_scan_count(db_path: str = None) -> int:
    """Total number of scans."""
    with get_db(db_path) as conn:
        return conn.execute("SELECT COUNT(*) as cnt FROM scan_history").fetchone()["cnt"]


# ══════════════════════════════════════════════════════════════
# NETWORK NODE OPERATIONS
# ══════════════════════════════════════════════════════════════

def add_node(
    node_id: str, label: str,
    segment: str = "unknown", node_type: str = "sensor",
    status: str = "confirmed", added_by: str = "manual",
    metadata: dict = None, db_path: str = None,
) -> int:
    """Add a node. Returns row ID, or -1 if already exists."""
    now = time.time()
    with get_db(db_path) as conn:
        try:
            cursor = conn.execute("""
                INSERT INTO network_nodes
                (node_id, label, segment, node_type, status,
                 first_seen, last_seen, added_by, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (node_id, label, segment, node_type, status,
                  now, now, added_by, json.dumps(metadata or {})))
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            conn.execute(
                "UPDATE network_nodes SET last_seen=? WHERE node_id=?",
                (now, node_id),
            )
            return -1


def detect_new_node(node_id: str, metadata: dict = None, db_path: str = None) -> bool:
    """Auto-detect a new node from logs. Adds as 'pending'. Returns True if new."""
    with get_db(db_path) as conn:
        existing = conn.execute(
            "SELECT id FROM network_nodes WHERE node_id=?", (node_id,)
        ).fetchone()

        now = time.time()
        if existing is None:
            conn.execute("""
                INSERT INTO network_nodes
                (node_id, label, segment, node_type, status,
                 first_seen, last_seen, added_by, metadata)
                VALUES (?, ?, 'unknown', 'unknown', 'pending', ?, ?, 'auto', ?)
            """, (node_id, node_id, now, now, json.dumps(metadata or {})))
            return True
        else:
            conn.execute(
                "UPDATE network_nodes SET last_seen=? WHERE node_id=?",
                (now, node_id),
            )
            return False


def confirm_node(node_id: str, label: str = None, segment: str = None,
                  node_type: str = None, db_path: str = None) -> bool:
    """Confirm a pending node."""
    with get_db(db_path) as conn:
        updates = ["status='confirmed'"]
        params = []
        if label:
            updates.append("label=?")
            params.append(label)
        if segment:
            updates.append("segment=?")
            params.append(segment)
        if node_type:
            updates.append("node_type=?")
            params.append(node_type)
        params.append(node_id)
        cursor = conn.execute(
            f"UPDATE network_nodes SET {', '.join(updates)} WHERE node_id=?", params
        )
        return cursor.rowcount > 0


def remove_node(node_id: str, db_path: str = None) -> bool:
    """Soft-delete a node (mark as 'removed')."""
    with get_db(db_path) as conn:
        cursor = conn.execute(
            "UPDATE network_nodes SET status='removed' WHERE node_id=?", (node_id,)
        )
        return cursor.rowcount > 0


def get_all_nodes(include_removed: bool = False, db_path: str = None) -> List[Dict[str, Any]]:
    """Get all network nodes."""
    with get_db(db_path) as conn:
        if include_removed:
            rows = conn.execute("SELECT * FROM network_nodes ORDER BY segment, node_id").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM network_nodes WHERE status!='removed' ORDER BY segment, node_id"
            ).fetchall()
        return [dict(r) for r in rows]


def get_pending_nodes(db_path: str = None) -> List[Dict[str, Any]]:
    """Get nodes awaiting operator confirmation."""
    with get_db(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM network_nodes WHERE status='pending' ORDER BY first_seen DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def get_node(node_id: str, db_path: str = None) -> Optional[Dict[str, Any]]:
    """Get a single node by ID."""
    with get_db(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM network_nodes WHERE node_id=?", (node_id,)
        ).fetchone()
        return dict(row) if row else None