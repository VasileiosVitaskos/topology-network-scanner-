"""
app/models/database.py
SQLite persistence layer.

Two tables:
  1. scan_history  — every scan result, unlimited, exportable to CSV
  2. network_nodes — known network topology, operator-managed

Why SQLite:
  - Zero config, single file, perfect for Docker
  - Survives container restarts (volume mount)
  - Export to CSV with one query
  - No external dependencies
"""

import os
import sqlite3
import json
import time
from pathlib import Path
from typing import List, Optional, Dict, Any
from contextlib import contextmanager


# ── Database path from env or default ────────────────────────
DB_PATH = os.getenv("DB_PATH", "/app/db/topo_scanner.db")


@contextmanager
def get_db():
    """
    Context manager for DB connections.
    Auto-commits on success, rolls back on error.
    Usage:
        with get_db() as conn:
            conn.execute(...)
    """
    # Ensure directory exists
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Dict-like access: row["column"]
    conn.execute("PRAGMA journal_mode=WAL")  # Better concurrent reads
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """
    Create tables if they don't exist.
    Called once at app startup.
    """
    with get_db() as conn:
        # ── Table 1: Scan History ────────────────────────────
        # Stores every scan result for timeline view + CSV export
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       REAL    NOT NULL,       -- Unix timestamp
                timestamp_iso   TEXT    NOT NULL,       -- Human readable
                dataset         TEXT    NOT NULL,       -- swat, batadal, hai, cicids
                domain          TEXT    NOT NULL,       -- water_treatment, etc.
                status          TEXT    NOT NULL,       -- CLEAN, INFO, WARNING, ALERT
                betti_h0        INTEGER NOT NULL DEFAULT 0,
                betti_h1        INTEGER NOT NULL DEFAULT 0,
                betti_h2        INTEGER NOT NULL DEFAULT 0,
                betti_h3        INTEGER NOT NULL DEFAULT 0,
                epsilon         REAL    NOT NULL DEFAULT 0.0,
                persistence_gap REAL    NOT NULL DEFAULT 0.0,
                confidence      TEXT    NOT NULL DEFAULT 'low',
                pattern         TEXT    NOT NULL DEFAULT '',
                involved_sensors TEXT   NOT NULL DEFAULT '[]',  -- JSON array
                window_start    TEXT    NOT NULL DEFAULT '',
                window_end      TEXT    NOT NULL DEFAULT '',
                consecutive_alerts INTEGER NOT NULL DEFAULT 0,
                -- Full scan result as JSON for anything we missed
                raw_result      TEXT    NOT NULL DEFAULT '{}'
            )
        """)

        # Index on timestamp for fast history queries
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_timestamp 
            ON scan_history(timestamp DESC)
        """)

        # Index on status for filtering alerts
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_status 
            ON scan_history(status)
        """)

        # ── Table 2: Network Nodes ───────────────────────────
        # Known network topology — operator adds/confirms nodes
        conn.execute("""
            CREATE TABLE IF NOT EXISTS network_nodes (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id     TEXT    NOT NULL UNIQUE,  -- IP or sensor ID (e.g. "192.168.1.10" or "FIT101")
                label       TEXT    NOT NULL,          -- Display name (e.g. "PLC-Stage1")
                segment     TEXT    NOT NULL DEFAULT 'unknown',  -- plc, scada, workstation, dmz, unknown
                node_type   TEXT    NOT NULL DEFAULT 'sensor',   -- sensor, plc, hmi, switch, firewall, workstation
                status      TEXT    NOT NULL DEFAULT 'confirmed', -- confirmed, pending, removed
                first_seen  REAL    NOT NULL,          -- Unix timestamp when first detected
                last_seen   REAL    NOT NULL,          -- Updated on every sighting
                added_by    TEXT    NOT NULL DEFAULT 'auto',  -- auto (from logs) or manual (operator)
                metadata    TEXT    NOT NULL DEFAULT '{}'      -- Extra JSON: port, protocol, etc.
            )
        """)

        # Index for fast lookups by node_id
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_node_id 
            ON network_nodes(node_id)
        """)

        # Index for filtering by status (pending nodes need confirmation)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_node_status 
            ON network_nodes(status)
        """)


# ── Scan History Operations ──────────────────────────────────

def save_scan(scan_result: Dict[str, Any]) -> int:
    """
    Save a scan result to history.
    Returns the new scan ID.
    """
    now = time.time()
    from datetime import datetime, timezone
    iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()

    with get_db() as conn:
        cursor = conn.execute("""
            INSERT INTO scan_history 
            (timestamp, timestamp_iso, dataset, domain, status,
             betti_h0, betti_h1, betti_h2, betti_h3,
             epsilon, persistence_gap, confidence, pattern,
             involved_sensors, window_start, window_end,
             consecutive_alerts, raw_result)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            now,
            iso,
            scan_result.get("data_source", "unknown"),
            scan_result.get("domain", "unknown"),
            scan_result.get("status", "UNKNOWN"),
            scan_result.get("betti_h0", 0),
            scan_result.get("betti_h1", 0),
            scan_result.get("betti_h2", 0),
            scan_result.get("betti_h3", 0),
            scan_result.get("epsilon", 0.0),
            scan_result.get("persistence_gap", 0.0),
            scan_result.get("confidence", "low"),
            scan_result.get("pattern", ""),
            json.dumps(scan_result.get("involved_sensors", [])),
            scan_result.get("window", "").split(" -> ")[0] if " -> " in scan_result.get("window", "") else "",
            scan_result.get("window", "").split(" -> ")[1] if " -> " in scan_result.get("window", "") else "",
            scan_result.get("consecutive_alerts", 0),
            json.dumps(scan_result),
        ))
        return cursor.lastrowid


def get_scan_history(
    limit: int = 100,
    offset: int = 0,
    status_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Fetch scan history, newest first.
    Optional: filter by status (CLEAN, WARNING, ALERT).
    """
    with get_db() as conn:
        if status_filter:
            rows = conn.execute("""
                SELECT * FROM scan_history 
                WHERE status = ?
                ORDER BY timestamp DESC 
                LIMIT ? OFFSET ?
            """, (status_filter, limit, offset)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM scan_history 
                ORDER BY timestamp DESC 
                LIMIT ? OFFSET ?
            """, (limit, offset)).fetchall()

        return [dict(row) for row in rows]


def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    """Fetch a single scan by ID."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM scan_history WHERE id = ?", (scan_id,)
        ).fetchone()
        return dict(row) if row else None


def get_scan_count() -> int:
    """Total number of scans in history."""
    with get_db() as conn:
        row = conn.execute("SELECT COUNT(*) as cnt FROM scan_history").fetchone()
        return row["cnt"]


def export_scans_csv() -> str:
    """
    Export all scan history as CSV string.
    Ready to send as file download.
    """
    with get_db() as conn:
        rows = conn.execute("""
            SELECT id, timestamp_iso, dataset, domain, status,
                   betti_h0, betti_h1, betti_h2, betti_h3,
                   epsilon, persistence_gap, confidence, pattern,
                   involved_sensors, window_start, window_end,
                   consecutive_alerts
            FROM scan_history 
            ORDER BY timestamp ASC
        """).fetchall()

    if not rows:
        return "No scans recorded yet."

    # CSV header
    columns = rows[0].keys()
    lines = [",".join(columns)]

    # CSV rows
    for row in rows:
        values = []
        for col in columns:
            val = row[col]
            # Escape commas in string values
            if isinstance(val, str) and ("," in val or '"' in val):
                val = f'"{val}"'
            values.append(str(val))
        lines.append(",".join(values))

    return "\n".join(lines)


# ── Network Nodes Operations ────────────────────────────────

def add_node(
    node_id: str,
    label: str,
    segment: str = "unknown",
    node_type: str = "sensor",
    status: str = "confirmed",
    added_by: str = "manual",
    metadata: dict = None,
) -> int:
    """
    Add a new node to the topology.
    Returns node row ID, or -1 if already exists.
    """
    now = time.time()
    with get_db() as conn:
        try:
            cursor = conn.execute("""
                INSERT INTO network_nodes 
                (node_id, label, segment, node_type, status, 
                 first_seen, last_seen, added_by, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                node_id, label, segment, node_type, status,
                now, now, added_by,
                json.dumps(metadata or {}),
            ))
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            # Already exists — update last_seen instead
            conn.execute("""
                UPDATE network_nodes 
                SET last_seen = ? 
                WHERE node_id = ?
            """, (now, node_id))
            return -1


def detect_new_node(
    node_id: str,
    metadata: dict = None,
) -> bool:
    """
    Auto-detect: called when we see an IP/sensor in logs
    that doesn't exist in our topology.
    
    Adds it as status='pending' so operator sees the notification.
    Returns True if this is genuinely new, False if already known.
    """
    with get_db() as conn:
        existing = conn.execute(
            "SELECT id, status FROM network_nodes WHERE node_id = ?",
            (node_id,)
        ).fetchone()

        now = time.time()

        if existing is None:
            # Brand new — add as pending
            conn.execute("""
                INSERT INTO network_nodes
                (node_id, label, segment, node_type, status,
                 first_seen, last_seen, added_by, metadata)
                VALUES (?, ?, 'unknown', 'unknown', 'pending', ?, ?, 'auto', ?)
            """, (
                node_id,
                node_id,  # Label defaults to the ID until operator names it
                now, now,
                json.dumps(metadata or {}),
            ))
            return True
        else:
            # Already known — just update last_seen
            conn.execute(
                "UPDATE network_nodes SET last_seen = ? WHERE node_id = ?",
                (now, node_id)
            )
            return False


def confirm_node(node_id: str, label: str = None, segment: str = None, node_type: str = None) -> bool:
    """
    Operator confirms a pending node.
    Optionally sets label, segment, type.
    """
    with get_db() as conn:
        # Build dynamic update
        updates = ["status = 'confirmed'"]
        params = []
        if label:
            updates.append("label = ?")
            params.append(label)
        if segment:
            updates.append("segment = ?")
            params.append(segment)
        if node_type:
            updates.append("node_type = ?")
            params.append(node_type)

        params.append(node_id)
        query = f"UPDATE network_nodes SET {', '.join(updates)} WHERE node_id = ?"
        
        cursor = conn.execute(query, params)
        return cursor.rowcount > 0


def remove_node(node_id: str) -> bool:
    """
    Soft delete — mark as 'removed', don't actually delete.
    Keeps history intact.
    """
    with get_db() as conn:
        cursor = conn.execute(
            "UPDATE network_nodes SET status = 'removed' WHERE node_id = ?",
            (node_id,)
        )
        return cursor.rowcount > 0


def get_all_nodes(include_removed: bool = False) -> List[Dict[str, Any]]:
    """Get all network nodes."""
    with get_db() as conn:
        if include_removed:
            rows = conn.execute(
                "SELECT * FROM network_nodes ORDER BY segment, node_id"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM network_nodes WHERE status != 'removed' ORDER BY segment, node_id"
            ).fetchall()
        return [dict(row) for row in rows]


def get_pending_nodes() -> List[Dict[str, Any]]:
    """Get nodes awaiting operator confirmation."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM network_nodes WHERE status = 'pending' ORDER BY first_seen DESC"
        ).fetchall()
        return [dict(row) for row in rows]


def get_node(node_id: str) -> Optional[Dict[str, Any]]:
    """Get a single node by ID."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM network_nodes WHERE node_id = ?", (node_id,)
        ).fetchone()
        return dict(row) if row else None
