"""
app/models/schemas.py
Core data models for the topological scanner.
All structured output flows through these.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Optional, Dict, Any


class AlertLevel(str, Enum):
    """Alert levels based on gate count."""
    CLEAN = "CLEAN"            # 0 gates triggered
    MID_ALERT = "MID_ALERT"    # 1-2 gates triggered
    HIGH_ALERT = "HIGH_ALERT"  # 3 gates triggered
    UNKNOWN = "UNKNOWN"


@dataclass
class GateResult:
    """Output from a single gate."""
    gate_name: str              # "sheaf", "ricci", "homology"
    triggered: bool             # Did this gate fire?
    findings: List[str]         # Human-readable findings
    involved_nodes: List[str]   # IPs/sensor IDs involved
    details: Dict[str, Any]     # Raw data (z-scores, curvatures, betti)

    def to_dict(self) -> dict:
        return {
            "gate": self.gate_name,
            "triggered": self.triggered,
            "findings": self.findings,
            "involved_nodes": self.involved_nodes,
            "details": self.details,
        }


@dataclass
class BettiNumbers:
    """Betti numbers β0..β3 at a given filtration scale."""
    h0: int = 0
    h1: int = 0
    h2: int = 0
    h3: int = 0

    def to_dict(self) -> dict:
        return {"h0": self.h0, "h1": self.h1, "h2": self.h2, "h3": self.h3}


@dataclass
class PersistenceFeature:
    """A single birth-death pair from the persistence diagram."""
    dimension: int
    birth: float
    death: float
    lifetime: float = 0.0

    def __post_init__(self):
        self.lifetime = self.death - self.birth


@dataclass
class ScanResult:
    """Structured output from a single topological scan window."""
    status: AlertLevel = AlertLevel.CLEAN
    betti: BettiNumbers = field(default_factory=BettiNumbers)
    involved_sensors: List[str] = field(default_factory=list)
    confidence: str = "none"
    pattern: str = ""
    window_start: str = ""
    window_end: str = ""
    epsilon: float = 0.0
    persistence_gap: float = 0.0
    persistence_diagram: List[PersistenceFeature] = field(default_factory=list)
    consecutive_alerts: int = 0
    domain: str = ""
    data_source: str = ""
    gate_results: List[GateResult] = field(default_factory=list)
    gates_triggered: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "betti_h0": self.betti.h0,
            "betti_h1": self.betti.h1,
            "betti_h2": self.betti.h2,
            "betti_h3": self.betti.h3,
            "involved_sensors": self.involved_sensors,
            "confidence": self.confidence,
            "pattern": self.pattern,
            "window": f"{self.window_start} -> {self.window_end}",
            "epsilon": round(self.epsilon, 4),
            "persistence_gap": round(self.persistence_gap, 4),
            "consecutive_alerts": self.consecutive_alerts,
            "domain": self.domain,
            "data_source": self.data_source,
            "gates_triggered": self.gates_triggered,
            "gate_results": [g.to_dict() for g in self.gate_results],
        }


@dataclass
class LogEntry:
    """A single firewall/IDS log entry."""
    timestamp: float = 0.0
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    action: str = "ALLOW"
    bytes_transferred: int = 0
    duration: float = 0.0
    segment: str = ""
    sensor_id: str = ""
    sensor_value: float = 0.0
    label: str = "Normal"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DenyEvent:
    """Lightweight DENY event for the reconnaissance pre-filter."""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    timestamp: float = 0.0
