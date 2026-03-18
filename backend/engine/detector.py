"""
engine/detector.py
Anomaly classification + temporal persistence buffer.

Two-stage detection:
    Stage 1: Single-window classification
        - Betti-based (top-down scan: β₃ → β₂ → β₁ → β₀)
        - Gate-based (count of triggered gates: 3 → HIGH, 1-2 → MID, 0 → CLEAN)
        - Combined: takes the maximum severity from both

    Stage 2: Temporal persistence buffer
        - Tracks consecutive anomalous windows
        - Escalates MID → HIGH after min_consecutive persistent anomalies
        - Prevents single-window noise from triggering alerts
        - De-escalates after sustained clean windows

The scanner calls process_window() every scan cycle.
The detector never sees raw sensor data — only classified results.
"""

import logging
from typing import Dict, List, Tuple, Optional
from collections import deque
from dataclasses import dataclass

from app.models.schemas import (
    AlertLevel,
    BettiNumbers,
    GateResult,
    PersistenceFeature,
)

logger = logging.getLogger(__name__)


@dataclass
class WindowRecord:
    """One entry in the temporal buffer."""
    betti: BettiNumbers
    betti_level: AlertLevel
    gate_level: AlertLevel
    final_level: AlertLevel
    gates_triggered: int
    consecutive_anomaly: int


class AnomalyDetector:
    """
    Classifies scan windows and maintains temporal persistence buffer.

    The temporal buffer prevents single noisy windows from triggering
    alerts. An anomaly must persist for min_consecutive windows before
    escalation. This is critical because:
        - Pearson correlation on 60 samples has noise
        - A single window with β₂ > 0 could be a numerical artifact
        - Real coordinated attacks persist across multiple windows
    """

    def __init__(
        self,
        h2_threshold: int = 1,
        h1_sigma: float = 3.0,
        h0_sigma: float = 2.0,
        min_consecutive: int = 3,
    ):
        self.h2_threshold = h2_threshold
        self.h1_sigma = h1_sigma
        self.h0_sigma = h0_sigma
        self.min_consecutive = min_consecutive

        # Baseline Betti stats from calibration: {dimension: (mean, std)}
        self.baseline: Dict[int, Tuple[float, float]] = {}

        # ── Temporal buffer ──
        # Stores last ~1 hour of results (360 windows at 10s steps)
        self.window_history: deque = deque(maxlen=360)

        # Consecutive anomaly counters
        self.consecutive_h2_count: int = 0       # β₂ > 0 streak
        self.consecutive_gate_count: int = 0     # any gate triggered streak
        self.consecutive_clean_count: int = 0    # clean streak (for de-escalation)

        # Sustained alert state
        self._escalated: bool = False

    def set_baseline(self, stats: Dict[int, Tuple[float, float]]) -> None:
        """
        Set baseline Betti statistics from calibration phase.

        Args:
            stats: {dimension: (mean, std)} e.g. {0: (4.2, 0.8), 1: (1.1, 0.5), ...}
        """
        self.baseline = stats
        logger.info(
            f"Baseline set: " +
            ", ".join(f"β{k}={mu:.1f}±{sigma:.1f}" for k, (mu, sigma) in sorted(stats.items()))
        )

    # ══════════════════════════════════════════════════════════
    # STAGE 1: SINGLE-WINDOW CLASSIFICATION
    # ══════════════════════════════════════════════════════════

    def classify_betti(self, betti: BettiNumbers) -> AlertLevel:
        """
        Betti-based classification (top-down scan with early exit).

        Scan order reflects topological significance:
            β₃ > 0  → 5-node coordination (botnet mesh) → HIGH
            β₂ > 0  → 4-node coordination loop           → MID (escalate if persistent)
            β₁ anom → unusual relay chains                → MID
            β₀ anom → topology fragmentation              → INFO (logged, not alerted)
            normal  →                                     → CLEAN
        """
        # β₃: highest dimension — extremely rare, always significant
        if betti.h3 > 0:
            return AlertLevel.HIGH_ALERT

        # β₂: primary detection signal
        if betti.h2 >= self.h2_threshold:
            return AlertLevel.MID_ALERT

        # β₁: compare against calibrated baseline
        if 1 in self.baseline:
            mu, sigma = self.baseline[1]
            if sigma > 0 and betti.h1 > mu + self.h1_sigma * sigma:
                return AlertLevel.MID_ALERT

        return AlertLevel.CLEAN

    def classify_gates(self, gate_results: List[GateResult]) -> AlertLevel:
        """
        Gate-based classification (count triggered gates).

            3 gates → HIGH ALERT (mathematically confirmed attack)
            1-2 gates → MID ALERT (partial detection, investigate)
            0 gates → CLEAN
        """
        triggered = sum(1 for g in gate_results if g.triggered)

        if triggered >= 3:
            return AlertLevel.HIGH_ALERT
        elif triggered >= 1:
            return AlertLevel.MID_ALERT
        else:
            return AlertLevel.CLEAN

    # ══════════════════════════════════════════════════════════
    # STAGE 2: TEMPORAL PERSISTENCE BUFFER
    # ══════════════════════════════════════════════════════════

    def process_window(
        self,
        betti: BettiNumbers,
        gate_results: List[GateResult],
    ) -> AlertLevel:
        """
        Process one window through both classification stages + temporal buffer.

        This is the main entry point called by scanner.scan() every cycle.

        Returns:
            Final alert level after temporal persistence logic.
        """
        # ── Stage 1: classify ──
        betti_level = self.classify_betti(betti)
        gate_level = self.classify_gates(gate_results)

        # Take the maximum severity from both classifiers
        combined = self._max_level(betti_level, gate_level)

        # ── Stage 2: temporal persistence ──
        # Track β₂ streak
        if betti.h2 > 0:
            self.consecutive_h2_count += 1
        else:
            self.consecutive_h2_count = 0

        # Track gate-triggered streak
        gates_triggered = sum(1 for g in gate_results if g.triggered)
        if gates_triggered > 0:
            self.consecutive_gate_count += 1
            self.consecutive_clean_count = 0
        else:
            self.consecutive_gate_count = 0
            self.consecutive_clean_count += 1

        # ── Escalation logic ──
        final = combined

        # Escalate MID → HIGH if anomaly persists
        if combined == AlertLevel.MID_ALERT:
            persistent = (
                self.consecutive_h2_count >= self.min_consecutive
                or self.consecutive_gate_count >= self.min_consecutive
            )
            if persistent:
                final = AlertLevel.HIGH_ALERT
                if not self._escalated:
                    self._escalated = True
                    logger.warning(
                        f"ESCALATION: MID → HIGH after {self.min_consecutive} "
                        f"consecutive anomalous windows "
                        f"(β₂ streak: {self.consecutive_h2_count}, "
                        f"gate streak: {self.consecutive_gate_count})"
                    )

        # β₃ is always HIGH regardless of persistence
        if betti.h3 > 0:
            final = AlertLevel.HIGH_ALERT

        # De-escalate after sustained clean period
        if self.consecutive_clean_count >= self.min_consecutive * 2:
            if self._escalated:
                self._escalated = False
                logger.info("De-escalated: sustained clean windows")

        # ── Record in history ──
        record = WindowRecord(
            betti=betti,
            betti_level=betti_level,
            gate_level=gate_level,
            final_level=final,
            gates_triggered=gates_triggered,
            consecutive_anomaly=max(self.consecutive_h2_count, self.consecutive_gate_count),
        )
        self.window_history.append(record)

        return final

    # ══════════════════════════════════════════════════════════
    # ACCESSORS
    # ══════════════════════════════════════════════════════════

    def get_consecutive_count(self) -> int:
        """How many consecutive windows have shown β₂ > 0."""
        return self.consecutive_h2_count

    def get_gate_streak(self) -> int:
        """How many consecutive windows have had any gate triggered."""
        return self.consecutive_gate_count

    def is_escalated(self) -> bool:
        """Whether we're currently in an escalated state."""
        return self._escalated

    def get_recent_summary(self, n: int = 10) -> Dict:
        """
        Summary of the last N windows for context.
        Useful for the AI chat assistant to explain trends.
        """
        recent = list(self.window_history)[-n:]
        if not recent:
            return {"windows": 0, "alerts": 0, "clean": 0}

        alerts = sum(1 for r in recent if r.final_level != AlertLevel.CLEAN)
        high = sum(1 for r in recent if r.final_level == AlertLevel.HIGH_ALERT)

        return {
            "windows": len(recent),
            "clean": len(recent) - alerts,
            "mid_alerts": alerts - high,
            "high_alerts": high,
            "current_h2_streak": self.consecutive_h2_count,
            "current_gate_streak": self.consecutive_gate_count,
            "escalated": self._escalated,
        }

    # ══════════════════════════════════════════════════════════
    # HELPERS
    # ══════════════════════════════════════════════════════════

    @staticmethod
    def _max_level(a: AlertLevel, b: AlertLevel) -> AlertLevel:
        """Return the more severe of two alert levels."""
        order = {
            AlertLevel.CLEAN: 0,
            AlertLevel.MID_ALERT: 1,
            AlertLevel.HIGH_ALERT: 2,
        }
        if order.get(a, 0) >= order.get(b, 0):
            return a
        return b