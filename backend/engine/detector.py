"""
app/engine/detector.py
Top-down anomaly scan + temporal persistence buffer.

Reference: Paper Section 4.6 (Top-Down Anomaly Scan) + 4.7 (Temporal Buffer)

Scan order (early exit):
    β3 > 0  → HIGH ALERT
    β2 > 0  → HIGH ALERT (if persistent) / MID ALERT (if transient)
    β1 anomaly → MID ALERT
    β0 change → reported but doesn't trigger alone
    all normal → CLEAN
"""

from typing import Dict, List, Tuple, Optional
from collections import deque

from app.models.schemas import (
    AlertLevel,
    BettiNumbers,
    ScanResult,
    PersistenceFeature,
)


class AnomalyDetector:
    """
    Two responsibilities:
    1. Classify a single window's Betti numbers
    2. Maintain temporal buffer and only escalate persistent anomalies
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

        # Baseline stats: {dimension: (mean, std)}
        self.baseline: Dict[int, Tuple[float, float]] = {}

        # Temporal buffer (Section 4.7)
        self.window_history: deque = deque(maxlen=360)  # ~1hr at 10s steps
        self.consecutive_h2_count: int = 0

    def set_baseline(self, stats: Dict[int, Tuple[float, float]]) -> None:
        """Set baseline Betti statistics from calibration phase."""
        self.baseline = stats

    def classify_window(self, betti: BettiNumbers) -> AlertLevel:
        """
        Single-window classification (Section 4.6).
        Top-down scan with early exit.
        """
        # H3 check — highest dimension first
        if betti.h3 > 0:
            return AlertLevel.HIGH_ALERT

        # H2 check — the primary detection signal
        if betti.h2 >= self.h2_threshold:
            return AlertLevel.MID_ALERT

        # H1 check — compare against baseline
        if 1 in self.baseline:
            mu, sigma = self.baseline[1]
            if sigma > 0 and betti.h1 > mu + self.h1_sigma * sigma:
                return AlertLevel.MID_ALERT

        return AlertLevel.CLEAN

    def process_window(
        self,
        betti: BettiNumbers,
        persistence_features: List[PersistenceFeature] = None,
    ) -> AlertLevel:
        """
        Process one window through the temporal buffer.
        Only escalates if anomaly persists for min_consecutive windows.
        """
        level = self.classify_window(betti)

        # Track consecutive H2 windows
        if betti.h2 > 0:
            self.consecutive_h2_count += 1
        else:
            self.consecutive_h2_count = 0

        # Store in history
        self.window_history.append({
            "betti": betti,
            "level": level,
            "consecutive_h2": self.consecutive_h2_count,
        })

        # Escalate MID → HIGH if persistent
        if level == AlertLevel.MID_ALERT and betti.h2 > 0:
            if self.consecutive_h2_count >= self.min_consecutive:
                return AlertLevel.HIGH_ALERT

        return level

    def get_consecutive_count(self) -> int:
        """How many consecutive windows have shown β2 > 0."""
        return self.consecutive_h2_count
