"""
app/engine/graph_builder.py
Sensor readings → NetworkX weighted graph with composite distance.

Reference: Paper Section 3 (Distance Metric Design) + Section 4.2-4.3

Pipeline:
    raw sensor data → sliding window → pairwise distance matrix → weighted graph
    
Distance components:
    d(si,sj) = α·dP(Pearson) + β·dDTW(Dynamic Time Warping) + γ·dG(Granger)
"""

import numpy as np
from typing import Tuple, Optional
from scipy.stats import pearsonr
from dtaidistance import dtw
from statsmodels.tsa.stattools import grangercausalitytests
"""
Builds the distance matrix D(t) for each time window.

For N sensors and window size W:
    Input:  (N, W) array of sensor readings
    Output: (N, N) symmetric distance matrix

OT scale: N ≤ 86 (HAI), so full pairwise is trivial.
"""

class GraphBuilder:

    def __init__(
        self,
        alpha: float = 0.2,
        beta: float = 0.6,
        gamma: float = 0.2,
        decay_factor: float = 0.95,
        dtw_tau_max: int = 10,
        granger_max_lag: int = 5,
    ):
        # Weights must sum to 1
        assert abs(alpha + beta + gamma - 1.0) < 1e-6, \
            f"Weights must sum to 1.0, got {alpha + beta + gamma}"

        self.alpha = alpha    # Pearson weight (instantaneous linear)
        self.beta = beta      # DTW weight (lagged coupling)
        self.gamma = gamma    # Granger weight (causal)
        self.decay_factor = decay_factor  # Matrix decay λ ∈ [0.9, 0.99]

        # DTW: maximum time warp allowed (samples)
        self.dtw_tau_max = dtw_tau_max

        # Granger: maximum lag to test (samples)
        self.granger_max_lag = granger_max_lag

        # Cache for DTW normalization
        self._dtw_max: float = 1.0

            # ── Three scan tiers ──
        # Fast: real-time (every window, Pearson+DTW only)
        self.decay_fast = decay_factor              # 0.95, half-life ~2 min
        
        # Slow: tactical (every 5 min, full metrics)
        self.decay_slow = 0.997                     # half-life ~38 min
        
        # Baseline: strategic (every 30 min, full recalc)
        self.decay_baseline = 0.99998               # half-life ~8 hours

        self._adjacency_fast: Optional[np.ndarray] = None
        self._adjacency_slow: Optional[np.ndarray] = None
        self._adjacency_baseline: Optional[np.ndarray] = None
        
        # Window counter — tracks when to run slow/baseline scans
        self._window_count: int = 0
        self._slow_interval: int = 30     # every 30 windows = 5 min
        self._baseline_interval: int = 180 # every 180 windows = 30 min

    def build_distance_matrix(
        self,
        sensor_data: np.ndarray,
        sensor_names: list,
    ) -> Tuple[np.ndarray, list]:
        """
    Build composite distance matrix for one time window.
    
    d(si,sj) = α·dP + β·dDTW + γ·dG
    
    Args:
        sensor_data: (N_sensors, W_samples) array
                     Each row is one sensor's time series for this window
        sensor_names: list of sensor IDs, length N_sensors
    
    Returns:
        (D, sensor_names) where D is NxN symmetric distance matrix
    
    Complexity: O(N² · W) — for N=51, W=60: ~milliseconds
        """
        n = sensor_data.shape[0]
        D = np.zeros((n, n))
        
        self._window_count += 1
        
        # Determine which metrics to compute this window
        include_granger = (
            self._window_count % self._slow_interval == 0
        )

        for i in range(n):
            for j in range(i + 1, n):
                xi = sensor_data[i]
                xj = sensor_data[j]

                # Always: Pearson + DTW
                dp = self.pearson_distance(xi, xj)
                dd = self.dtw_distance(xi, xj)

                if include_granger:
                    # Every 5 min: add Granger
                    dg = self.granger_distance(xi, xj)
                    d = self.alpha * dp + self.beta * dd + self.gamma * dg
                else:
                    # Real-time: redistribute gamma weight to alpha+beta
                    # Keeps total = 1.0
                    a = self.alpha + self.gamma * (self.alpha / (self.alpha + self.beta))
                    b = self.beta + self.gamma * (self.beta / (self.alpha + self.beta))
                    d = a * dp + b * dd

                D[i][j] = d
                D[j][i] = d

        return D, sensor_names

    def pearson_distance(self, x: np.ndarray, y: np.ndarray) -> float:
        """
    dP(si,sj) = 1 - |ρ(xi,xj)|
    
    Pearson correlation distance.
    Captures instantaneous linear coupling between sensors.
    
    Args:
        x: time series of sensor i, shape (W,)
        y: time series of sensor j, shape (W,)
    
    Returns:
        distance in [0, 1]
        0 = perfectly correlated (positive or negative)
        1 = no linear correlation
        """
        # Edge case: constant signal (no variance)
        # A sensor stuck at one value has zero std → Pearson undefined
        # We return max distance — no information to correlate
        if np.std(x) < 1e-10 or np.std(y) < 1e-10:
            return 1.0

        # scipy.stats.pearsonr returns (correlation, p-value)
        rho, _ = pearsonr(x, y)

        # Handle NaN (can happen with degenerate data)
        if np.isnan(rho):
            return 1.0

        return 1.0 - abs(rho)

    def dtw_distance(self, x: np.ndarray, y: np.ndarray) -> float:
        """
    dDTW(si,sj) = DTW(xi, xj; τmax) / DTWmax
    
    Dynamic Time Warping distance.
    Captures lagged coupling: sensor j follows sensor i
    with a time delay (e.g., valve opens → tank fills later).
    
    Args:
        x: time series of sensor i, shape (W,)
        y: time series of sensor j, shape (W,)
    
    Returns:
        distance in [0, 1] after normalization
        0 = identical (possibly time-shifted) signals
        1 = maximally different signals
        """
        # Edge case: constant signals
        if np.std(x) < 1e-10 and np.std(y) < 1e-10:
            return 0.0  # Two flat lines = identical
        if np.std(x) < 1e-10 or np.std(y) < 1e-10:
            return 1.0  # One flat, one moving = max distance

        # Z-normalize both series before DTW
        # This makes DTW scale-invariant:
        # a sensor reading in liters vs bars doesn't matter
        x_norm = (x - np.mean(x)) / (np.std(x) + 1e-10)
        y_norm = (y - np.mean(y)) / (np.std(y) + 1e-10)

        # Compute DTW with Sakoe-Chiba band (limits maximum warp)
        # window=tau_max means: alignment can shift at most tau_max samples
        raw_dtw = dtw.distance(
            x_norm.astype(np.double),
            y_norm.astype(np.double),
            window=self.dtw_tau_max,
            use_pruning=True,  # Speed optimization for long series
        )

        # Update running max for normalization
        if raw_dtw > self._dtw_max:
            self._dtw_max = raw_dtw

        # Normalize to [0, 1]
        if self._dtw_max < 1e-10:
            return 0.0

        return min(raw_dtw / self._dtw_max, 1.0)

    def granger_distance(self, x: np.ndarray, y: np.ndarray) -> float:
        """
        dG(si,sj) = min p-value of Granger causality in both directions.
        
        Captures causal relationships:
        Does knowing sensor j's past help predict sensor i's future?
        
        We test both directions (i→j and j→i) and take the minimum
        p-value, because causality can flow either way.
        
        Args:
            x: time series of sensor i, shape (W,)
            y: time series of sensor j, shape (W,)
        
        Returns:
            distance in [0, 1]
            0 = strong causal relationship (either direction)
            1 = no causal relationship
        """
        # Edge case: constant signals — Granger needs variance
        if np.std(x) < 1e-10 or np.std(y) < 1e-10:
            return 1.0

        # Edge case: window too short for the requested lag
        min_samples = 3 * self.granger_max_lag + 1
        if len(x) < min_samples:
            return 1.0  # Not enough data to test causality

        # Stack into (W, 2) matrix — statsmodels format
        # Column 0 = effect, Column 1 = cause
        try:
            # Test direction 1: does y Granger-cause x?
            data_xy = np.column_stack([x, y])
            result_xy = grangercausalitytests(
                data_xy,
                maxlag=self.granger_max_lag,
                verbose=False,
            )
            # Extract minimum p-value across all tested lags
            # result is dict: {lag: (test_results, ols_results)}
            # test_results[0] is ssr_ftest: (F-stat, p-value, df_denom, df_num)
            p_xy = min(
                result_xy[lag][0]['ssr_ftest'][1]
                for lag in result_xy
            )

            # Test direction 2: does x Granger-cause y?
            data_yx = np.column_stack([y, x])
            result_yx = grangercausalitytests(
                data_yx,
                maxlag=self.granger_max_lag,
                verbose=False,
            )
            p_yx = min(
                result_yx[lag][0]['ssr_ftest'][1]
                for lag in result_yx
            )

            # Take minimum: if causality exists in EITHER direction,
            # these sensors are "close"
            p_min = min(p_xy, p_yx)

            # Clamp to [0, 1]
            return float(np.clip(p_min, 0.0, 1.0))

        except Exception:
            # Granger can fail on degenerate data (singular matrix, etc.)
            # Return max distance — no information
            return 1.0

    def update_adjacency_with_decay(
        self,
        distance_matrix: np.ndarray,
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Triple-rate decay update.
        
        A(t) = λ · A(t-δ) + ΔA(t)
        
        Three layers, each with different memory:
        
        Fast (λ=0.95):
            Half-life ~2 min (14 windows)
            Purpose: real-time burst detection
            Catches: port scans, brute force, rapid lateral movement
        
        Slow (λ=0.997):
            Half-life ~38 min (230 windows)
            Purpose: tactical pattern accumulation
            Catches: slow probes every 15 min, cautious lateral movement
        
        Baseline (λ=0.99998):
            Half-life ~8 hours (34,657 windows)
            Purpose: strategic long-term profile
            Catches: state-actor APT, 1 probe per 30 min over days
            Also serves as "normal" reference for anomaly detection
        
        All three update every window (cost: 3 matrix multiplies ≈ 0.03ms).
        GUDHI runs on each at different frequencies (see scanner.py).
        
        Reference: Paper Section 11.3 + Section 4.7
        
        Args:
            distance_matrix: NxN distance matrix from current window
        
        Returns:
            (fast, slow, baseline) — three NxN adjacency matrices
        """
        # Convert distance → adjacency (proximity)
        # d=0 (close) → a=1 (strong connection)
        # d=1 (far)   → a=0 (no connection)
        new_adjacency = 1.0 - np.clip(distance_matrix, 0.0, 1.0)

        # Zero out diagonal — no self-connections
        np.fill_diagonal(new_adjacency, 0.0)

        # ── Fast layer: aggressive decay, real-time ──
        # Half-life ~2 min → burst detection
        if self._adjacency_fast is None:
            self._adjacency_fast = new_adjacency.copy()
        else:
            self._adjacency_fast = (
                self.decay_fast * self._adjacency_fast + new_adjacency
            )

        # ── Slow layer: gentle decay, tactical ──
        # Half-life ~38 min → slow attacker accumulation
        if self._adjacency_slow is None:
            self._adjacency_slow = new_adjacency.copy()
        else:
            self._adjacency_slow = (
                self.decay_slow * self._adjacency_slow + new_adjacency
            )

        # ── Baseline layer: near-permanent, strategic ──
        # Half-life ~8 hours → state actor / daily pattern
        if self._adjacency_baseline is None:
            self._adjacency_baseline = new_adjacency.copy()
        else:
            self._adjacency_baseline = (
                self.decay_baseline * self._adjacency_baseline + new_adjacency
            )

        return (
            self._adjacency_fast.copy(),
            self._adjacency_slow.copy(),
            self._adjacency_baseline.copy(),
        )
