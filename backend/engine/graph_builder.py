"""
engine/graph_builder.py
Sensor readings → distance matrix → triple-layer adjacency.

Three distance metrics, blended by domain-specific weights:
    alpha · D_pearson  +  beta · D_dtw  +  gamma · D_granger

Performance targets (30 sensors, 60-sample window):
    Pearson:  <1ms   (fully vectorized)
    DTW:      ~50ms  (C backend batch)
    Granger:  ~200ms (only every Nth window, cached)
    Total:    ~60ms per window (without Granger)
"""

import logging
import numpy as np
from typing import Tuple, Optional, Dict

logger = logging.getLogger(__name__)


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
        total = alpha + beta + gamma
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"Weights must sum to 1.0, got {total:.4f}")

        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma
        self.dtw_tau_max = dtw_tau_max
        self.granger_max_lag = granger_max_lag

        # Triple-layer decay rates
        # half-life = -ln(2) / ln(decay) * step_sec
        self.decay_fast = decay_factor       # ~2 min half-life at 10s steps
        self.decay_slow = 0.997              # ~38 min half-life
        self.decay_baseline = 0.99998        # ~8 hr half-life

        # EMA adjacency matrices (None until first window)
        self._adjacency_fast: Optional[np.ndarray] = None
        self._adjacency_slow: Optional[np.ndarray] = None
        self._adjacency_baseline: Optional[np.ndarray] = None
        self._current_n_sensors: int = 0     # track for shape-change detection

        # Window counter for scheduling expensive operations
        self._window_count: int = 0
        self._slow_interval: int = 30        # Granger every 30 windows
        self._baseline_interval: int = 180   # Baseline decay check every 180

        # Granger cache (expensive — reuse across windows)
        self._granger_cache: Optional[np.ndarray] = None
        self._granger_cache_age: int = 0     # windows since last Granger compute

    # ══════════════════════════════════════════════════════════
    # PUBLIC API
    # ══════════════════════════════════════════════════════════

    def build_distance_matrix(
        self,
        sensor_data: np.ndarray,
        sensor_names: list,
    ) -> Tuple[np.ndarray, list]:
        """
        Build NxN distance matrix from sensor window.

        Args:
            sensor_data: (N_sensors, W_samples) array
            sensor_names: list of sensor IDs

        Returns:
            (D, sensor_names) where D is NxN distance in [0, 1]
        """
        self._window_count += 1
        n = sensor_data.shape[0]

        # ── Layer 1: Pearson correlation distance (every window) ──
        D_pearson = self._pearson_matrix(sensor_data)

        # ── Layer 2: DTW distance (every window, C-optimized) ──
        D_dtw = self._dtw_matrix(sensor_data)

        # ── Layer 3: Granger causality (expensive, periodic + cached) ──
        include_granger = (
            self.gamma > 0.01
            and self._window_count % self._slow_interval == 0
            and n <= 40
            and sensor_data.shape[1] >= 3 * self.granger_max_lag + 1
        )

        if include_granger:
            D_granger = self._granger_matrix(sensor_data)
            self._granger_cache = D_granger
            self._granger_cache_age = 0
            D = self.alpha * D_pearson + self.beta * D_dtw + self.gamma * D_granger

        elif self._granger_cache is not None and self._granger_cache.shape[0] == n:
            # Reuse cached Granger from previous computation
            self._granger_cache_age += 1
            D = self.alpha * D_pearson + self.beta * D_dtw + self.gamma * self._granger_cache

        else:
            # No Granger available — redistribute weight proportionally
            ab_sum = self.alpha + self.beta
            if ab_sum > 1e-10:
                a = self.alpha / ab_sum
                b = self.beta / ab_sum
            else:
                a = b = 0.5
            D = a * D_pearson + b * D_dtw

        # ── Sanitize output ──
        D = np.nan_to_num(D, nan=1.0, posinf=1.0, neginf=0.0)
        D = np.clip(D, 0.0, 1.0)
        np.fill_diagonal(D, 0.0)
        # Force symmetry (floating point can break it slightly)
        D = (D + D.T) / 2.0

        return D, sensor_names

    def update_adjacency_with_decay(
        self,
        distance_matrix: np.ndarray,
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Triple-rate EMA decay update.
            A(t) = λ · A(t-1) + (1-λ) · A_new

        Three timescales capture different attack patterns:
            fast     (~2 min)  : detects sudden short-lived anomalies
            slow     (~38 min) : detects persistent slow attacks
            baseline (~8 hr)   : long-term structural reference

        Handles sensor count changes by resetting EMA state.
        """
        n = distance_matrix.shape[0]
        new_adj = 1.0 - np.clip(distance_matrix, 0.0, 1.0)
        np.fill_diagonal(new_adj, 0.0)

        # Detect shape change → reset all EMA layers
        if n != self._current_n_sensors:
            if self._current_n_sensors > 0:
                logger.info(
                    f"Sensor count changed {self._current_n_sensors} → {n}, "
                    f"resetting EMA adjacency matrices"
                )
            self._adjacency_fast = None
            self._adjacency_slow = None
            self._adjacency_baseline = None
            self._granger_cache = None
            self._current_n_sensors = n

        # Update each layer
        for attr, decay in [
            ('_adjacency_fast', self.decay_fast),
            ('_adjacency_slow', self.decay_slow),
            ('_adjacency_baseline', self.decay_baseline),
        ]:
            prev = getattr(self, attr)
            if prev is None:
                setattr(self, attr, new_adj.copy())
            else:
                updated = decay * prev + (1.0 - decay) * new_adj
                setattr(self, attr, updated)

        return (
            self._adjacency_fast.copy(),
            self._adjacency_slow.copy(),
            self._adjacency_baseline.copy(),
        )

    # ══════════════════════════════════════════════════════════
    # LAYER 1: PEARSON CORRELATION DISTANCE
    # ══════════════════════════════════════════════════════════

    def _pearson_matrix(self, data: np.ndarray) -> np.ndarray:
        """
        Vectorized Pearson correlation distance.

        Distance = 1 - |corr(i, j)|

        Uses matrix multiplication for the correlation computation:
            corr = (X_centered @ X_centered.T) / W

        Complexity: O(N² · W) for the matmul, no Python loops.
        """
        n, w = data.shape
        D = np.ones((n, n))

        if w < 2:
            np.fill_diagonal(D, 0.0)
            return D

        stds = np.std(data, axis=1)
        active_mask = stds > 1e-10
        active_idx = np.where(active_mask)[0]

        if len(active_idx) < 2:
            np.fill_diagonal(D, 0.0)
            return D

        # Z-normalize active sensors: (x - mean) / std
        active_data = data[active_idx]
        means = active_data.mean(axis=1, keepdims=True)
        active_stds = stds[active_idx, np.newaxis] + 1e-10
        normed = (active_data - means) / active_stds

        # Correlation via dot product: shape (n_active, n_active)
        corr = normed @ normed.T / w
        np.clip(corr, -1.0, 1.0, out=corr)

        # Distance = 1 - |correlation| — fully vectorized fill
        dist_block = 1.0 - np.abs(corr)
        np.fill_diagonal(dist_block, 0.0)

        # Place back into full NxN matrix
        D[np.ix_(active_idx, active_idx)] = dist_block

        np.fill_diagonal(D, 0.0)
        return D

    # ══════════════════════════════════════════════════════════
    # LAYER 2: DTW DISTANCE
    # ══════════════════════════════════════════════════════════

    def _dtw_matrix(self, data: np.ndarray) -> np.ndarray:
        """
        DTW distance matrix.

        Strategy:
            1. Try dtaidistance batch C backend (fastest)
            2. Fall back to pairwise C calls (still fast)
            3. Skip dead sensors (std ≈ 0)

        DTW distances are normalized to [0, 1] by dividing by max
        possible DTW distance (W * max_amplitude_diff).
        """
        from dtaidistance import dtw

        n, w = data.shape
        D = np.ones((n, n))

        if w < 2:
            np.fill_diagonal(D, 0.0)
            return D

        stds = np.std(data, axis=1)
        active_mask = stds > 1e-10
        active_idx = np.where(active_mask)[0]

        if len(active_idx) < 2:
            np.fill_diagonal(D, 0.0)
            return D

        # Z-normalize active sensors
        active_data = data[active_idx].copy()
        active_means = active_data.mean(axis=1, keepdims=True)
        active_stds = stds[active_idx, np.newaxis] + 1e-10
        normed = (active_data - active_means) / active_stds

        # Normalization factor for DTW distances
        # After z-norm, values are roughly in [-3, 3], so max single-step
        # cost is ~6, and max DTW path length is ~2W (Sakoe-Chiba band)
        max_dtw = w * 2.0

        # ── Try batch computation first (C backend, much faster) ──
        batch_success = False
        try:
            # dtaidistance expects list of 1D arrays (float64)
            series_list = [normed[i].astype(np.float64) for i in range(len(active_idx))]
            dm = dtw.distance_matrix_fast(
                series_list,
                window=self.dtw_tau_max,
                use_pruning=True,
            )
            # dm is a condensed or full matrix depending on version
            dm = np.array(dm, dtype=np.float64)

            # Normalize to [0, 1]
            dm_normed = np.clip(dm / max_dtw, 0.0, 1.0)
            np.fill_diagonal(dm_normed, 0.0)

            # Fill into full D matrix
            D[np.ix_(active_idx, active_idx)] = dm_normed
            batch_success = True
        except Exception:
            # Batch failed — fall through to pairwise
            pass

        # ── Fallback: pairwise C calls ──
        if not batch_success:
            for ii, i in enumerate(active_idx):
                for jj in range(ii + 1, len(active_idx)):
                    j = active_idx[jj]
                    try:
                        raw = dtw.distance(
                            normed[ii].astype(np.float64),
                            normed[jj].astype(np.float64),
                            window=self.dtw_tau_max,
                            use_pruning=True,
                        )
                        d = min(raw / max_dtw, 1.0)
                    except Exception:
                        d = 1.0
                    D[i, j] = d
                    D[j, i] = d

        np.fill_diagonal(D, 0.0)
        return D

    # ══════════════════════════════════════════════════════════
    # LAYER 3: GRANGER CAUSALITY DISTANCE
    # ══════════════════════════════════════════════════════════

    def _granger_matrix(self, data: np.ndarray) -> np.ndarray:
        """
        Granger causality distance.

        For each pair (i, j), tests if i Granger-causes j and vice versa.
        Distance = min(p_value_xy, p_value_yx), so low p = strong
        causal link = small distance.

        This is O(N² · L · W) where L = max_lag. Expensive.
        Only called every _slow_interval windows and results are cached.
        """
        from statsmodels.tsa.stattools import grangercausalitytests
        import warnings

        n = data.shape[0]
        D = np.ones((n, n))
        min_samples = 3 * self.granger_max_lag + 1

        if data.shape[1] < min_samples:
            np.fill_diagonal(D, 0.0)
            return D

        stds = np.std(data, axis=1)

        for i in range(n):
            if stds[i] < 1e-10:
                continue
            for j in range(i + 1, n):
                if stds[j] < 1e-10:
                    continue
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")

                        # Test i → j
                        xy = np.column_stack([data[j], data[i]])
                        r1 = grangercausalitytests(
                            xy, maxlag=self.granger_max_lag, verbose=False
                        )
                        p1 = min(
                            r1[lag][0]['ssr_ftest'][1]
                            for lag in r1
                        )

                        # Test j → i
                        yx = np.column_stack([data[i], data[j]])
                        r2 = grangercausalitytests(
                            yx, maxlag=self.granger_max_lag, verbose=False
                        )
                        p2 = min(
                            r2[lag][0]['ssr_ftest'][1]
                            for lag in r2
                        )

                        d = float(np.clip(min(p1, p2), 0.0, 1.0))
                except Exception:
                    d = 1.0

                D[i, j] = d
                D[j, i] = d

        np.fill_diagonal(D, 0.0)
        return D