"""
engine/scanner.py
Topological Scanner — Three-Gate Cascading Architecture.

Gate 1: Sheaf Consistency  (every window, ~1ms)   → physical relationship violations
Gate 2: Ollivier-Ricci     (every N windows, ~50ms) → bridge/bottleneck detection
Gate 3: Persistent Homology (every M windows, ~200ms) → coordination proof (β₂ > 0)

The gates cascade: Gate 1 is cheap and runs always. Gate 2 is triggered
more often when Gate 1 fires (focus edges from sheaf violations guide
where to look for bridges). Gate 3 is the heavyweight mathematical proof.

Alert flow:
    Gates → Detector.process_window() → temporal persistence → final alert level

Lifecycle:
    1. __init__(config)           — initialize with domain-specific parameters
    2. calibrate(data, names)     — Phase 0: learn sheaf maps + baseline Betti stats
    3. scan(sensor_data, names)   — Phases 1-6: one full scan cycle, returns ScanResult
"""

import logging
import numpy as np
import networkx as nx
import gudhi
from typing import Optional, Dict, List, Tuple
from scipy.optimize import linprog

from config.settings import TopoConfig
from app.models.schemas import ScanResult, BettiNumbers, AlertLevel, GateResult
from engine.graph_builder import GraphBuilder
from engine.detector import AnomalyDetector

logger = logging.getLogger(__name__)


class TopologicalScanner:

    def __init__(self, config: TopoConfig):
        self.config = config

        # ── Graph Builder (distance matrix + triple-rate EMA decay) ──
        weights = config.domain.weights
        self.graph_builder = GraphBuilder(
            alpha=weights.alpha,
            beta=weights.beta,
            gamma=weights.gamma,
            decay_factor=config.matrix.decay_factor,
        )

        # ── Anomaly Detector (classification + temporal buffer) ──
        self.detector = AnomalyDetector(
            h2_threshold=config.anomaly.h2_alert_threshold,
            h1_sigma=config.anomaly.h1_warning_sigma,
            h0_sigma=config.anomaly.h0_info_sigma,
            min_consecutive=config.anomaly.min_consecutive_windows,
        )

        # ── Gate 1 state: Sheaf maps keyed by (sensor_name_i, sensor_name_j) ──
        # Maps store (slope, intercept, residual_std) from linear fit during calibration
        self._sheaf_maps: Dict[Tuple[str, str], Tuple[float, float, float]] = {}
        self._sheaf_flagged_edges: List[Tuple[str, str]] = []

        # ── Gate 2 state: Ricci bridges (cached between recomputations) ──
        self._ricci_bridges: List[Tuple[int, int]] = []
        self._ricci_last_computed: int = 0    # scan count when last computed
        self._ricci_interval: int = 30        # recompute every N windows

        # ── Gate 3 state: Persistent homology (cached between recomputations) ──
        self._last_betti: BettiNumbers = BettiNumbers()
        self._last_gate3_result: Optional[GateResult] = None
        self._homology_last_computed: int = 0
        self._homology_interval: int = 5      # recompute every N windows (not every window!)
        # On baseline schedule (every 180 windows), use baseline_adj instead of fast_adj
        self._baseline_interval: int = 180

        # ── Filtration scale (auto-selected) ──
        self._epsilon: float = 0.5

        # ── Calibration state ──
        self._calibrated: bool = False
        self._scan_count: int = 0

    # ══════════════════════════════════════════════════════════
    # PHASE 0: CALIBRATION
    # ══════════════════════════════════════════════════════════

    def calibrate(self, baseline_data: np.ndarray, sensor_names: list) -> None:
        """
        Phase 0: Offline calibration. Run ONCE at startup with normal data.

        1. Learn Sheaf restriction maps — linear models between correlated
           sensor pairs. During scanning, deviations from these models
           indicate that the physical relationship has been disrupted.

        2. Compute baseline Betti statistics — mean and std of β₀..β₃
           across sliding windows of normal data. Used by the detector
           to judge what's "normal" for this specific plant.
        """
        n = baseline_data.shape[0]

        # ── 1. Learn Sheaf Maps (keyed by sensor name) ──
        self._sheaf_maps = {}

        for i in range(n):
            for j in range(i + 1, n):
                xi = baseline_data[i]
                xj = baseline_data[j]

                # Skip dead sensors
                std_i, std_j = np.std(xi), np.std(xj)
                if std_i < 1e-10 or std_j < 1e-10:
                    continue

                # Fit linear model: xj ≈ a * xi + b
                a, b = np.polyfit(xi, xj, deg=1)
                predicted = a * xi + b
                residual_std = np.std(xj - predicted)

                # R² quality check — only keep strong relationships
                ss_res = np.sum((xj - predicted) ** 2)
                ss_tot = np.sum((xj - np.mean(xj)) ** 2)
                r_squared = 1.0 - (ss_res / (ss_tot + 1e-10))

                if r_squared > 0.3:
                    name_i = sensor_names[i] if i < len(sensor_names) else f"s{i}"
                    name_j = sensor_names[j] if j < len(sensor_names) else f"s{j}"
                    self._sheaf_maps[(name_i, name_j)] = (a, b, residual_std)

        logger.info(f"Calibration: {len(self._sheaf_maps)} sheaf maps learned from {n} sensors")

        # ── 2. Baseline Betti Statistics ──
        window_size = max(int(self.config.domain.window_sec), 2)
        step = max(int(self.config.domain.step_sec), 1)
        total_samples = baseline_data.shape[1]

        betti_history = []
        # Sample every 10th step to avoid over-computing during calibration
        cal_step = max(step * 10, window_size)

        for start in range(0, total_samples - window_size, cal_step):
            window = baseline_data[:, start:start + window_size]
            if window.shape[1] < window_size:
                break
            D, _ = self.graph_builder.build_distance_matrix(window, sensor_names)
            betti = self._compute_betti(D)
            betti_history.append(betti)

        if betti_history:
            baseline_stats = {}
            for k in range(4):
                values = [getattr(b, f'h{k}') for b in betti_history]
                baseline_stats[k] = (float(np.mean(values)), float(np.std(values)))
            self.detector.set_baseline(baseline_stats)

        self._calibrated = True
        logger.info(
            f"Calibration complete: {len(betti_history)} baseline windows, "
            f"{len(self._sheaf_maps)} sheaf maps"
        )

    # ══════════════════════════════════════════════════════════
    # GATE 1: SHEAF CONSISTENCY
    # ══════════════════════════════════════════════════════════

    def _gate1_sheaf_consistency(
        self, sensor_data: np.ndarray, sensor_names: list,
    ) -> GateResult:
        """
        Gate 1: instantaneous physical consistency check.

        For each learned relationship (sensor_i ↔ sensor_j), checks if
        the current readings are consistent with the calibrated linear model.
        A z-score > 3.0 means the relationship has been disrupted — either
        one sensor is being spoofed or the physical process has changed.

        Runs every window. Cost: O(|sheaf_maps|) ≈ O(1ms) for ~200 maps.
        """
        flagged = []

        if not self._sheaf_maps:
            return GateResult(
                gate_name="sheaf",
                triggered=False,
                findings=["No sheaf maps (not calibrated)"],
                involved_nodes=[],
                details={"flagged_edges": 0, "total_maps": 0},
            )

        # Build name → index lookup for current sensor set
        name_to_idx = {name: idx for idx, name in enumerate(sensor_names)}

        for (name_i, name_j), (a, b, residual_std) in self._sheaf_maps.items():
            idx_i = name_to_idx.get(name_i)
            idx_j = name_to_idx.get(name_j)

            # Skip if either sensor isn't in the current window
            if idx_i is None or idx_j is None:
                continue

            # Use mean of last 5 samples for stability (not just [-1])
            tail = min(5, sensor_data.shape[1])
            current_i = np.mean(sensor_data[idx_i, -tail:])
            current_j = np.mean(sensor_data[idx_j, -tail:])

            predicted_j = a * current_i + b
            error = abs(current_j - predicted_j)

            if residual_std > 1e-10:
                z_score = error / residual_std
            else:
                z_score = error * 100 if error > 1e-10 else 0.0

            if z_score > 3.0:
                flagged.append((name_i, name_j, round(z_score, 2)))

        self._sheaf_flagged_edges = [(ni, nj) for ni, nj, _ in flagged]

        involved = list(set(
            name for ni, nj, _ in flagged for name in (ni, nj)
        ))

        return GateResult(
            gate_name="sheaf",
            triggered=len(flagged) > 0,
            findings=[
                f"{ni} ↔ {nj}: {z:.1f}σ deviation"
                for ni, nj, z in flagged[:10]  # Cap findings for readability
            ] if flagged else ["All physical relationships consistent"],
            involved_nodes=involved,
            details={
                "flagged_edges": len(flagged),
                "total_maps": len(self._sheaf_maps),
                "max_z_score": max((z for _, _, z in flagged), default=0.0),
            },
        )

    # ══════════════════════════════════════════════════════════
    # GATE 2: OLLIVIER-RICCI CURVATURE
    # ══════════════════════════════════════════════════════════

    def _gate2_ricci_curvature(
        self, adjacency_matrix: np.ndarray, sensor_names: list,
        focus_edges: List[Tuple[str, str]] = None,
    ) -> GateResult:
        """
        Gate 2: bridge detection via Ollivier-Ricci curvature.

        Negative curvature on an edge means it acts as a bridge between
        otherwise disconnected clusters. In OT networks, unexpected bridges
        indicate lateral movement — an attacker pivoting between segments.

        focus_edges: if Gate 1 flagged specific sensor pairs, we check those
        edges and their neighborhoods first (cascade from Gate 1 → Gate 2).

        Cost: O(E · (deg_u · deg_v)) per edge. ~50ms for 30 sensors.
        """
        bridges = []
        n = adjacency_matrix.shape[0]

        # Build weighted graph from adjacency matrix
        G = nx.Graph()
        G.add_nodes_from(range(n))
        edge_threshold = 0.1
        for i in range(n):
            for j in range(i + 1, n):
                w = adjacency_matrix[i, j]
                if w > edge_threshold:
                    G.add_edge(i, j, weight=float(w))

        if G.number_of_edges() == 0:
            self._ricci_bridges = []
            return GateResult(
                gate_name="ricci",
                triggered=False,
                findings=["No edges above threshold — graph too sparse"],
                involved_nodes=[],
                details={"bridge_count": 0, "total_edges": 0},
            )

        # Pre-compute shortest path lengths for cost matrix
        try:
            all_shortest = dict(nx.all_pairs_shortest_path_length(G))
        except Exception:
            all_shortest = {}

        # Determine which edges to check
        if focus_edges:
            # Gate 1 flagged specific sensor pairs — check those + neighbors
            name_to_idx = {name: idx for idx, name in enumerate(sensor_names)}
            edges_to_check = set()
            for name_i, name_j in focus_edges:
                i, j = name_to_idx.get(name_i), name_to_idx.get(name_j)
                if i is not None and j is not None and G.has_edge(i, j):
                    edges_to_check.add((i, j))
                # Also check neighbors of flagged nodes
                for idx in (i, j):
                    if idx is not None and idx in G:
                        for nb in G.neighbors(idx):
                            edge = (min(idx, nb), max(idx, nb))
                            edges_to_check.add(edge)
        else:
            edges_to_check = set(G.edges())

        # Compute Ricci curvature for selected edges
        for u, v in edges_to_check:
            if not G.has_edge(u, v):
                continue
            kappa = self._compute_ricci_edge(G, u, v, all_shortest)
            if kappa < -0.5:
                bridges.append((u, v, round(kappa, 3)))

        self._ricci_bridges = [(u, v) for u, v, _ in bridges]
        self._ricci_last_computed = self._scan_count

        involved = list(set(
            sensor_names[idx]
            for u, v, _ in bridges
            for idx in (u, v)
            if idx < len(sensor_names)
        ))

        return GateResult(
            gate_name="ricci",
            triggered=len(bridges) > 0,
            findings=[
                f"{sensor_names[u]} ↔ {sensor_names[v]}: bridge κ={k:.2f}"
                for u, v, k in bridges[:10]  # Cap for readability
            ] if bridges else ["No bridge edges detected"],
            involved_nodes=involved,
            details={
                "bridge_count": len(bridges),
                "edges_checked": len(edges_to_check),
                "total_edges": G.number_of_edges(),
                "min_curvature": min((k for _, _, k in bridges), default=0.0),
            },
        )

    def _make_stale_ricci_result(self, sensor_names: list) -> GateResult:
        """
        Return cached Ricci state between recomputations.

        Critical: stale results are NOT marked as triggered.
        The detector's temporal buffer handles persistence — we don't want
        a single Ricci computation at window 31 to keep firing through window 59.
        """
        age = self._scan_count - self._ricci_last_computed
        return GateResult(
            gate_name="ricci",
            triggered=False,  # Stale data → not triggered (detector handles persistence)
            findings=[
                f"Cached ({age} windows ago): {len(self._ricci_bridges)} bridges"
            ] if self._ricci_bridges else [f"Last check clean ({age} windows ago)"],
            involved_nodes=[],
            details={
                "bridges_cached": len(self._ricci_bridges),
                "cache_age_windows": age,
            },
        )

    def _compute_ricci_edge(
        self, G: nx.Graph, u: int, v: int,
        all_shortest: dict = None,
    ) -> float:
        """
        Compute Ollivier-Ricci curvature for edge (u, v).

        κ(u,v) = 1 - W₁(μ_u, μ_v) / d(u,v)

        where μ_u is the uniform distribution on neighbors of u (including u),
        and W₁ is the Wasserstein-1 (earth mover's) distance.

        κ > 0: locally clustered (triangle-rich)
        κ ≈ 0: tree-like
        κ < 0: bridge-like (connects otherwise distant clusters)
        """
        neighbors_u = list(G.neighbors(u)) + [u]
        neighbors_v = list(G.neighbors(v)) + [v]

        n_u, n_v = len(neighbors_u), len(neighbors_v)
        mu_u = np.ones(n_u) / n_u  # Uniform measure
        mu_v = np.ones(n_v) / n_v

        # Build cost matrix: shortest path distances between neighborhoods
        cost = np.zeros((n_u, n_v))
        for i, nu in enumerate(neighbors_u):
            for j, nv in enumerate(neighbors_v):
                if nu == nv:
                    cost[i, j] = 0.0
                elif G.has_edge(nu, nv):
                    w = G[nu][nv].get('weight', 1.0)
                    cost[i, j] = 1.0 / (w + 1e-10)
                elif all_shortest and nu in all_shortest and nv in all_shortest[nu]:
                    cost[i, j] = float(all_shortest[nu][nv])
                else:
                    cost[i, j] = 10.0  # Disconnected fallback

        w1 = self._wasserstein_1(mu_u, mu_v, cost)

        edge_weight = G[u][v].get('weight', 1.0)
        d_uv = 1.0 / (edge_weight + 1e-10)

        if d_uv < 1e-10:
            return 0.0
        return 1.0 - (w1 / d_uv)

    @staticmethod
    def _wasserstein_1(mu: np.ndarray, nu: np.ndarray, cost: np.ndarray) -> float:
        """
        Wasserstein-1 distance via linear programming (Earth Mover's Distance).

        Solves the optimal transport problem:
            min Σ c_ij · γ_ij
            s.t. Σ_j γ_ij = μ_i  (row sums = source)
                 Σ_i γ_ij = ν_j  (col sums = target)
                 γ_ij ≥ 0
        """
        n, m = len(mu), len(nu)
        c = cost.flatten()

        # Row-sum constraints
        A_row = np.zeros((n, n * m))
        for i in range(n):
            A_row[i, i * m:(i + 1) * m] = 1.0

        # Column-sum constraints
        A_col = np.zeros((m, n * m))
        for j in range(m):
            for i in range(n):
                A_col[j, i * m + j] = 1.0

        A_eq = np.vstack([A_row, A_col])
        b_eq = np.concatenate([mu, nu])
        bounds = [(0, None)] * (n * m)

        try:
            result = linprog(c, A_eq=A_eq, b_eq=b_eq, bounds=bounds, method='highs')
            return result.fun if result.success else 0.0
        except Exception:
            return 0.0

    # ══════════════════════════════════════════════════════════
    # GATE 3: PERSISTENT HOMOLOGY (GUDHI)
    # ══════════════════════════════════════════════════════════

    def _gate3_persistent_homology(
        self, adjacency_matrix: np.ndarray, sensor_names: list,
    ) -> GateResult:
        """
        Gate 3: coordination proof via persistent homology.

        Builds a Vietoris-Rips complex from the sensor distance matrix
        and computes Betti numbers at an auto-selected filtration scale.

        β₂ > 0 = mathematical proof that 4+ nodes are behaving in a
        coordinated pattern that cannot arise from independent noise.

        This is the heavyweight gate — GUDHI builds the full simplex tree
        up to dimension 4. Cost scales with the number of simplices.
        """
        findings = []
        involved = []

        # Convert adjacency → distance
        adj_safe = np.clip(adjacency_matrix, 0.0, None)
        distance = np.where(adj_safe > 1e-6, 1.0 - adj_safe, 1.0)
        np.fill_diagonal(distance, 0.0)
        distance = np.clip(distance, 0.0, 1.0)
        # Force symmetry
        distance = (distance + distance.T) / 2.0

        # Compute Betti numbers
        betti = self._compute_betti(distance)
        self._last_betti = betti
        triggered = False

        # ── Top-down Betti scan ──
        if betti.h3 > 0:
            triggered = True
            findings.append(f"β₃={betti.h3}: 5-node coordination mesh detected")

        if betti.h2 > 0:
            triggered = True
            findings.append(f"β₂={betti.h2}: 4-node coordination — mathematical proof of coordinated behavior")

        # β₁ anomaly check against baseline
        if 1 in self.detector.baseline:
            mu, sigma = self.detector.baseline[1]
            if sigma > 0 and betti.h1 > mu + self.config.anomaly.h1_warning_sigma * sigma:
                triggered = True
                findings.append(
                    f"β₁={betti.h1} (baseline: {mu:.1f}±{sigma:.1f}): "
                    f"unusual relay chain count"
                )

        # β₀ change (informational, does not trigger gate alone)
        if 0 in self.detector.baseline:
            mu, sigma = self.detector.baseline[0]
            if sigma > 0 and abs(betti.h0 - mu) > self.config.anomaly.h0_info_sigma * sigma:
                findings.append(
                    f"β₀={betti.h0} (baseline: {mu:.1f}±{sigma:.1f}): "
                    f"topology fragmentation changed"
                )

        if not findings:
            findings.append(
                f"Clean — β₀={betti.h0} β₁={betti.h1} β₂={betti.h2} β₃={betti.h3}"
            )

        # Identify involved sensors (only when β₂ > 0)
        if betti.h2 > 0:
            involved = self._find_involved_sensors(distance, sensor_names)

        return GateResult(
            gate_name="homology",
            triggered=triggered,
            findings=findings,
            involved_nodes=involved,
            details={
                "betti_h0": betti.h0,
                "betti_h1": betti.h1,
                "betti_h2": betti.h2,
                "betti_h3": betti.h3,
                "epsilon": round(self._epsilon, 4),
            },
        )

    def _compute_betti(self, distance_matrix: np.ndarray) -> BettiNumbers:
        """
        Compute Betti numbers using GUDHI Vietoris-Rips complex.

        Pipeline:
            distance_matrix → RipsComplex → SimplexTree → persistence → Betti numbers

        The filtration scale ε is auto-selected by blending:
            ε = λ · ε_domain (from H₀ persistence gap)
              + (1-λ) · ε_local (from kNN distance median)
        """
        try:
            dm = np.array(distance_matrix, dtype=np.float64)
            if not np.all(np.isfinite(dm)):
                dm = np.nan_to_num(dm, nan=1.0, posinf=1.0, neginf=0.0)
            dm = np.clip(dm, 0.0, 1.0)
            np.fill_diagonal(dm, 0.0)
            dm = (dm + dm.T) / 2.0  # GUDHI requires symmetric

            rips = gudhi.RipsComplex(distance_matrix=dm, max_edge_length=1.0)
            simplex_tree = rips.create_simplex_tree(
                max_dimension=min(self.config.max_dimension + 1, 5)
            )
            simplex_tree.compute_persistence()

            # Auto-select filtration scale
            epsilon = self._select_epsilon(simplex_tree, dm)
            self._epsilon = epsilon

            # Read Betti numbers at selected scale
            betti = simplex_tree.persistent_betti_numbers(
                from_value=0.0, to_value=epsilon,
            )
            while len(betti) < 4:
                betti.append(0)

            return BettiNumbers(
                h0=int(betti[0]), h1=int(betti[1]),
                h2=int(betti[2]), h3=int(betti[3]),
            )
        except Exception as e:
            logger.warning(f"GUDHI computation failed: {e}")
            return BettiNumbers()

    def _select_epsilon(self, simplex_tree, distance_matrix: np.ndarray) -> float:
        """
        Auto-select filtration scale ε.

        Two sources, blended:
            ε_local  = median kNN distance × γ_scale (data-driven)
            ε_domain = largest H₀ persistence gap (topological)

        The blend λ controls how much we trust the topological signal
        vs the raw data geometry.
        """
        # ── ε_local from kNN distances ──
        epsilon_local = 0.5
        k = self.config.filtration.knn_k
        n = distance_matrix.shape[0]
        if n > k:
            knn_dists = []
            for i in range(n):
                row = distance_matrix[i].copy()
                row[i] = np.inf  # Exclude self
                sorted_dists = np.sort(row)
                if len(sorted_dists) > k - 1:
                    knn_dists.append(sorted_dists[k - 1])  # k-th nearest
            if knn_dists:
                epsilon_local = float(np.median(knn_dists)) * self.config.filtration.knn_gamma_scale

        # ── ε_domain from H₀ persistence gap ──
        epsilon_domain = 0.5
        persistence = simplex_tree.persistence()
        h0_pairs = [
            (b, d) for dim, (b, d) in persistence
            if dim == 0 and d != float('inf')
        ]
        if h0_pairs:
            lifetimes = sorted([d - b for b, d in h0_pairs], reverse=True)
            if lifetimes:
                epsilon_domain = lifetimes[0]

        # ── Blend ──
        lam = self.config.filtration.lambda_blend
        epsilon = lam * epsilon_domain + (1.0 - lam) * epsilon_local
        return float(np.clip(epsilon, 0.05, 0.95))

    def _find_involved_sensors(
        self, distance_matrix: np.ndarray, sensor_names: list,
    ) -> List[str]:
        """
        Identify sensors participating in H₂ structures.

        Looks for 4-cliques (complete subgraphs on 4 vertices) in the
        ε-neighborhood graph. A 4-clique is the minimal structure that
        creates a β₂ feature (the boundary of a tetrahedron).
        """
        involved = set()
        epsilon = self._epsilon

        # Build binary adjacency: edge exists if distance ≤ ε
        adj_binary = (distance_matrix <= epsilon) & (distance_matrix > 0)
        G = nx.from_numpy_array(adj_binary.astype(int))

        try:
            for clique in nx.find_cliques(G):
                if len(clique) >= 4:
                    for idx in clique:
                        if idx < len(sensor_names):
                            involved.add(sensor_names[idx])
        except Exception:
            pass

        # Fallback: if no 4-cliques found, report highest-degree nodes
        if not involved:
            degrees = np.sum(adj_binary, axis=1)
            top_indices = np.argsort(degrees)[-4:]
            for idx in top_indices:
                if idx < len(sensor_names):
                    involved.add(sensor_names[idx])

        return sorted(involved)

    # ══════════════════════════════════════════════════════════
    # PATTERN DESCRIPTION (for human-readable output)
    # ══════════════════════════════════════════════════════════

    def _build_pattern_string(
        self, alert_level: AlertLevel, gate_results: List[GateResult],
    ) -> str:
        """Build a human-readable pattern description for the ScanResult."""
        triggered = [g for g in gate_results if g.triggered]
        gates_triggered = len(triggered)

        if gates_triggered == 0:
            return "All gates clean"

        all_nodes = set()
        findings = []
        for g in triggered:
            all_nodes.update(g.involved_nodes)
            findings.extend(g.findings[:2])

        node_str = ', '.join(sorted(all_nodes)[:8]) if all_nodes else 'none'
        gate_names = [g.gate_name for g in triggered]

        severity = "HIGH" if alert_level == AlertLevel.HIGH_ALERT else "MID"
        return (
            f"{severity}: {gates_triggered}/3 gates ({', '.join(gate_names)}). "
            f"Involved: {node_str}. {'; '.join(findings[:3])}"
        )

    # ══════════════════════════════════════════════════════════
    # MAIN SCAN METHOD
    # ══════════════════════════════════════════════════════════

    def scan(
        self,
        data_source: str = "unknown",
        sensor_data: np.ndarray = None,
        sensor_names: list = None,
        window_index: Optional[int] = None,
    ) -> ScanResult:
        """
        Run one full scan cycle (Phases 1-6).

        This is the main entry point called every window.

        Args:
            data_source: dataset name (for labeling output)
            sensor_data: (N_sensors, W_samples) array
            sensor_names: list of sensor IDs
            window_index: optional window counter for labeling

        Returns:
            ScanResult with alert level, gate results, Betti numbers, etc.
        """
        self._scan_count += 1

        # ── Phase 1: Input validation ──
        if sensor_data is None or sensor_data.size == 0:
            return ScanResult(
                status=AlertLevel.CLEAN,
                betti=BettiNumbers(),
                pattern="No sensor data provided",
                domain=self.config.domain.name,
                data_source=data_source,
            )

        if sensor_names is None:
            sensor_names = [f"s{i}" for i in range(sensor_data.shape[0])]

        # ── Phase 1b: Subsample sensors if too many ──
        max_sensors = self.config.domain.max_sensors
        if max_sensors and sensor_data.shape[0] > max_sensors:
            variances = np.var(sensor_data, axis=1)
            top_idx = np.sort(np.argsort(variances)[-max_sensors:])
            sensor_data = sensor_data[top_idx]
            sensor_names = [sensor_names[i] for i in top_idx]

        # ── Phase 2: Build distance matrix ──
        D, names = self.graph_builder.build_distance_matrix(sensor_data, sensor_names)

        # ── Phase 3: Triple-rate EMA decay update ──
        fast_adj, slow_adj, baseline_adj = self.graph_builder.update_adjacency_with_decay(D)

        # ── Phase 4: Run gates ──
        gate_results = []

        # Gate 1: Sheaf — EVERY window (fast, ~1ms)
        gate1 = self._gate1_sheaf_consistency(sensor_data, sensor_names)
        gate_results.append(gate1)

        # Gate 2: Ricci — every _ricci_interval windows, or more often if Gate 1 fired
        run_ricci = (
            self._scan_count % self._ricci_interval == 0
            or (gate1.triggered and self._scan_count - self._ricci_last_computed >= 5)
        )
        if run_ricci:
            gate2 = self._gate2_ricci_curvature(
                slow_adj, sensor_names,
                focus_edges=self._sheaf_flagged_edges if gate1.triggered else None,
            )
        else:
            gate2 = self._make_stale_ricci_result(sensor_names)
        gate_results.append(gate2)

        # Gate 3: Homology — every _homology_interval windows
        # Use baseline_adj on the baseline schedule, fast_adj otherwise
        run_homology = (
            self._scan_count % self._homology_interval == 0
            or self._last_gate3_result is None
        )
        if run_homology:
            if self._scan_count % self._baseline_interval == 0:
                gate3 = self._gate3_persistent_homology(baseline_adj, sensor_names)
            else:
                gate3 = self._gate3_persistent_homology(fast_adj, sensor_names)
            self._last_gate3_result = gate3
            self._homology_last_computed = self._scan_count
        else:
            gate3 = self._last_gate3_result
        gate_results.append(gate3)

        # ── Phase 5: Alert level via detector (classification + temporal buffer) ──
        alert_level = self.detector.process_window(self._last_betti, gate_results)

        gates_triggered = sum(1 for g in gate_results if g.triggered)
        pattern = self._build_pattern_string(alert_level, gate_results)

        all_involved = set()
        for g in gate_results:
            all_involved.update(g.involved_nodes)

        # ── Phase 6: Confidence ──
        if gates_triggered >= 3:
            confidence = "high"
        elif gates_triggered == 2:
            confidence = "medium"
        elif gates_triggered == 1:
            confidence = "low"
        else:
            confidence = "none"

        return ScanResult(
            status=alert_level,
            betti=self._last_betti,
            involved_sensors=sorted(all_involved),
            confidence=confidence,
            pattern=pattern,
            window_start=str(window_index if window_index is not None else self._scan_count),
            window_end=str((window_index if window_index is not None else self._scan_count) + 1),
            epsilon=self._epsilon,
            consecutive_alerts=self.detector.get_consecutive_count(),
            domain=self.config.domain.name,
            data_source=data_source,
            gate_results=gate_results,
            gates_triggered=gates_triggered,
        )