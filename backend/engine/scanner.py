"""
app/engine/scanner.py
Topological Scanner — Three-Gate Cascading Architecture.

Gate 1: Sheaf Laplacian    (fast layer,     every 10s)  → protocol consistency
Gate 2: Ollivier-Ricci     (slow layer,     every 5min) → bridge detection
Gate 3: Persistent Homology (baseline layer, every 30min) → coordination proof

Alert logic:
    3 gates triggered → HIGH ALERT
    1-2 gates triggered → MID ALERT
    0 gates triggered → CLEAN

Reference: Paper Sections 4, 5, 11.4
"""

import numpy as np
import networkx as nx
import gudhi
from typing import Optional, Dict, List, Tuple
from scipy.optimize import linprog

from config.settings import TopoConfig
from app.models.schemas import ScanResult, BettiNumbers, AlertLevel, GateResult
from engine.graph_builder import GraphBuilder
from engine.detector import AnomalyDetector


class TopologicalScanner:
    """
    Main scanner class — orchestrates the three gates.

    Lifecycle:
        1. __init__(config)   — loads domain weights, thresholds
        2. calibrate(data)    — Phase 0: learn sheaf maps + baseline betti
        3. scan(sensor_data)  — Phases 1-6: one full scan cycle
    """

    def __init__(self, config: TopoConfig):
        self.config = config

        # ── Graph Builder (distance matrix + triple decay) ──
        weights = config.domain.weights
        self.graph_builder = GraphBuilder(
            alpha=weights.alpha,
            beta=weights.beta,
            gamma=weights.gamma,
            decay_factor=config.matrix.decay_factor,
        )

        # ── Anomaly Detector (temporal buffer) ──
        self.detector = AnomalyDetector(
            h2_threshold=config.anomaly.h2_alert_threshold,
            h1_sigma=config.anomaly.h1_warning_sigma,
            h0_sigma=config.anomaly.h0_info_sigma,
            min_consecutive=config.anomaly.min_consecutive_windows,
        )

        # ── Gate states ──
        self._sheaf_flagged_edges: List[Tuple[int, int]] = []
        self._ricci_bridges: List[Tuple[int, int]] = []
        self._last_betti: BettiNumbers = BettiNumbers()

        # ── Sheaf maps (learned in calibration) ──
        self._sheaf_maps: Dict[Tuple[int, int], Tuple[float, float, float]] = {}

        # ── Filtration scale ──
        self._epsilon: float = 0.5
        self._calibrated: bool = False

        # ── Scan counter ──
        self._scan_count: int = 0

    # ══════════════════════════════════════════════════════════
    # PHASE 0: CALIBRATION
    # ══════════════════════════════════════════════════════════

    def calibrate(self, baseline_data: np.ndarray, sensor_names: list) -> None:
        """
        Phase 0: Offline calibration. Run ONCE at startup.

        1. Learn Sheaf restriction maps (physical relationships)
        2. Compute baseline Betti statistics
        """
        n = baseline_data.shape[0]

        # ── 1. Learn Sheaf Maps ──
        self._sheaf_maps = {}
        for i in range(n):
            for j in range(i + 1, n):
                xi = baseline_data[i]
                xj = baseline_data[j]

                if np.std(xi) < 1e-10 or np.std(xj) < 1e-10:
                    continue

                a, b = np.polyfit(xi, xj, deg=1)
                predicted = a * xi + b
                residual_std = np.std(xj - predicted)

                ss_res = np.sum((xj - predicted) ** 2)
                ss_tot = np.sum((xj - np.mean(xj)) ** 2)
                r_squared = 1.0 - (ss_res / (ss_tot + 1e-10))

                if r_squared > 0.3:
                    self._sheaf_maps[(i, j)] = (a, b, residual_std)

        # ── 2. Baseline Betti Statistics ──
        window_size = int(self.config.domain.window_sec)
        step = int(self.config.domain.step_sec)
        total_samples = baseline_data.shape[1]

        betti_history = []
        for start in range(0, total_samples - window_size, step * 10):
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

    # ══════════════════════════════════════════════════════════
    # GATE 1: SHEAF LAPLACIAN (Data-Driven)
    # ══════════════════════════════════════════════════════════

    def _gate1_sheaf_consistency(
        self, sensor_data: np.ndarray, sensor_names: list,
    ) -> GateResult:
        """
        Gate 1: checks instantaneous physical consistency.
        Runs every window (~1ms).
        """
        flagged = []

        if self._sheaf_maps:
            for (i, j), (a, b, residual_std) in self._sheaf_maps.items():
                current_i = sensor_data[i][-1]
                current_j = sensor_data[j][-1]
                predicted_j = a * current_i + b
                error = abs(current_j - predicted_j)

                if residual_std > 1e-10:
                    z_score = error / residual_std
                else:
                    z_score = error * 100 if error > 1e-10 else 0.0

                if z_score > 3.0:
                    flagged.append((i, j, round(z_score, 2)))

        self._sheaf_flagged_edges = [(i, j) for i, j, _ in flagged]

        involved = list(set(
            sensor_names[idx]
            for i, j, _ in flagged
            for idx in (i, j)
            if idx < len(sensor_names)
        ))

        return GateResult(
            gate_name="sheaf",
            triggered=len(flagged) > 0,
            findings=[
                f"{sensor_names[i]} ↔ {sensor_names[j]}: {z:.1f}σ deviation"
                for i, j, z in flagged
            ] if flagged else ["All physical relationships consistent"],
            involved_nodes=involved,
            details={
                "flagged_edges": len(flagged),
                "max_z_score": max((z for _, _, z in flagged), default=0.0),
            },
        )

    # ══════════════════════════════════════════════════════════
    # GATE 2: OLLIVIER-RICCI CURVATURE
    # ══════════════════════════════════════════════════════════

    def _gate2_ricci_curvature(
        self, adjacency_matrix: np.ndarray, sensor_names: list,
        focus_edges: List[Tuple[int, int]] = None,
    ) -> GateResult:
        """
        Gate 2: bridge detection via Ollivier-Ricci curvature.
        Runs every 30 windows (~50ms).
        """
        bridges = []
        n = adjacency_matrix.shape[0]

        # Build NetworkX graph
        G = nx.Graph()
        for i in range(n):
            G.add_node(i)
        edge_threshold = 0.1
        for i in range(n):
            for j in range(i + 1, n):
                if adjacency_matrix[i][j] > edge_threshold:
                    G.add_edge(i, j, weight=adjacency_matrix[i][j])

        if G.number_of_edges() > 0:
            # Determine edges to check
            if focus_edges:
                edges_to_check = set()
                for i, j in focus_edges:
                    if G.has_edge(i, j):
                        edges_to_check.add((i, j))
                    for nb in G.neighbors(i):
                        edges_to_check.add((min(i, nb), max(i, nb)))
                    for nb in G.neighbors(j):
                        edges_to_check.add((min(j, nb), max(j, nb)))
            else:
                edges_to_check = set(G.edges())

            for u, v in edges_to_check:
                if not G.has_edge(u, v):
                    continue
                kappa = self._compute_ricci_edge(G, u, v)
                if kappa < -0.5:
                    bridges.append((u, v, round(kappa, 3)))

        self._ricci_bridges = [(u, v) for u, v, _ in bridges]

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
                for u, v, k in bridges
            ] if bridges else ["No bridge edges detected"],
            involved_nodes=involved,
            details={
                "bridge_count": len(bridges),
                "min_curvature": min((k for _, _, k in bridges), default=0.0),
            },
        )

    def _compute_ricci_edge(self, G: nx.Graph, u: int, v: int) -> float:
        """Compute Ollivier-Ricci curvature for edge (u,v)."""
        neighbors_u = list(G.neighbors(u)) + [u]
        neighbors_v = list(G.neighbors(v)) + [v]

        n_u, n_v = len(neighbors_u), len(neighbors_v)
        mu_u = np.ones(n_u) / n_u
        mu_v = np.ones(n_v) / n_v

        cost = np.zeros((n_u, n_v))
        for i, nu in enumerate(neighbors_u):
            for j, nv in enumerate(neighbors_v):
                if nu == nv:
                    cost[i][j] = 0.0
                elif G.has_edge(nu, nv):
                    w = G[nu][nv].get('weight', 1.0)
                    cost[i][j] = 1.0 / (w + 1e-10)
                else:
                    try:
                        cost[i][j] = nx.shortest_path_length(G, nu, nv)
                    except nx.NetworkXNoPath:
                        cost[i][j] = 10.0

        w1 = self._wasserstein_1(mu_u, mu_v, cost)
        edge_weight = G[u][v].get('weight', 1.0)
        d_uv = 1.0 / (edge_weight + 1e-10)

        if d_uv < 1e-10:
            return 0.0
        return 1.0 - (w1 / d_uv)

    @staticmethod
    def _wasserstein_1(mu: np.ndarray, nu: np.ndarray, cost: np.ndarray) -> float:
        """Wasserstein-1 distance via linear programming."""
        n, m = len(mu), len(nu)
        c = cost.flatten()

        A_row = np.zeros((n, n * m))
        for i in range(n):
            A_row[i, i * m:(i + 1) * m] = 1.0

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
        H₂ > 0 = mathematical proof of multi-node coordination.
        """
        findings = []
        involved = []

        # Convert adjacency → distance
        distance = 1.0 / (adjacency_matrix + 1e-10)
        np.fill_diagonal(distance, 0.0)
        max_dist = np.max(distance[distance < 1e8])
        if max_dist > 0:
            distance = distance / max_dist
        distance = np.clip(distance, 0.0, 1.0)

        betti = self._compute_betti(distance)
        self._last_betti = betti
        triggered = False

        if betti.h3 > 0:
            triggered = True
            findings.append(f"H3={betti.h3}: 5-node coordination — botnet mesh")

        if betti.h2 > 0:
            triggered = True
            findings.append(f"H2={betti.h2}: 4-node coordination loop — mathematical proof")

        if hasattr(self.detector, 'baseline') and 1 in self.detector.baseline:
            mu, sigma = self.detector.baseline[1]
            if sigma > 0 and betti.h1 > mu + self.config.anomaly.h1_warning_sigma * sigma:
                triggered = True
                findings.append(f"H1={betti.h1} (baseline: {mu:.1f}±{sigma:.1f}): unusual relay chains")

        if hasattr(self.detector, 'baseline') and 0 in self.detector.baseline:
            mu, sigma = self.detector.baseline[0]
            if sigma > 0 and abs(betti.h0 - mu) > self.config.anomaly.h0_info_sigma * sigma:
                findings.append(f"H0={betti.h0} (baseline: {mu:.1f}±{sigma:.1f}): topology changed")

        if not findings:
            findings.append(f"Clean — H0={betti.h0} H1={betti.h1} H2={betti.h2} H3={betti.h3}")

        if betti.h2 > 0:
            involved = self._find_involved_sensors(distance, sensor_names)

        return GateResult(
            gate_name="homology",
            triggered=triggered,
            findings=findings,
            involved_nodes=involved,
            details={
                "betti_h0": betti.h0, "betti_h1": betti.h1,
                "betti_h2": betti.h2, "betti_h3": betti.h3,
                "epsilon": round(self._epsilon, 4),
            },
        )

    def _compute_betti(self, distance_matrix: np.ndarray) -> BettiNumbers:
        """Compute Betti numbers using GUDHI Vietoris-Rips."""
        try:
            rips = gudhi.RipsComplex(
                distance_matrix=distance_matrix,
                max_edge_length=1.0,
            )
            simplex_tree = rips.create_simplex_tree(max_dimension=4)
            simplex_tree.compute_persistence()

            epsilon = self._select_epsilon(simplex_tree)
            self._epsilon = epsilon

            betti = simplex_tree.persistent_betti_numbers(
                from_value=0.0, to_value=epsilon,
            )
            while len(betti) < 4:
                betti.append(0)

            return BettiNumbers(h0=int(betti[0]), h1=int(betti[1]),
                                h2=int(betti[2]), h3=int(betti[3]))
        except Exception:
            return BettiNumbers()

    def _select_epsilon(self, simplex_tree) -> float:
        """Auto-select filtration scale (Section 2.4)."""
        # kNN scale
        epsilon_local = 0.5
        if self.graph_builder._adjacency_fast is not None:
            adj = self.graph_builder._adjacency_fast
            dist = 1.0 / (adj + 1e-10)
            np.fill_diagonal(dist, 0.0)
            k = self.config.filtration.knn_k
            knn_dists = []
            for i in range(dist.shape[0]):
                s = np.sort(dist[i])
                if len(s) > k:
                    knn_dists.append(s[k])
            if knn_dists:
                epsilon_local = float(np.median(knn_dists)) * self.config.filtration.knn_gamma_scale

        # H0 dendrogram gap
        epsilon_domain = 0.5
        persistence = simplex_tree.persistence()
        h0_pairs = [(b, d) for dim, (b, d) in persistence if dim == 0 and d != float('inf')]
        if h0_pairs:
            lifetimes = sorted([d - b for b, d in h0_pairs], reverse=True)
            epsilon_domain = lifetimes[0] if lifetimes else 0.5

        lam = self.config.filtration.lambda_blend
        epsilon = lam * epsilon_domain + (1.0 - lam) * epsilon_local
        return float(np.clip(epsilon, 0.05, 0.95))

    def _find_involved_sensors(self, distance_matrix: np.ndarray, sensor_names: list) -> List[str]:
        """Find sensors involved in H₂ structures."""
        involved = set()
        epsilon = self._epsilon
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

        if not involved:
            degrees = np.sum(adj_binary, axis=1)
            for idx in np.argsort(degrees)[-4:]:
                if idx < len(sensor_names):
                    involved.add(sensor_names[idx])

        return sorted(list(involved))

    # ══════════════════════════════════════════════════════════
    # ALERT LEVEL DETERMINATION
    # ══════════════════════════════════════════════════════════

    def _determine_alert_level(self, gate_results: List[GateResult]) -> Tuple[AlertLevel, str]:
        """3 gates → HIGH, 1-2 → MID, 0 → CLEAN."""
        triggered = [g for g in gate_results if g.triggered]
        count = len(triggered)

        if count == 0:
            return AlertLevel.CLEAN, "All gates clean"

        all_nodes = set()
        findings = []
        for g in triggered:
            all_nodes.update(g.involved_nodes)
            findings.extend(g.findings)

        node_str = ', '.join(sorted(all_nodes)) if all_nodes else 'none'

        if count >= 3:
            return AlertLevel.HIGH_ALERT, (
                f"HIGH: All 3 gates. Involved: {node_str}. "
                f"{'; '.join(findings[:3])}"
            )

        gate_names = [g.gate_name for g in triggered]
        return AlertLevel.MID_ALERT, (
            f"MID: {count}/3 gates ({', '.join(gate_names)}). "
            f"Involved: {node_str}. {'; '.join(findings[:3])}"
        )

    # ══════════════════════════════════════════════════════════
    # MAIN SCAN METHOD
    # ══════════════════════════════════════════════════════════

    def scan(
        self,
        data_source: str = "swat",
        sensor_data: np.ndarray = None,
        sensor_names: list = None,
        time_window_sec: Optional[int] = None,
        domain_weights: Optional[Dict[str, float]] = None,
        window_index: Optional[int] = None,
    ) -> ScanResult:
        """
        Run one full scan cycle — Phases 1-6.

        Args:
            data_source: dataset name
            sensor_data: (N_sensors, W_samples) array
            sensor_names: list of sensor IDs
        """
        self._scan_count += 1

        # ── Phase 1: Check data ──
        if sensor_data is None:
            return ScanResult(
                status=AlertLevel.CLEAN, betti=BettiNumbers(),
                pattern="No sensor data provided",
                domain=self.config.domain.name, data_source=data_source,
            )

        if sensor_names is None:
            sensor_names = [f"s{i}" for i in range(sensor_data.shape[0])]

        # ── Phase 2: Distance matrix ──
        D, names = self.graph_builder.build_distance_matrix(sensor_data, sensor_names)

        # ── Phase 3: Triple decay update ──
        fast_adj, slow_adj, baseline_adj = self.graph_builder.update_adjacency_with_decay(D)

        # ── Phase 4: Run gates ──
        gate_results = []

        # Gate 1: Sheaf — every window
        gate1 = self._gate1_sheaf_consistency(sensor_data, sensor_names)
        gate_results.append(gate1)

        # Gate 2: Ricci — every 30 windows
        if self._scan_count % self.graph_builder._slow_interval == 0:
            gate2 = self._gate2_ricci_curvature(
                slow_adj, sensor_names,
                focus_edges=self._sheaf_flagged_edges if gate1.triggered else None,
            )
        else:
            gate2 = GateResult(
                gate_name="ricci",
                triggered=len(self._ricci_bridges) > 0,
                findings=[f"Last check: {len(self._ricci_bridges)} bridges"]
                    if self._ricci_bridges else ["Waiting for next check"],
                involved_nodes=[
                    sensor_names[idx]
                    for u, v in self._ricci_bridges
                    for idx in (u, v)
                    if idx < len(sensor_names)
                ],
                details={"bridges_from_last_check": len(self._ricci_bridges)},
            )
        gate_results.append(gate2)

        # Gate 3: Homology — fast layer every time, baseline every 180
        if self._scan_count % self.graph_builder._baseline_interval == 0:
            gate3 = self._gate3_persistent_homology(baseline_adj, sensor_names)
        else:
            gate3 = self._gate3_persistent_homology(fast_adj, sensor_names)
        gate_results.append(gate3)

        # ── Phase 5: Alert level ──
        alert_level, pattern = self._determine_alert_level(gate_results)
        gates_triggered = sum(1 for g in gate_results if g.triggered)

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
            involved_sensors=sorted(list(all_involved)),
            confidence=confidence,
            pattern=pattern,
            window_start=str(window_index or self._scan_count),
            window_end=str((window_index or self._scan_count) + 1),
            epsilon=self._epsilon,
            consecutive_alerts=self.detector.get_consecutive_count(),
            domain=self.config.domain.name,
            data_source=data_source,
            gate_results=gate_results,
            gates_triggered=gates_triggered,
        )
