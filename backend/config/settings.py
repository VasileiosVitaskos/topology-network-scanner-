"""
config/settings.py
Central configuration loader.
Reads .env for secrets, domains.yaml for domain presets.

Usage:
    from config.settings import get_config
    config = get_config()              # default domain from .env
    config = get_config("manufacturing")  # override domain
"""

import os
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from dotenv import load_dotenv

# ── Resolve project root & load .env ─────────────────────────
# ROOT_DIR = backend/ (parent of config/)
ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env")
# Also try project root (parent of backend/) for non-Docker setups
load_dotenv(ROOT_DIR.parent / ".env")

logger = logging.getLogger(__name__)


# ── Typed Config Objects ─────────────────────────────────────

@dataclass
class DatabaseConfig:
    """SQLite persistence for scan history + topology."""
    db_path: str = os.getenv("DB_PATH", "/app/db/topo_scanner.db")


@dataclass
class OpenAIConfig:
    """GPT integration for Quick Scan analysis + Chat assistant."""
    api_key: str = os.getenv("OPENAI_API_KEY", "")
    model: str = os.getenv("OPENAI_MODEL", "gpt-4.1")
    temperature: float = float(os.getenv("OPENAI_TEMPERATURE", "0.1"))
    max_tokens: int = int(os.getenv("OPENAI_MAX_TOKENS", "4096"))

    @property
    def available(self) -> bool:
        return bool(self.api_key and self.api_key.startswith("sk-"))


@dataclass
class FlaskConfig:
    host: str = os.getenv("FLASK_HOST", "0.0.0.0")
    port: int = int(os.getenv("FLASK_PORT", "5000"))
    debug: bool = os.getenv("FLASK_DEBUG", "0") == "1"
    secret_key: str = os.getenv("SECRET_KEY", "change-me")


@dataclass
class DomainWeights:
    """
    Blending weights for the three distance layers:
        alpha = Pearson correlation (instantaneous coupling)
        beta  = DTW (time-lagged similarity)
        gamma = Granger causality (causal relationships)
    Must sum to 1.0.
    """
    alpha: float = 0.2
    beta: float = 0.6
    gamma: float = 0.2

    def __post_init__(self):
        total = self.alpha + self.beta + self.gamma
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"Domain weights must sum to 1.0, got {total:.4f}")


@dataclass
class DomainConfig:
    name: str = "water_treatment"
    description: str = ""
    weights: DomainWeights = field(default_factory=DomainWeights)
    window_sec: float = 60       # float to support sub-second windows (power_grid)
    step_sec: float = 10         # float to support sub-second steps
    max_sensors: int = 86
    dominant_physics: str = "slow_fluid_dynamics"
    datasets: List[str] = field(default_factory=list)


@dataclass
class AnomalyScanConfig:
    h2_alert_threshold: int = 1
    h1_warning_sigma: float = 3.0
    h0_info_sigma: float = 2.0
    min_consecutive_windows: int = 3
    buffer_short_sec: int = 60
    buffer_medium_sec: int = 3600
    buffer_long_sec: int = 86400


@dataclass
class FiltrationConfig:
    lambda_blend: float = 0.5
    knn_k: int = 5
    knn_gamma_scale: float = 1.75


@dataclass
class MatrixConfig:
    decay_factor: float = 0.95
    novelty_memory_sec: int = 3600


@dataclass
class DenyFilterConfig:
    k_recon: int = 10
    t_recon_sec: int = 60


@dataclass
class TopoConfig:
    """Master config object — single import, all settings."""
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    flask: FlaskConfig = field(default_factory=FlaskConfig)
    openai: OpenAIConfig = field(default_factory=OpenAIConfig)
    domain: DomainConfig = field(default_factory=DomainConfig)
    anomaly: AnomalyScanConfig = field(default_factory=AnomalyScanConfig)
    filtration: FiltrationConfig = field(default_factory=FiltrationConfig)
    matrix: MatrixConfig = field(default_factory=MatrixConfig)
    deny_filter: DenyFilterConfig = field(default_factory=DenyFilterConfig)
    all_domains: Dict[str, DomainConfig] = field(default_factory=dict)
    data_dir: str = os.getenv("DATA_DIR", "/app/data")
    max_dimension: int = int(os.getenv("TOPO_MAX_DIMENSION", "3"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")


# ── YAML Loader ──────────────────────────────────────────────

def _load_domains_yaml() -> dict:
    """Load config/domains.yaml. Tries multiple paths for flexibility."""
    candidates = [
        ROOT_DIR / "config" / "domains.yaml",
        ROOT_DIR / "domains.yaml",
        Path("config") / "domains.yaml",
    ]
    for path in candidates:
        if path.exists():
            with open(path) as f:
                return yaml.safe_load(f) or {}
    logger.warning("domains.yaml not found, using defaults")
    return {}


def _build_domain_config(name: str, raw: dict) -> DomainConfig:
    return DomainConfig(
        name=name,
        description=raw.get("description", ""),
        weights=DomainWeights(
            alpha=raw.get("alpha", 0.2),
            beta=raw.get("beta", 0.6),
            gamma=raw.get("gamma", 0.2),
        ),
        window_sec=float(raw.get("window_sec", 60)),
        step_sec=float(raw.get("step_sec", 10)),
        max_sensors=int(raw.get("max_sensors", 86)),
        dominant_physics=raw.get("dominant_physics", ""),
        datasets=raw.get("datasets", []),
    )


def load_config(domain_name: Optional[str] = None) -> TopoConfig:
    """
    Build the full config.

    Args:
        domain_name: Override the default domain from .env.
                     Options: water_treatment, power_grid, manufacturing,
                              gas_pipeline, it_network
    """
    raw = _load_domains_yaml()
    domain_name = domain_name or os.getenv("TOPO_DEFAULT_DOMAIN", "water_treatment")

    # Build all domain configs
    all_domains = {}
    for dname, dconfig in raw.get("domains", {}).items():
        all_domains[dname] = _build_domain_config(dname, dconfig)

    # Active domain
    active_domain = all_domains.get(domain_name, DomainConfig(name=domain_name))

    # Anomaly scan
    scan_raw = raw.get("anomaly_scan", {})
    anomaly = AnomalyScanConfig(
        h2_alert_threshold=scan_raw.get("h2_alert_threshold", 1),
        h1_warning_sigma=scan_raw.get("h1_warning_sigma", 3.0),
        h0_info_sigma=scan_raw.get("h0_info_sigma", 2.0),
        min_consecutive_windows=scan_raw.get("min_consecutive_windows", 3),
        buffer_short_sec=scan_raw.get("buffer_short_sec", 60),
        buffer_medium_sec=scan_raw.get("buffer_medium_sec", 3600),
        buffer_long_sec=scan_raw.get("buffer_long_sec", 86400),
    )

    # Filtration
    filt_raw = raw.get("filtration", {})
    filtration = FiltrationConfig(
        lambda_blend=filt_raw.get("lambda", 0.5),
        knn_k=filt_raw.get("knn_k", 5),
        knn_gamma_scale=filt_raw.get("knn_gamma_scale", 1.75),
    )

    # Matrix
    mat_raw = raw.get("matrix", {})
    matrix_cfg = MatrixConfig(
        decay_factor=mat_raw.get("decay_factor", 0.95),
        novelty_memory_sec=mat_raw.get("novelty_memory_sec", 3600),
    )

    # Deny filter
    deny_raw = raw.get("deny_filter", {})
    deny_cfg = DenyFilterConfig(
        k_recon=deny_raw.get("k_recon", 10),
        t_recon_sec=deny_raw.get("t_recon_sec", 60),
    )

    config = TopoConfig(
        database=DatabaseConfig(),
        flask=FlaskConfig(),
        openai=OpenAIConfig(),
        domain=active_domain,
        anomaly=anomaly,
        filtration=filtration,
        matrix=matrix_cfg,
        deny_filter=deny_cfg,
        all_domains=all_domains,
    )

    logger.info(
        f"Config loaded: domain={active_domain.name}, "
        f"weights=({active_domain.weights.alpha}/{active_domain.weights.beta}/{active_domain.weights.gamma}), "
        f"window={active_domain.window_sec}s, max_sensors={active_domain.max_sensors}, "
        f"AI={'available' if config.openai.available else 'disabled'}"
    )

    return config


# ── Singleton ────────────────────────────────────────────────
_config: Optional[TopoConfig] = None


def get_config(domain_name: Optional[str] = None) -> TopoConfig:
    """Get or create the singleton config."""
    global _config
    if _config is None or domain_name is not None:
        _config = load_config(domain_name)
    return _config