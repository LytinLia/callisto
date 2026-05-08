"""CALLISTO global configuration."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class CallistoConfig:
    # --- Data Collection ---
    log_dir: Path = Path("./logs")
    watch_interval: float = 1.0  # seconds

    # --- Feature Extraction ---
    context_window: int = 10  # sliding window size for temporal features
    embedding_dim: int = 64

    # --- CRS (Causal Responsibility Scoring) ---
    crs_samples: int = 30  # Shapley sampling count k
    crs_threshold: float = 0.7

    # --- MA-BOCPD (Changepoint Detection) ---
    bocpd_hazard_base: float = 1 / 25  # base hazard rate 1/λ (expect ~25 events between changes)
    bocpd_threshold: float = 0.5
    bocpd_run_length_cap: int = 50

    # --- CSBF (Cross-Session Behavioral Fingerprinting) ---
    csbf_distance_threshold: float = 3.0  # Mahalanobis distance
    csbf_min_history: int = 5  # minimum sessions for fingerprint

    # --- Response Engine ---
    alert_cooldown: float = 5.0  # seconds between repeated alerts
    circuit_breaker_threshold: int = 3  # consecutive alerts to trigger break

    # --- Temporal Anomaly Detection (engine thresholds) ---
    burst_window: float = 5.0  # seconds for rate burst window
    burst_count_threshold: int = 10  # calls within window to trigger (increased from 8 to reduce false positives)
    sensitive_chain_min: int = 3  # min consecutive sensitive tool calls
    pace_shift_low: float = 0.15  # IAT ratio below = dramatic slowdown
    pace_shift_high: float = 8.0  # IAT ratio above = dramatic speedup
    pace_shift_min_iats: int = 6  # min IATs needed for pace shift check
    temporal_violation_score: float = 0.7
    state_poison_score: float = 0.85
    # Note: state_poison_patterns moved to engine.py (_STATE_POISON_PATTERNS)

    # --- DAG Construction ---
    dag_min_snippet_len: int = 16  # min result snippet length for dataflow edges
    dag_trivial_values: set[str] = field(
        default_factory=lambda: {"true", "false", "null", "0", "1", "none", "ok", ""}
    )

    # --- Persistence ---
    fingerprint_path: Optional[Path] = None  # save/load CSBF fingerprints

    # --- Attack Simulation ---
    seed: int = 42

    # --- Evaluation ---
    eval_output_dir: Path = Path("./eval_results")


DEFAULT_CONFIG = CallistoConfig()
