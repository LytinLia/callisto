"""MA-BOCPD — Meta-Adaptive Bayesian Online Changepoint Detection.

Core contribution #2: Performs real-time changepoint detection on
behavioral embedding streams. Unlike classical BOCPD with a fixed
hazard function, MA-BOCPD uses a meta-learned hazard that adapts
to agent type and task context, solving the cold-start problem.
"""

from __future__ import annotations

import time
import numpy as np
from dataclasses import dataclass, field
from scipy.special import logsumexp

from callisto.collector.models import Alert, RiskLevel, AttackType


@dataclass
class ChangepointResult:
    """Result of changepoint analysis at a single timestep."""

    timestep: int = 0
    changepoint_prob: float = 0.0  # P(r_t = 0 | e_{1:t})
    run_length_map: int = 0  # MAP estimate of current run length
    is_changepoint: bool = False


class HazardFunction:
    """Base constant hazard H(r) = 1/λ."""

    def __init__(self, lam: float = 100.0):
        self.lam = lam

    def __call__(self, run_length: int) -> float:
        return 1.0 / self.lam

    def batch_call(self, n: int) -> np.ndarray:
        """Return hazard values for run lengths 0..n-1 as a vector."""
        return np.full(n, 1.0 / self.lam)


class MetaAdaptiveHazard(HazardFunction):
    """Meta-learned hazard function that adapts based on context."""

    def __init__(self, base_lam: float = 100.0, n_prototypes: int = 5, dim: int = 64, seed: int = 42):
        super().__init__(base_lam)
        self.dim = dim
        rng = np.random.RandomState(seed)
        self.prototypes: np.ndarray = rng.randn(n_prototypes, dim)
        self.prototype_lams: np.ndarray = rng.uniform(50, 200, size=n_prototypes)
        self._context_embedding: np.ndarray | None = None
        self._cached_hazard: float | None = None

    def set_context(self, embedding: np.ndarray) -> None:
        self._context_embedding = embedding
        self._cached_hazard = None  # invalidate cache

    def __call__(self, run_length: int) -> float:
        if self._context_embedding is None:
            return 1.0 / self.lam
        if self._cached_hazard is None:
            sims = self.prototypes @ self._context_embedding
            weights = np.exp(sims - sims.max())
            weights /= weights.sum() + 1e-12
            adapted_lam = float(weights @ self.prototype_lams)
            self._cached_hazard = 1.0 / max(adapted_lam, 1.0)
        return self._cached_hazard

    def batch_call(self, n: int) -> np.ndarray:
        h = self(0)  # hazard is context-dependent but run-length-independent
        return np.full(n, h)

    def update_prototypes(self, embeddings: np.ndarray, lams: np.ndarray) -> None:
        self.prototypes = embeddings
        self.prototype_lams = lams
        self._cached_hazard = None


# ---------------------------------------------------------------------------
# MA-BOCPD Core Algorithm (vectorized)
# ---------------------------------------------------------------------------

class MABOCPD:
    """Meta-Adaptive Bayesian Online Changepoint Detection (vectorized).

    Maintains a run-length distribution P(r_t | e_{1:t}) and updates it
    online as new behavioral embeddings arrive. Uses a fixed-variance
    Gaussian observation model with known-variance / unknown-mean conjugacy
    so that genuine distribution shifts produce detectable changepoints.

    Key design: variance is fixed (not learned per run length), so the
    predictive distribution widens only through mean uncertainty, not by
    absorbing the shift into a larger variance estimate.
    """

    def __init__(
        self,
        dim: int = 64,
        hazard: HazardFunction | None = None,
        threshold: float = 0.5,
        run_length_cap: int = 50,
        bocpd_dim: int = 8,
        obs_variance: float = 0.5,
        seed: int = 42,
    ):
        self.input_dim = dim
        self.dim = bocpd_dim
        self.hazard = hazard or HazardFunction()
        self.threshold = threshold
        self.cap = run_length_cap

        # Random projection matrix for dimensionality reduction
        rng = np.random.RandomState(seed)
        proj = rng.randn(dim, bocpd_dim)
        self._proj = proj / (np.linalg.norm(proj, axis=0, keepdims=True) + 1e-9)

        # Fixed observation variance (known σ²)
        self._obs_var = obs_variance

        self._log_joint = np.array([0.0])
        self._t = 0
        self._prev_rl_map = 0  # track previous MAP run length for drop detection

        # Prior: N(mu0, sigma² / kappa0)
        self._mu0 = np.zeros(bocpd_dim)
        self._kappa0 = 0.01

        # Sufficient stats
        self._sum_x = np.zeros((1, bocpd_dim))
        self._counts = np.array([0], dtype=np.int32)

    def _predictive_log_prob_batch(self, x: np.ndarray) -> np.ndarray:
        """Vectorized log predictive probability for all run lengths.

        Known-variance Gaussian conjugate model:
          Prior:     mu ~ N(mu0, sigma² / kappa0)
          Posterior: mu | x_{1:n} ~ N(mu_n, sigma² / kappa_n)
          Predictive: x_{n+1} ~ N(mu_n, sigma² * (1 + 1/kappa_n))

        The fixed sigma² means a shifted observation gets penalized by the
        full shift magnitude, not absorbed into a growing variance estimate.
        """
        n_rl = len(self._counts)
        counts = self._counts.astype(np.float64)
        kappa_n = self._kappa0 + counts  # (n_rl,)

        # Posterior mean: (n_rl, dim)
        mu_n = (self._kappa0 * self._mu0 + self._sum_x[:n_rl]) / kappa_n[:, None]

        # Predictive variance: σ² * (1 + 1/κ_n) per dimension
        pred_var = self._obs_var * (1.0 + 1.0 / kappa_n)  # (n_rl,)

        # Log predictive: sum over dimensions of N(x; mu_n, pred_var)
        diff = x[None, :] - mu_n  # (n_rl, dim)
        log_p = -0.5 * self.dim * np.log(2 * np.pi * pred_var) \
                - 0.5 * np.sum(diff ** 2, axis=1) / pred_var
        return log_p

    def _project(self, x: np.ndarray) -> np.ndarray:
        """Project high-dimensional embedding to low-dimensional BOCPD space."""
        return x @ self._proj

    def update(self, x: np.ndarray) -> ChangepointResult:
        """Process one new observation (vectorized).

        Changepoint detection uses the run-length posterior: when the
        cumulative probability of short run lengths (r <= 2) spikes,
        it means the model believes a new regime just started.
        """
        x = self._project(x)
        self._t += 1
        n_rl = len(self._log_joint)

        # Step 1: Batch predictive probabilities
        log_pred = self._predictive_log_prob_batch(x)

        # Step 2: Batch hazard
        h = self.hazard.batch_call(n_rl)
        log_h = np.log(h + 1e-12)
        log_1mh = np.log(1.0 - h + 1e-12)

        # Step 3: Growth probabilities
        log_growth = self._log_joint + log_pred + log_1mh

        # Step 4: Changepoint probability
        log_cp = logsumexp(self._log_joint + log_pred + log_h)

        # Step 5: Assemble new joint
        new_n = min(n_rl + 1, self.cap)
        new_log_joint = np.empty(new_n)
        new_log_joint[0] = log_cp
        new_log_joint[1:new_n] = log_growth[:new_n - 1]

        # Normalize
        new_log_joint -= logsumexp(new_log_joint)
        self._log_joint = new_log_joint

        # Step 6: Update sufficient stats (no sum_x2 needed)
        new_sum_x = np.empty((new_n, self.dim))
        new_counts = np.empty(new_n, dtype=np.int32)
        new_sum_x[0] = 0.0
        new_counts[0] = 0
        copy_n = new_n - 1
        if copy_n > 0:
            new_sum_x[1:new_n] = self._sum_x[:copy_n] + x[None, :]
            new_counts[1:new_n] = self._counts[:copy_n] + 1
        self._sum_x = new_sum_x
        self._counts = new_counts

        # Step 7: Changepoint detection via run-length posterior
        # P(r_t <= 2) = sum of posterior mass on short run lengths
        # This spikes when the model believes a new regime just started
        rl_map = int(np.argmax(new_log_joint))
        short_rl_prob = float(np.exp(logsumexp(new_log_joint[:min(3, new_n)])))

        # Also detect via MAP drop: if RL_MAP was long and suddenly drops
        rl_drop = self._prev_rl_map > 3 and rl_map <= 2
        self._prev_rl_map = rl_map

        # Combine: use short_rl_prob as the score, trigger on either signal
        is_cp = (short_rl_prob > self.threshold) or rl_drop

        return ChangepointResult(
            timestep=self._t,
            changepoint_prob=short_rl_prob,
            run_length_map=rl_map,
            is_changepoint=is_cp and self._t > 3,  # skip warmup
        )

    def detect(self, x: np.ndarray, session_id: str = "") -> Alert | None:
        result = self.update(x)
        if not result.is_changepoint:
            return None
        return Alert(
            timestamp=time.time(),
            session_id=session_id,
            risk_level=RiskLevel.HIGH if result.changepoint_prob > 0.8 else RiskLevel.MEDIUM,
            attack_type=AttackType.A4_BEHAVIOR_DRIFT,
            source_module="MA-BOCPD",
            score=result.changepoint_prob,
            explanation=(
                f"Behavioral changepoint detected at step {result.timestep} "
                f"(P(cp)={result.changepoint_prob:.3f}, "
                f"run_length_MAP={result.run_length_map})"
            ),
        )

    def reset(self) -> None:
        self._log_joint = np.array([0.0])
        self._t = 0
        self._prev_rl_map = 0
        self._sum_x = np.zeros((1, self.dim))
        self._counts = np.array([0], dtype=np.int32)
