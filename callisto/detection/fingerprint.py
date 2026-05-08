"""CSBF — Cross-Session Behavioral Fingerprinting.

Core contribution #3: Builds a behavioral fingerprint baseline for each
agent from historical sessions, then detects identity anomalies (hijacking,
state poisoning) by measuring Mahalanobis distance in fingerprint space.

No prior work performs cross-session behavioral analysis for LLM agents.
"""

from __future__ import annotations

import json
import logging
import time
import numpy as np
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

from callisto.collector.models import CallEvent, Session, Alert, RiskLevel, AttackType


@dataclass
class BehavioralFingerprint:
    """Behavioral fingerprint for an agent, learned from historical sessions."""

    agent_id: str = ""
    mean: np.ndarray = field(default_factory=lambda: np.zeros(0))
    cov_inv: np.ndarray = field(default_factory=lambda: np.zeros((0, 0)))
    n_sessions: int = 0


@dataclass
class FingerprintResult:
    """Result of fingerprint comparison for a new session."""

    agent_id: str = ""
    distance: float = 0.0  # Mahalanobis distance
    threshold: float = 0.0
    is_anomalous: bool = False
    anomaly_dimensions: list[int] = field(default_factory=list)


class SessionFeaturizer:
    """Extract a fixed-size behavioral summary vector from a session."""

    def __init__(self, n_tool_bins: int = 20):
        self.n_tool_bins = n_tool_bins

    def featurize(self, session: Session) -> np.ndarray:
        """Extract behavioral summary vector from a session.

        Features (total dim = n_tool_bins + 8):
        - Tool usage distribution (n_tool_bins)
        - Session duration
        - Total call count
        - Mean/std inter-arrival time
        - Unique tools used
        - Max burst rate (calls in any 5s window)
        - Read/write ratio
        - Mean parameter complexity (avg param string length)
        """
        calls = session.tool_calls
        n = len(calls)

        # Tool distribution
        tool_dist = np.zeros(self.n_tool_bins)
        for c in calls:
            idx = hash(c.tool_name) % self.n_tool_bins
            tool_dist[idx] += 1
        if n > 0:
            tool_dist /= n

        # Temporal stats
        duration = session.duration
        if n >= 2:
            ts = np.array([c.timestamp for c in calls])
            iats = np.diff(ts)
            mean_iat = float(np.mean(iats))
            std_iat = float(np.std(iats))
        else:
            mean_iat = 0.0
            std_iat = 0.0

        unique_tools = len(set(c.tool_name for c in calls))

        # Burst rate: max calls in any 5-second window (sliding window O(n))
        burst = 0
        if n > 0:
            ts = [c.timestamp for c in calls]
            j = 0
            for i in range(n):
                while j < n and ts[j] - ts[i] <= 5.0:
                    j += 1
                burst = max(burst, j - i)

        # Read/write ratio
        read_ops = sum(1 for c in calls if "read" in c.tool_name.lower() or "get" in c.tool_name.lower())
        write_ops = sum(1 for c in calls if "write" in c.tool_name.lower() or "set" in c.tool_name.lower() or "exec" in c.tool_name.lower())
        rw_ratio = read_ops / (write_ops + 1e-9)

        # Parameter complexity
        param_lens = [len(str(c.parameters)) for c in calls]
        mean_param_len = float(np.mean(param_lens)) if param_lens else 0.0

        scalar_feats = np.array([
            duration, float(n), mean_iat, std_iat,
            float(unique_tools), float(burst), rw_ratio, mean_param_len,
        ])

        return np.concatenate([tool_dist, scalar_feats])


# ---------------------------------------------------------------------------
# CSBF Core Algorithm
# ---------------------------------------------------------------------------

class CrossSessionFingerprinter:
    """Cross-Session Behavioral Fingerprinting detector.

    Algorithm:
    1. Fit phase: collect session feature vectors, compute per-agent
       mean and covariance (regularized).
    2. Detect phase: for a new session, compute Mahalanobis distance
       to the agent's fingerprint. Flag if distance > threshold.
    3. Attribution: identify which feature dimensions contribute most
       to the anomaly.
    """

    def __init__(
        self,
        distance_threshold: float = 3.0,
        min_history: int = 5,
        regularization: float = 1.0,
        adaptive_threshold: bool = True,
    ):
        self.distance_threshold = distance_threshold
        self.min_history = min_history
        self.reg = regularization
        self.adaptive_threshold = adaptive_threshold
        self.featurizer = SessionFeaturizer()
        self._fingerprints: dict[str, BehavioralFingerprint] = {}
        self._history: dict[str, list[np.ndarray]] = {}
        self._train_distances: dict[str, list[float]] = {}
        self._adaptive_thresholds: dict[str, float] = {}

    def fit_session(self, session: Session) -> None:
        """Add a session to the agent's behavioral history and update fingerprint."""
        aid = session.agent_id
        vec = self.featurizer.featurize(session)

        if aid not in self._history:
            self._history[aid] = []
        self._history[aid].append(vec)

        if len(self._history[aid]) >= self.min_history:
            self._update_fingerprint(aid)

    def _update_fingerprint(self, agent_id: str) -> None:
        """Recompute fingerprint from accumulated history."""
        vecs = np.stack(self._history[agent_id])
        mean = vecs.mean(axis=0)
        cov = np.cov(vecs, rowvar=False)
        # Strong regularization for stability with small sample sizes
        cov += self.reg * np.eye(cov.shape[0])
        try:
            cov_inv = np.linalg.inv(cov)
        except np.linalg.LinAlgError:
            cov_inv = np.linalg.pinv(cov)

        self._fingerprints[agent_id] = BehavioralFingerprint(
            agent_id=agent_id,
            mean=mean,
            cov_inv=cov_inv,
            n_sessions=len(self._history[agent_id]),
        )

        # Compute adaptive threshold from leave-one-out distances
        if self.adaptive_threshold and len(vecs) >= self.min_history:
            dists = []
            for v in vecs:
                diff = v - mean
                d = np.sqrt(max(float(diff @ cov_inv @ diff), 0.0))
                dists.append(d)
            # Threshold = mean + 3*std of training distances
            self._adaptive_thresholds[agent_id] = float(
                np.mean(dists) + 3.0 * np.std(dists)
            )

    def compare(self, session: Session) -> FingerprintResult:
        """Compare a new session against the agent's fingerprint."""
        aid = session.agent_id
        fp = self._fingerprints.get(aid)

        if fp is None or fp.n_sessions < self.min_history:
            return FingerprintResult(agent_id=aid, distance=0.0,
                                     threshold=self.distance_threshold)

        vec = self.featurizer.featurize(session)
        diff = vec - fp.mean
        maha_sq = float(diff @ fp.cov_inv @ diff)
        maha = np.sqrt(max(maha_sq, 0.0))

        # Use adaptive threshold if available
        threshold = self._adaptive_thresholds.get(aid, self.distance_threshold)

        # Attribution: per-dimension contribution to Mahalanobis distance
        per_dim = (diff ** 2) * np.diag(fp.cov_inv)
        top_dims = list(np.argsort(per_dim)[-5:][::-1])

        return FingerprintResult(
            agent_id=aid,
            distance=maha,
            threshold=threshold,
            is_anomalous=maha > threshold,
            anomaly_dimensions=top_dims,
        )

    def detect(self, session: Session) -> Alert | None:
        """Run fingerprint comparison and return Alert if anomalous."""
        result = self.compare(session)
        if not result.is_anomalous:
            # Still add to history for future comparisons
            self.fit_session(session)
            return None

        alert = Alert(
            timestamp=time.time(),
            session_id=session.session_id,
            risk_level=RiskLevel.CRITICAL if result.distance > 2 * result.threshold else RiskLevel.HIGH,
            attack_type=AttackType.A4_BEHAVIOR_DRIFT,
            source_module="CSBF",
            score=result.distance / (result.threshold + 1e-9),
            explanation=(
                f"Session behavioral fingerprint deviates from agent '{result.agent_id}' "
                f"baseline (Mahalanobis={result.distance:.2f}, threshold={result.threshold:.2f}). "
                f"Top anomalous dimensions: {result.anomaly_dimensions}"
            ),
        )
        return alert

    @property
    def fingerprints(self) -> dict[str, BehavioralFingerprint]:
        return dict(self._fingerprints)

    def save(self, path: Path) -> None:
        """Serialize fingerprinter state to a JSON file."""
        fingerprints_data = {}
        for aid, fp in self._fingerprints.items():
            fingerprints_data[aid] = {
                "mean": fp.mean.tolist(),
                "cov_inv": fp.cov_inv.tolist(),
                "n_sessions": fp.n_sessions,
            }

        history_data = {}
        for aid, vecs in self._history.items():
            history_data[aid] = [v.tolist() for v in vecs]

        data = {
            "version": 1,
            "distance_threshold": self.distance_threshold,
            "min_history": self.min_history,
            "reg": self.reg,
            "n_tool_bins": self.featurizer.n_tool_bins,
            "fingerprints": fingerprints_data,
            "adaptive_thresholds": dict(self._adaptive_thresholds),
            "history": history_data,
        }

        path = Path(path)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "CrossSessionFingerprinter":
        """Reconstruct a CrossSessionFingerprinter from a JSON file."""
        path = Path(path)
        data = json.loads(path.read_text(encoding="utf-8"))

        if data.get("version") != 1:
            raise ValueError(
                f"Unsupported fingerprint file version: {data.get('version')}"
            )

        n_tool_bins = data["n_tool_bins"]
        expected_dim = n_tool_bins + 8

        obj = cls(
            distance_threshold=data["distance_threshold"],
            min_history=data["min_history"],
            regularization=data["reg"],
        )
        obj.featurizer = SessionFeaturizer(n_tool_bins=n_tool_bins)

        # Rebuild fingerprints
        for aid, fp_data in data.get("fingerprints", {}).items():
            mean = np.array(fp_data["mean"])
            cov_inv = np.array(fp_data["cov_inv"])
            if mean.shape != (expected_dim,) or cov_inv.shape != (expected_dim, expected_dim):
                logger.warning(
                    "Skipping incompatible fingerprint for agent '%s': "
                    "expected dim %d, got mean %s / cov_inv %s",
                    aid, expected_dim, mean.shape, cov_inv.shape,
                )
                continue
            obj._fingerprints[aid] = BehavioralFingerprint(
                agent_id=aid,
                mean=mean,
                cov_inv=cov_inv,
                n_sessions=fp_data["n_sessions"],
            )

        # Rebuild history
        for aid, vecs_data in data.get("history", {}).items():
            vecs = []
            for v in vecs_data:
                arr = np.array(v)
                if arr.shape != (expected_dim,):
                    logger.warning(
                        "Skipping incompatible history vector for agent '%s': "
                        "expected dim %d, got %s",
                        aid, expected_dim, arr.shape,
                    )
                    continue
                vecs.append(arr)
            if vecs:
                obj._history[aid] = vecs

        # Rebuild adaptive thresholds
        for aid, thresh in data.get("adaptive_thresholds", {}).items():
            obj._adaptive_thresholds[aid] = float(thresh)

        return obj
