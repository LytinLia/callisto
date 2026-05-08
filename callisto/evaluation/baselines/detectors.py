"""Baseline detectors for comparison."""

from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

from callisto.collector.models import Session, Alert, AttackType, RiskLevel
from callisto.features.temporal import TemporalExtractor
from callisto.features.structural import StructuralExtractor


class RuleBasedDetector:
    """Fixed-rule baseline: rate limiting + tool blacklist."""

    def __init__(self, max_rate: float = 5.0, blacklist: set[str] | None = None):
        self.max_rate = max_rate
        self.blacklist = blacklist or {"exec", "shell", "run_command"}

    def detect(self, session: Session) -> list[Alert]:
        alerts = []
        calls = session.tool_calls
        if not calls:
            return alerts

        # Rate check
        if len(calls) >= 2:
            duration = calls[-1].timestamp - calls[0].timestamp
            rate = len(calls) / (duration + 1e-9)
            if rate > self.max_rate:
                alerts.append(Alert(
                    session_id=session.session_id,
                    risk_level=RiskLevel.MEDIUM,
                    attack_type=AttackType.A1_RATE_FLOOD,
                    source_module="RuleBaseline",
                    score=rate / self.max_rate,
                ))

        # Blacklist check
        for c in calls:
            if c.tool_name in self.blacklist:
                alerts.append(Alert(
                    session_id=session.session_id,
                    risk_level=RiskLevel.LOW,
                    source_module="RuleBaseline",
                    score=0.5,
                ))
                break

        return alerts


class IsolationForestDetector:
    """Isolation Forest baseline on temporal + structural features."""

    def __init__(self, contamination: float = 0.1):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self._temporal = TemporalExtractor()
        self._structural = StructuralExtractor()
        self._fitted = False

    def _featurize(self, session: Session) -> np.ndarray:
        calls = session.tool_calls
        tf = self._temporal.extract(calls)
        _, sf = self._structural.extract(calls)
        return np.concatenate([tf.to_vector(), sf.to_vector()])

    def fit(self, sessions: list[Session]) -> None:
        X = np.stack([self._featurize(s) for s in sessions])
        try:
            self.model.fit(X)
            self._fitted = True
        except Exception:
            self._fitted = False

    def detect(self, session: Session) -> list[Alert]:
        if not self._fitted:
            return []
        x = self._featurize(session).reshape(1, -1)
        pred = self.model.predict(x)[0]
        if pred == -1:
            return [Alert(
                session_id=session.session_id,
                risk_level=RiskLevel.MEDIUM,
                source_module="IsolationForest",
                score=float(-self.model.score_samples(x)[0]),
            )]
        return []


class LOFDetector:
    """Local Outlier Factor baseline."""

    def __init__(self, n_neighbors: int = 20, contamination: float = 0.1):
        self.model = LocalOutlierFactor(n_neighbors=n_neighbors, contamination=contamination, novelty=True)
        self._temporal = TemporalExtractor()
        self._structural = StructuralExtractor()
        self._fitted = False

    def _featurize(self, session: Session) -> np.ndarray:
        calls = session.tool_calls
        tf = self._temporal.extract(calls)
        _, sf = self._structural.extract(calls)
        return np.concatenate([tf.to_vector(), sf.to_vector()])

    def fit(self, sessions: list[Session]) -> None:
        X = np.stack([self._featurize(s) for s in sessions])
        try:
            self.model.fit(X)
            self._fitted = True
        except Exception:
            self._fitted = False

    def detect(self, session: Session) -> list[Alert]:
        if not self._fitted:
            return []
        x = self._featurize(session).reshape(1, -1)
        pred = self.model.predict(x)[0]
        if pred == -1:
            return [Alert(
                session_id=session.session_id,
                risk_level=RiskLevel.MEDIUM,
                source_module="LOF",
                score=float(-self.model.score_samples(x)[0]),
            )]
        return []
