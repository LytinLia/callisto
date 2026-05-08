"""Temporal feature extraction for API call sequences.

Extracts inter-arrival time distributions, burst detection,
periodicity, and sliding-window rate statistics.
"""

from __future__ import annotations

import numpy as np
from dataclasses import dataclass, field

from callisto.collector.models import CallEvent


@dataclass
class TemporalFeatures:
    """Temporal feature vector for a window of events."""

    mean_iat: float = 0.0          # mean inter-arrival time
    std_iat: float = 0.0           # std of inter-arrival times
    min_iat: float = 0.0
    max_iat: float = 0.0
    cv_iat: float = 0.0            # coefficient of variation
    burst_score: float = 0.0       # fraction of IATs below burst threshold
    rate: float = 0.0              # events per second
    acceleration: float = 0.0      # rate change vs previous window
    entropy_tool_dist: float = 0.0 # Shannon entropy of tool distribution

    def to_vector(self) -> np.ndarray:
        return np.array([
            self.mean_iat, self.std_iat, self.min_iat, self.max_iat,
            self.cv_iat, self.burst_score, self.rate,
            self.acceleration, self.entropy_tool_dist,
        ])


class TemporalExtractor:
    """Sliding-window temporal feature extractor."""

    def __init__(self, window_size: int = 10, burst_threshold: float = 0.1):
        self.window_size = window_size
        self.burst_threshold = burst_threshold
        self._prev_rate: float = 0.0

    def extract(self, events: list[CallEvent]) -> TemporalFeatures:
        if len(events) < 2:
            return TemporalFeatures()

        timestamps = np.array([e.timestamp for e in events])
        iats = np.diff(timestamps)

        if len(iats) == 0:
            return TemporalFeatures()

        mean_iat = float(np.mean(iats))
        std_iat = float(np.std(iats))
        cv_iat = std_iat / mean_iat if mean_iat > 1e-9 else 0.0
        burst_score = float(np.mean(iats < self.burst_threshold))

        duration = timestamps[-1] - timestamps[0]
        rate = len(events) / duration if duration > 1e-9 else 0.0
        acceleration = rate - self._prev_rate
        self._prev_rate = rate

        # Shannon entropy of tool name distribution
        tool_names = [e.tool_name for e in events]
        unique, counts = np.unique(tool_names, return_counts=True)
        probs = counts / counts.sum()
        entropy = float(-np.sum(probs * np.log2(probs + 1e-12)))

        return TemporalFeatures(
            mean_iat=mean_iat,
            std_iat=std_iat,
            min_iat=float(np.min(iats)),
            max_iat=float(np.max(iats)),
            cv_iat=cv_iat,
            burst_score=burst_score,
            rate=rate,
            acceleration=acceleration,
            entropy_tool_dist=entropy,
        )

    def extract_sliding(self, events: list[CallEvent]) -> list[TemporalFeatures]:
        """Extract features over sliding windows."""
        results = []
        for i in range(len(events) - self.window_size + 1):
            window = events[i : i + self.window_size]
            results.append(self.extract(window))
        return results
