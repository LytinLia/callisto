"""Evaluation metrics for CALLISTO."""

from __future__ import annotations

import numpy as np
from dataclasses import dataclass
from collections import Counter

from callisto.collector.models import Session, Alert, AttackType


@dataclass
class EvalMetrics:
    """Aggregate evaluation metrics."""

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / total if total > 0 else 0.0


def evaluate_detector(
    sessions: list[Session],
    alerts_per_session: list[list[Alert]],
) -> EvalMetrics:
    """Evaluate detection results against ground-truth labels.

    A session is positive (attack) if any of its events has a non-BENIGN label.
    A session is detected if the detector produced at least one alert.
    """
    metrics = EvalMetrics()
    for session, alerts in zip(sessions, alerts_per_session):
        is_attack = any(e.label != AttackType.BENIGN for e in session.events)
        is_detected = len(alerts) > 0

        if is_attack and is_detected:
            metrics.tp += 1
        elif is_attack and not is_detected:
            metrics.fn += 1
        elif not is_attack and is_detected:
            metrics.fp += 1
        else:
            metrics.tn += 1

    return metrics


def per_attack_metrics(
    sessions: list[Session],
    alerts_per_session: list[list[Alert]],
) -> dict[str, EvalMetrics]:
    """Compute metrics broken down by attack type."""
    results: dict[str, EvalMetrics] = {}
    for session, alerts in zip(sessions, alerts_per_session):
        attack_types = set(e.label for e in session.events if e.label != AttackType.BENIGN)
        if not attack_types:
            atype = "benign"
        else:
            atype = attack_types.pop().value

        if atype not in results:
            results[atype] = EvalMetrics()

        is_attack = atype != "benign"
        is_detected = len(alerts) > 0

        m = results[atype]
        if is_attack and is_detected:
            m.tp += 1
        elif is_attack and not is_detected:
            m.fn += 1
        elif not is_attack and is_detected:
            m.fp += 1
        else:
            m.tn += 1

    return results


def detection_latency(
    sessions: list[Session],
    alerts_per_session: list[list[Alert]],
) -> list[int]:
    """Compute detection latency: index of first attack event in the session.

    For each true-positive session, latency = position of the first attack
    event in the full event list (0-indexed). This measures how deep into
    the session the attack begins — a proxy for how early the detector
    *could* have caught it.

    For detectors that process sessions as a whole (batch mode), this is
    the best available metric since all alerts share the same wall-clock
    timestamp.
    """
    latencies = []
    for session, alerts in zip(sessions, alerts_per_session):
        attack_events = [e for e in session.events if e.label != AttackType.BENIGN]
        if not attack_events or not alerts:
            continue
        # Find the index of the first attack event in the full event list
        all_events = session.events
        first_attack_idx = next(
            i for i, e in enumerate(all_events) if e.label != AttackType.BENIGN
        )
        latencies.append(first_attack_idx)
    return latencies


def detection_latency_online(
    sessions: list[Session],
    alerts_per_session: list[list[Alert]],
) -> list[int]:
    """Compute online detection latency using trigger_events.

    For detectors that populate alert.trigger_events with event IDs,
    latency = number of events processed before the first triggered event.
    Falls back to detection_latency if trigger_events is empty.
    """
    latencies = []
    for session, alerts in zip(sessions, alerts_per_session):
        attack_events = [e for e in session.events if e.label != AttackType.BENIGN]
        if not attack_events or not alerts:
            continue

        # Collect all trigger event IDs from alerts
        trigger_ids = set()
        for a in alerts:
            trigger_ids.update(a.trigger_events)

        if trigger_ids:
            # Find earliest triggered event position
            all_events = session.events
            for i, e in enumerate(all_events):
                if e.event_id in trigger_ids:
                    latencies.append(i)
                    break
            else:
                # trigger IDs don't match any event — fall back
                first_attack_idx = next(
                    i for i, e in enumerate(all_events) if e.label != AttackType.BENIGN
                )
                latencies.append(first_attack_idx)
        else:
            # No trigger events — use first attack event index
            all_events = session.events
            first_attack_idx = next(
                i for i, e in enumerate(all_events) if e.label != AttackType.BENIGN
            )
            latencies.append(first_attack_idx)
    return latencies
