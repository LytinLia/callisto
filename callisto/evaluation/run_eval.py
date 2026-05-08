"""Evaluation runner — runs CALLISTO and baselines on synthetic datasets."""

from __future__ import annotations

import time
import json
import numpy as np
from pathlib import Path

from callisto.config import CallistoConfig
from callisto.engine import CallistoEngine
from callisto.attacks.simulator import generate_dataset, generate_benign_session
from callisto.evaluation.metrics import (
    evaluate_detector, per_attack_metrics, detection_latency, EvalMetrics,
)
from callisto.evaluation.baselines.detectors import (
    RuleBasedDetector, IsolationForestDetector, LOFDetector,
)
from callisto.collector.models import Session


def run_callisto(sessions: list[Session], config: CallistoConfig) -> list[list]:
    """Run CALLISTO engine on all sessions, return alerts per session."""
    engine = CallistoEngine(config)
    # Pre-train fingerprints with first batch of benign sessions
    benign = [s for s in sessions if all(
        e.label.value == "benign" for e in s.events
    )][:50]
    engine.train_fingerprints(benign)

    results = []
    for s in sessions:
        alerts = engine.analyze_session(s)
        results.append(alerts)
    return results


def run_baseline(name: str, sessions: list[Session]) -> list[list]:
    """Run a baseline detector on all sessions."""
    benign = [s for s in sessions if all(
        e.label.value == "benign" for e in s.events
    )]

    if name == "rule":
        det = RuleBasedDetector()
        return [det.detect(s) for s in sessions]
    elif name == "iforest":
        det = IsolationForestDetector()
        det.fit(benign[:50])
        return [det.detect(s) for s in sessions]
    elif name == "lof":
        det = LOFDetector()
        det.fit(benign[:50])
        return [det.detect(s) for s in sessions]
    return [[] for _ in sessions]


def format_metrics(m: EvalMetrics) -> dict:
    return {
        "precision": round(m.precision, 4),
        "recall": round(m.recall, 4),
        "f1": round(m.f1, 4),
        "fpr": round(m.fpr, 4),
        "accuracy": round(m.accuracy, 4),
        "tp": m.tp, "fp": m.fp, "tn": m.tn, "fn": m.fn,
    }


def run_evaluation(
    n_benign: int = 100,
    n_per_attack: int = 30,
    output_dir: str = "./eval_results",
    seed: int = 42,
) -> dict:
    """Run full evaluation: CALLISTO + all baselines."""
    print("[CALLISTO Eval] Generating dataset...")
    sessions = generate_dataset(n_benign=n_benign, n_per_attack=n_per_attack, seed=seed)
    print(f"  Total sessions: {len(sessions)}")

    config = CallistoConfig(seed=seed)
    results = {}

    # --- CALLISTO ---
    print("[CALLISTO Eval] Running CALLISTO...")
    t0 = time.time()
    callisto_alerts = run_callisto(sessions, config)
    callisto_time = time.time() - t0
    m = evaluate_detector(sessions, callisto_alerts)
    per_attack = per_attack_metrics(sessions, callisto_alerts)
    latencies = detection_latency(sessions, callisto_alerts)

    results["callisto"] = {
        "overall": format_metrics(m),
        "per_attack": {k: format_metrics(v) for k, v in per_attack.items()},
        "mean_latency": round(float(np.mean(latencies)), 2) if latencies else None,
        "runtime_s": round(callisto_time, 3),
        "avg_ms_per_session": round(callisto_time / len(sessions) * 1000, 2),
    }
    print(f"  CALLISTO F1={m.f1:.4f}, Precision={m.precision:.4f}, Recall={m.recall:.4f}")

    # --- Baselines ---
    for bname in ["rule", "iforest", "lof"]:
        print(f"[CALLISTO Eval] Running baseline: {bname}...")
        t0 = time.time()
        b_alerts = run_baseline(bname, sessions)
        b_time = time.time() - t0
        bm = evaluate_detector(sessions, b_alerts)
        b_per_attack = per_attack_metrics(sessions, b_alerts)
        b_latencies = detection_latency(sessions, b_alerts)

        results[bname] = {
            "overall": format_metrics(bm),
            "per_attack": {k: format_metrics(v) for k, v in b_per_attack.items()},
            "mean_latency": round(float(np.mean(b_latencies)), 2) if b_latencies else None,
            "runtime_s": round(b_time, 3),
        }
        print(f"  {bname} F1={bm.f1:.4f}, Precision={bm.precision:.4f}, Recall={bm.recall:.4f}")

    # --- Save results ---
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "results.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[CALLISTO Eval] Results saved to {out / 'results.json'}")

    # --- Print summary table ---
    print("\n" + "=" * 70)
    print(f"{'Detector':<15} {'Precision':>10} {'Recall':>10} {'F1':>10} {'FPR':>10}")
    print("-" * 70)
    for name, r in results.items():
        o = r["overall"]
        print(f"{name:<15} {o['precision']:>10.4f} {o['recall']:>10.4f} {o['f1']:>10.4f} {o['fpr']:>10.4f}")
    print("=" * 70)

    return results


if __name__ == "__main__":
    run_evaluation()
