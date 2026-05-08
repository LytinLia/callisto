"""Comparative evaluation: CALLISTO vs. three paper-inspired baselines."""

from __future__ import annotations

import time
import json
import numpy as np
from pathlib import Path

from callisto.config import CallistoConfig
from callisto.engine import CallistoEngine
from callisto.attacks.simulator import generate_dataset
from callisto.evaluation.metrics import (
    evaluate_detector, per_attack_metrics, detection_latency, EvalMetrics,
)
from callisto.evaluation.baselines.detectors import (
    RuleBasedDetector, IsolationForestDetector,
)
from callisto.evaluation.baselines.paper_baselines import (
    Pro2GuardDetector, AMDMDetector, STACDefenseDetector,
)
from callisto.collector.models import Session


def _format(m: EvalMetrics) -> dict:
    return {
        "precision": round(m.precision, 4),
        "recall": round(m.recall, 4),
        "f1": round(m.f1, 4),
        "fpr": round(m.fpr, 4),
        "accuracy": round(m.accuracy, 4),
        "tp": m.tp, "fp": m.fp, "tn": m.tn, "fn": m.fn,
    }


def run_comparative_evaluation(
    n_benign: int = 100,
    n_per_attack: int = 30,
    seed: int = 42,
    output_dir: str = "./eval_results",
) -> dict:
    print("=" * 72)
    print("  CALLISTO Comparative Evaluation")
    print("  vs. Pro2Guard / AMDM / STAC-Defense / Rule / IsolationForest")
    print("=" * 72)

    print("\n[1/7] Generating dataset...")
    sessions = generate_dataset(n_benign=n_benign, n_per_attack=n_per_attack, seed=seed)
    benign = [s for s in sessions if all(e.label.value == "benign" for e in s.events)]
    print(f"  Total: {len(sessions)} sessions ({len(benign)} benign, {len(sessions)-len(benign)} attack)")

    results = {}
    config = CallistoConfig(seed=seed)

    # --- CALLISTO ---
    print("\n[2/7] Running CALLISTO...")
    engine = CallistoEngine(config)
    benign_train = benign[:50]
    engine.train_fingerprints(benign_train)
    t0 = time.time()
    callisto_alerts = [engine.analyze_session(s) for s in sessions]
    callisto_time = time.time() - t0
    m = evaluate_detector(sessions, callisto_alerts)
    pa = per_attack_metrics(sessions, callisto_alerts)
    lat = detection_latency(sessions, callisto_alerts)
    results["CALLISTO"] = {
        "overall": _format(m),
        "per_attack": {k: _format(v) for k, v in pa.items()},
        "mean_latency": round(float(np.mean(lat)), 2) if lat else None,
        "runtime_ms": round(callisto_time * 1000, 1),
        "ms_per_session": round(callisto_time / len(sessions) * 1000, 2),
    }
    print(f"  F1={m.f1:.4f}  Prec={m.precision:.4f}  Rec={m.recall:.4f}  FPR={m.fpr:.4f}  ({callisto_time*1000:.0f}ms)")

    # --- Pro2Guard ---
    print("\n[3/7] Running Pro2Guard (DTMC)...")
    pg = Pro2GuardDetector(threshold=0.3)
    pg.fit(benign_train)
    t0 = time.time()
    pg_alerts = [pg.detect(s) for s in sessions]
    pg_time = time.time() - t0
    m = evaluate_detector(sessions, pg_alerts)
    pa = per_attack_metrics(sessions, pg_alerts)
    lat = detection_latency(sessions, pg_alerts)
    results["Pro2Guard"] = {
        "overall": _format(m),
        "per_attack": {k: _format(v) for k, v in pa.items()},
        "mean_latency": round(float(np.mean(lat)), 2) if lat else None,
        "runtime_ms": round(pg_time * 1000, 1),
        "ms_per_session": round(pg_time / len(sessions) * 1000, 2),
    }
    print(f"  F1={m.f1:.4f}  Prec={m.precision:.4f}  Rec={m.recall:.4f}  FPR={m.fpr:.4f}  ({pg_time*1000:.0f}ms)")

    # --- AMDM ---
    print("\n[4/7] Running AMDM (Adaptive Multi-Dim)...")
    amdm = AMDMDetector(k_sigma=3.0, min_dims_anomalous=2)
    amdm.fit(benign_train)
    t0 = time.time()
    amdm_alerts = [amdm.detect(s) for s in sessions]
    amdm_time = time.time() - t0
    m = evaluate_detector(sessions, amdm_alerts)
    pa = per_attack_metrics(sessions, amdm_alerts)
    lat = detection_latency(sessions, amdm_alerts)
    results["AMDM"] = {
        "overall": _format(m),
        "per_attack": {k: _format(v) for k, v in pa.items()},
        "mean_latency": round(float(np.mean(lat)), 2) if lat else None,
        "runtime_ms": round(amdm_time * 1000, 1),
        "ms_per_session": round(amdm_time / len(sessions) * 1000, 2),
    }
    print(f"  F1={m.f1:.4f}  Prec={m.precision:.4f}  Rec={m.recall:.4f}  FPR={m.fpr:.4f}  ({amdm_time*1000:.0f}ms)")

    # --- STAC-Defense ---
    print("\n[5/7] Running STAC-Defense (Chain Pattern)...")
    stac = STACDefenseDetector(max_gap=2)
    t0 = time.time()
    stac_alerts = [stac.detect(s) for s in sessions]
    stac_time = time.time() - t0
    m = evaluate_detector(sessions, stac_alerts)
    pa = per_attack_metrics(sessions, stac_alerts)
    lat = detection_latency(sessions, stac_alerts)
    results["STAC-Defense"] = {
        "overall": _format(m),
        "per_attack": {k: _format(v) for k, v in pa.items()},
        "mean_latency": round(float(np.mean(lat)), 2) if lat else None,
        "runtime_ms": round(stac_time * 1000, 1),
        "ms_per_session": round(stac_time / len(sessions) * 1000, 2),
    }
    print(f"  F1={m.f1:.4f}  Prec={m.precision:.4f}  Rec={m.recall:.4f}  FPR={m.fpr:.4f}  ({stac_time*1000:.0f}ms)")

    # --- Rule Baseline ---
    print("\n[6/7] Running Rule Baseline...")
    rule = RuleBasedDetector()
    t0 = time.time()
    rule_alerts = [rule.detect(s) for s in sessions]
    rule_time = time.time() - t0
    m = evaluate_detector(sessions, rule_alerts)
    results["Rule"] = {
        "overall": _format(m),
        "runtime_ms": round(rule_time * 1000, 1),
    }
    print(f"  F1={m.f1:.4f}  Prec={m.precision:.4f}  Rec={m.recall:.4f}  FPR={m.fpr:.4f}  ({rule_time*1000:.0f}ms)")

    # --- IsolationForest ---
    print("\n[7/7] Running IsolationForest...")
    ifo = IsolationForestDetector()
    ifo.fit(benign_train)
    t0 = time.time()
    ifo_alerts = [ifo.detect(s) for s in sessions]
    ifo_time = time.time() - t0
    m = evaluate_detector(sessions, ifo_alerts)
    results["IForest"] = {
        "overall": _format(m),
        "runtime_ms": round(ifo_time * 1000, 1),
    }
    print(f"  F1={m.f1:.4f}  Prec={m.precision:.4f}  Rec={m.recall:.4f}  FPR={m.fpr:.4f}  ({ifo_time*1000:.0f}ms)")

    # --- Summary Table ---
    print("\n" + "=" * 82)
    print(f"{'Detector':<16} {'Precision':>9} {'Recall':>9} {'F1':>9} {'FPR':>9} {'ms/sess':>9}")
    print("-" * 82)
    for name, r in results.items():
        o = r["overall"]
        ms = r.get("ms_per_session", r.get("runtime_ms", 0))
        print(f"{name:<16} {o['precision']:>9.4f} {o['recall']:>9.4f} {o['f1']:>9.4f} {o['fpr']:>9.4f} {ms:>9.2f}")
    print("=" * 82)

    # --- Per-Attack Breakdown for top detectors ---
    print("\n--- Per-Attack F1 Breakdown ---")
    attack_names = set()
    for name in ["CALLISTO", "Pro2Guard", "AMDM", "STAC-Defense"]:
        if "per_attack" in results[name]:
            attack_names.update(results[name]["per_attack"].keys())
    attack_names = sorted(attack_names - {"benign"})

    header = f"{'Attack':<20}"
    for name in ["CALLISTO", "Pro2Guard", "AMDM", "STAC-Defense"]:
        header += f" {name:>13}"
    print(header)
    print("-" * (20 + 14 * 4))
    for atype in attack_names:
        row = f"{atype:<20}"
        for name in ["CALLISTO", "Pro2Guard", "AMDM", "STAC-Defense"]:
            pa = results[name].get("per_attack", {})
            if atype in pa:
                row += f" {pa[atype]['f1']:>13.4f}"
            else:
                row += f" {'N/A':>13}"
        print(row)

    # Save
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "comparative_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {out / 'comparative_results.json'}")

    return results


if __name__ == "__main__":
    run_comparative_evaluation()
