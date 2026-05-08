"""Scalability and performance experiments for the CALLISTO detection system."""

from __future__ import annotations

import json
import time
import tracemalloc
import numpy as np
from pathlib import Path

from callisto.config import CallistoConfig
from callisto.engine import CallistoEngine
from callisto.attacks.simulator import (
    generate_dataset,
    generate_benign_session,
    generate_rate_flood,
)
from callisto.evaluation.metrics import (
    evaluate_detector,
    detection_latency,
    per_attack_metrics,
    EvalMetrics,
)
from callisto.evaluation.baselines.paper_baselines import (
    Pro2GuardDetector,
    AMDMDetector,
    STACDefenseDetector,
)
from callisto.collector.models import Session, AttackType


def _fmt(m: EvalMetrics) -> dict:
    return {"precision": round(m.precision, 4), "recall": round(m.recall, 4),
            "f1": round(m.f1, 4), "fpr": round(m.fpr, 4)}


# ── 1. Session length scaling ───────────────────────────────────────────────

def run_session_length_scaling(output_dir: str = "./eval_results") -> dict:
    """Measure how detection cost and quality scale with session length."""
    print("=" * 68)
    print("  Experiment 1: Session Length Scaling")
    print("=" * 68)

    lengths = [5, 10, 20, 30, 50, 75, 100, 150, 200, 300, 500]
    results = {}

    for n in lengths:
        burst = min(20, n // 3)
        benign = [generate_benign_session(n_calls=n, seed=i) for i in range(20)]
        attacks = [generate_rate_flood(n_calls=n, burst_size=max(1, burst), seed=1000 + i) for i in range(10)]
        all_sessions = benign + attacks

        engine = CallistoEngine(CallistoConfig())
        engine.train_fingerprints(benign[:10])

        t0 = time.perf_counter()
        alerts = [engine.analyze_session(s) for s in all_sessions]
        elapsed = time.perf_counter() - t0

        m = evaluate_detector(all_sessions, alerts)
        ms_per = elapsed / len(all_sessions) * 1000
        results[n] = {"ms_per_session": round(ms_per, 3), "f1": round(m.f1, 4)}

    print(f"\n{'n_calls':>10} | {'ms/session':>12} | {'F1':>8}")
    print("-" * 38)
    for n in lengths:
        r = results[n]
        print(f"{n:>10} | {r['ms_per_session']:>12.3f} | {r['f1']:>8.4f}")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "session_length_scaling.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved to {out / 'session_length_scaling.json'}")
    return results


# ── 2. Throughput scaling ────────────────────────────────────────────────────

def run_throughput_scaling(output_dir: str = "./eval_results") -> dict:
    """Measure throughput as the number of sessions grows."""
    print("=" * 68)
    print("  Experiment 2: Throughput Scaling")
    print("=" * 68)

    counts = [10, 50, 100, 200, 500, 1000]
    results = {}

    for count in counts:
        n_benign = int(count * 0.8)
        n_per_attack = max(1, int(count * 0.2) // 6)  # 6 attack types
        sessions = generate_dataset(n_benign=n_benign, n_per_attack=n_per_attack, seed=42)

        benign_train = [s for s in sessions
                        if all(e.label == AttackType.BENIGN for e in s.events)][:50]
        engine = CallistoEngine(CallistoConfig())
        engine.train_fingerprints(benign_train)

        t0 = time.perf_counter()
        alerts = [engine.analyze_session(s) for s in sessions]
        elapsed = time.perf_counter() - t0

        ms_per = elapsed / len(sessions) * 1000
        throughput = len(sessions) / elapsed if elapsed > 0 else 0
        results[count] = {
            "actual_sessions": len(sessions),
            "total_ms": round(elapsed * 1000, 1),
            "ms_per_session": round(ms_per, 3),
            "sessions_per_sec": round(throughput, 1),
        }

    print(f"\n{'target':>8} | {'actual':>8} | {'total_ms':>10} | {'ms/sess':>10} | {'sess/sec':>10}")
    print("-" * 58)
    for c in counts:
        r = results[c]
        print(f"{c:>8} | {r['actual_sessions']:>8} | {r['total_ms']:>10.1f} | "
              f"{r['ms_per_session']:>10.3f} | {r['sessions_per_sec']:>10.1f}")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "throughput_scaling.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved to {out / 'throughput_scaling.json'}")
    return results


# ── 3. Detection latency analysis ───────────────────────────────────────────

def run_latency_analysis(output_dir: str = "./eval_results") -> dict:
    """Detailed detection latency analysis across detectors and attack types."""
    print("=" * 68)
    print("  Experiment 3: Detection Latency Analysis")
    print("=" * 68)

    sessions = generate_dataset(n_benign=100, n_per_attack=30, seed=42)
    benign_train = [s for s in sessions
                    if all(e.label == AttackType.BENIGN for e in s.events)][:50]

    # Set up detectors
    engine = CallistoEngine(CallistoConfig())
    engine.train_fingerprints(benign_train)

    pg = Pro2GuardDetector(threshold=0.3)
    pg.fit(benign_train)

    amdm = AMDMDetector(k_sigma=3.0, min_dims_anomalous=2)
    amdm.fit(benign_train)

    stac = STACDefenseDetector(max_gap=2)

    detectors = {
        "CALLISTO": lambda s: engine.analyze_session(s),
        "Pro2Guard": lambda s: pg.detect(s),
        "AMDM": lambda s: amdm.detect(s),
        "STAC-Defense": lambda s: stac.detect(s),
    }

    results = {}
    for name, detect_fn in detectors.items():
        alerts_all = [detect_fn(s) for s in sessions]
        lat = detection_latency(sessions, alerts_all)
        lat_arr = np.array(lat) if lat else np.array([])

        summary = {
            "mean": round(float(lat_arr.mean()), 2) if len(lat_arr) else None,
            "median": round(float(np.median(lat_arr)), 2) if len(lat_arr) else None,
            "min": int(lat_arr.min()) if len(lat_arr) else None,
            "max": int(lat_arr.max()) if len(lat_arr) else None,
            "std": round(float(lat_arr.std()), 2) if len(lat_arr) else None,
            "n_tp": len(lat),
        }

        # Per-attack-type latency
        pa_latency = {}
        for session, alerts in zip(sessions, alerts_all):
            atypes = set(e.label for e in session.events if e.label != AttackType.BENIGN)
            if not atypes or not alerts:
                continue
            atype = atypes.pop().value
            attack_events = [e for e in session.events if e.label != AttackType.BENIGN]
            first_alert_time = min(a.timestamp for a in alerts)
            steps = sum(1 for e in attack_events if e.timestamp < first_alert_time)
            pa_latency.setdefault(atype, []).append(steps)

        per_attack = {}
        for atype, lats in pa_latency.items():
            arr = np.array(lats)
            per_attack[atype] = {
                "mean": round(float(arr.mean()), 2),
                "median": round(float(np.median(arr)), 2),
                "count": len(lats),
            }
        summary["per_attack"] = per_attack
        results[name] = summary

    # Fine-grained CALLISTO latency: events before first alert
    callisto_alerts = [engine.analyze_session(s) for s in sessions]
    fine_grained = []
    for session, alerts in zip(sessions, callisto_alerts):
        is_attack = any(e.label != AttackType.BENIGN for e in session.events)
        if not is_attack or not alerts:
            continue
        first_alert_time = min(a.timestamp for a in alerts)
        events_before = sum(1 for e in session.events if e.timestamp < first_alert_time)
        fine_grained.append(events_before)
    fg_arr = np.array(fine_grained) if fine_grained else np.array([])
    results["CALLISTO"]["fine_grained_events_before_alert"] = {
        "mean": round(float(fg_arr.mean()), 2) if len(fg_arr) else None,
        "median": round(float(np.median(fg_arr)), 2) if len(fg_arr) else None,
        "min": int(fg_arr.min()) if len(fg_arr) else None,
        "max": int(fg_arr.max()) if len(fg_arr) else None,
    }

    # Print summary tables
    print(f"\n{'Detector':<14} | {'Mean':>6} | {'Median':>6} | {'Min':>4} | {'Max':>4} | {'Std':>6} | {'N_TP':>5}")
    print("-" * 60)
    for name, r in results.items():
        m, md = r["mean"], r["median"]
        mn, mx, sd = r["min"], r["max"], r["std"]
        print(f"{name:<14} | {m if m is not None else 'N/A':>6} | {md if md is not None else 'N/A':>6} | "
              f"{mn if mn is not None else 'N/A':>4} | {mx if mx is not None else 'N/A':>4} | "
              f"{sd if sd is not None else 'N/A':>6} | {r['n_tp']:>5}")

    print("\n--- Per-Attack-Type Mean Latency ---")
    all_atypes = sorted(set(a for r in results.values() for a in r.get("per_attack", {})))
    header = f"{'Attack':<22}"
    for name in results:
        header += f" {name:>13}"
    print(header)
    print("-" * (22 + 14 * len(results)))
    for atype in all_atypes:
        row = f"{atype:<22}"
        for name in results:
            pa = results[name].get("per_attack", {})
            if atype in pa:
                row += f" {pa[atype]['mean']:>13.2f}"
            else:
                row += f" {'N/A':>13}"
        print(row)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "latency_analysis.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved to {out / 'latency_analysis.json'}")
    return results


# ── 4. Embedding dimension scaling ──────────────────────────────────────────

def run_embedding_dim_scaling(output_dir: str = "./eval_results") -> dict:
    """Measure impact of embedding dimension on F1 and speed."""
    print("=" * 68)
    print("  Experiment 4: Embedding Dimension Scaling")
    print("=" * 68)

    dims = [8, 16, 32, 64, 128, 256]
    sessions = generate_dataset(n_benign=100, n_per_attack=30, seed=42)
    benign_train = [s for s in sessions
                    if all(e.label == AttackType.BENIGN for e in s.events)][:50]
    results = {}

    for dim in dims:
        config = CallistoConfig(embedding_dim=dim)
        engine = CallistoEngine(config)
        engine.train_fingerprints(benign_train)

        t0 = time.perf_counter()
        alerts = [engine.analyze_session(s) for s in sessions]
        elapsed = time.perf_counter() - t0

        m = evaluate_detector(sessions, alerts)
        ms_per = elapsed / len(sessions) * 1000
        results[dim] = {"f1": round(m.f1, 4), "ms_per_session": round(ms_per, 3)}

    print(f"\n{'dim':>8} | {'F1':>8} | {'ms/session':>12}")
    print("-" * 34)
    for dim in dims:
        r = results[dim]
        print(f"{dim:>8} | {r['f1']:>8.4f} | {r['ms_per_session']:>12.3f}")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "embedding_dim_scaling.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved to {out / 'embedding_dim_scaling.json'}")
    return results


# ── 5. Memory profiling ─────────────────────────────────────────────────────

def run_memory_profile(output_dir: str = "./eval_results") -> dict:
    """Measure peak memory usage during detection for each detector."""
    print("=" * 68)
    print("  Experiment 5: Memory Profiling")
    print("=" * 68)

    sessions = generate_dataset(n_benign=100, n_per_attack=30, seed=42)
    benign_train = [s for s in sessions
                    if all(e.label == AttackType.BENIGN for e in s.events)][:50]

    # Pre-train all detectors before measuring memory
    engine = CallistoEngine(CallistoConfig())
    engine.train_fingerprints(benign_train)

    pg = Pro2GuardDetector(threshold=0.3)
    pg.fit(benign_train)

    amdm = AMDMDetector(k_sigma=3.0, min_dims_anomalous=2)
    amdm.fit(benign_train)

    stac = STACDefenseDetector(max_gap=2)

    detectors = {
        "CALLISTO": lambda s: engine.analyze_session(s),
        "Pro2Guard": lambda s: pg.detect(s),
        "AMDM": lambda s: amdm.detect(s),
        "STAC-Defense": lambda s: stac.detect(s),
    }

    results = {}
    for name, detect_fn in detectors.items():
        tracemalloc.start()
        _ = [detect_fn(s) for s in sessions]
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        results[name] = {"peak_memory_kb": round(peak / 1024, 1)}

    print(f"\n{'Detector':<14} | {'Peak Memory (KB)':>16}")
    print("-" * 35)
    for name, r in results.items():
        print(f"{name:<14} | {r['peak_memory_kb']:>16.1f}")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "memory_profile.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved to {out / 'memory_profile.json'}")
    return results


# ── Run all ──────────────────────────────────────────────────────────────────

def run_all_scalability(output_dir: str = "./eval_results") -> dict:
    """Run all scalability experiments and save combined results."""
    print("\n" + "#" * 68)
    print("#  CALLISTO Scalability & Performance Experiments")
    print("#" * 68 + "\n")

    all_results = {}
    all_results["session_length_scaling"] = run_session_length_scaling(output_dir)
    print()
    all_results["throughput_scaling"] = run_throughput_scaling(output_dir)
    print()
    all_results["latency_analysis"] = run_latency_analysis(output_dir)
    print()
    all_results["embedding_dim_scaling"] = run_embedding_dim_scaling(output_dir)
    print()
    all_results["memory_profile"] = run_memory_profile(output_dir)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "scalability_all.json", "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nAll results saved to {out / 'scalability_all.json'}")
    return all_results


if __name__ == "__main__":
    run_all_scalability()
