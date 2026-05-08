"""Hyperparameter sensitivity analysis for CALLISTO detection system."""

from __future__ import annotations

import json
import time
from pathlib import Path

from callisto.config import CallistoConfig
from callisto.engine import CallistoEngine
from callisto.attacks.simulator import generate_dataset
from callisto.evaluation.metrics import evaluate_detector, EvalMetrics
from callisto.collector.models import Session


SWEEPS: dict[str, list] = {
    "bocpd_threshold": [0.1, 0.3, 0.5, 0.7, 0.9],
    "crs_threshold": [0.3, 0.5, 0.7, 0.9],
    "csbf_distance_threshold": [1.0, 2.0, 3.0, 4.0, 5.0],
    "crs_samples": [5, 10, 30, 50, 100],
    "bocpd_run_length_cap": [10, 30, 50, 100, 200],
}

TIMED_PARAMS = {"crs_samples", "bocpd_run_length_cap"}


def _run_single(
    sessions: list[Session],
    benign_train: list[Session],
    param_name: str,
    param_value,
) -> dict:
    """Run engine with one parameter changed, return metrics dict."""
    overrides = {param_name: param_value}
    config = CallistoConfig(**overrides)
    engine = CallistoEngine(config)
    engine.train_fingerprints(benign_train)

    t0 = time.time()
    alerts_per_session = [engine.analyze_session(s) for s in sessions]
    runtime = time.time() - t0

    m = evaluate_detector(sessions, alerts_per_session)
    result = {
        "value": param_value,
        "f1": round(m.f1, 4),
        "precision": round(m.precision, 4),
        "recall": round(m.recall, 4),
        "fpr": round(m.fpr, 4),
    }
    if param_name in TIMED_PARAMS:
        result["runtime_s"] = round(runtime, 3)
    return result


def _print_table(param_name: str, rows: list[dict]) -> None:
    """Print a formatted table for one parameter sweep."""
    timed = param_name in TIMED_PARAMS
    header = f"{'Value':>10} {'F1':>8} {'Prec':>8} {'Recall':>8} {'FPR':>8}"
    if timed:
        header += f" {'Time(s)':>9}"

    print(f"\n{'=' * len(header)}")
    print(f"Sweep: {param_name}")
    print(f"{'-' * len(header)}")
    print(header)
    print(f"{'-' * len(header)}")
    for r in rows:
        line = (
            f"{r['value']:>10} {r['f1']:>8.4f} {r['precision']:>8.4f} "
            f"{r['recall']:>8.4f} {r['fpr']:>8.4f}"
        )
        if timed:
            line += f" {r['runtime_s']:>9.3f}"
        print(line)
    print(f"{'=' * len(header)}")


def run_sensitivity_analysis(
    n_benign: int = 100,
    n_per_attack: int = 30,
    seed: int = 42,
    output_dir: str = "./eval_results",
) -> dict:
    """Run hyperparameter sensitivity sweeps and save results."""
    print("[Sensitivity] Generating dataset...")
    sessions = generate_dataset(n_benign=n_benign, n_per_attack=n_per_attack, seed=seed)
    print(f"  Total sessions: {len(sessions)}")

    benign_train = [
        s for s in sessions
        if all(e.label.value == "benign" for e in s.events)
    ][:50]

    all_results: dict[str, list[dict]] = {}

    for param_name, values in SWEEPS.items():
        print(f"\n[Sensitivity] Sweeping {param_name} ({len(values)} values)...")
        rows = []
        for val in values:
            row = _run_single(sessions, benign_train, param_name, val)
            rows.append(row)
            print(f"  {param_name}={val} -> F1={row['f1']:.4f}")
        all_results[param_name] = rows
        _print_table(param_name, rows)

    # Save results
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    out_path = out / "sensitivity.json"
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n[Sensitivity] Results saved to {out_path}")

    return all_results


if __name__ == "__main__":
    run_sensitivity_analysis()
