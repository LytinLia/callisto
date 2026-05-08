"""Statistical significance testing and ROC/AUC analysis for CALLISTO."""

from __future__ import annotations

import json
import numpy as np
from pathlib import Path

from scipy import stats

from callisto.engine import CallistoEngine
from callisto.attacks.simulator import generate_dataset
from callisto.evaluation.metrics import evaluate_detector, EvalMetrics
from callisto.evaluation.baselines.paper_baselines import (
    Pro2GuardDetector,
    AMDMDetector,
    STACDefenseDetector,
)
from callisto.collector.models import Session, Alert, AttackType


def _is_attack_session(session: Session) -> bool:
    return any(e.label != AttackType.BENIGN for e in session.events)


def _max_alert_score(alerts: list[Alert]) -> float:
    return max((a.score for a in alerts), default=0.0)


def _get_benign_sessions(sessions: list[Session]) -> list[Session]:
    return [s for s in sessions if not _is_attack_session(s)]


# ---------------------------------------------------------------------------
# Detector helpers
# ---------------------------------------------------------------------------

def _run_all_detectors(
    sessions: list[Session],
    train_sessions: list[Session],
) -> dict[str, list[list[Alert]]]:
    """Run CALLISTO + all baselines, return alerts per session per detector."""
    # CALLISTO
    engine = CallistoEngine()
    engine.train_fingerprints(train_sessions)
    callisto_alerts = [engine.analyze_session(s) for s in sessions]

    # Pro2Guard
    p2g = Pro2GuardDetector(threshold=0.3)
    p2g.fit(train_sessions)
    p2g_alerts = [p2g.detect(s) for s in sessions]

    # AMDM
    amdm = AMDMDetector(k_sigma=3.0, min_dims_anomalous=2)
    amdm.fit(train_sessions)
    amdm_alerts = [amdm.detect(s) for s in sessions]

    # STAC
    stac = STACDefenseDetector(max_gap=2)
    stac_alerts = [stac.detect(s) for s in sessions]

    return {
        "CALLISTO": callisto_alerts,
        "Pro2Guard": p2g_alerts,
        "AMDM": amdm_alerts,
        "STAC": stac_alerts,
    }


def _collect_metrics(sessions: list[Session], alerts_map: dict[str, list[list[Alert]]]) -> dict[str, EvalMetrics]:
    return {name: evaluate_detector(sessions, alerts) for name, alerts in alerts_map.items()}


# ---------------------------------------------------------------------------
# 1. Multi-seed statistical significance
# ---------------------------------------------------------------------------

def run_statistical_tests(
    n_seeds: int = 10,
    n_benign: int = 100,
    n_per_attack: int = 30,
    output_dir: str = "./eval_results",
) -> dict:
    """Run all detectors across multiple seeds and compute significance tests."""
    detector_names = ["CALLISTO", "Pro2Guard", "AMDM", "STAC"]
    # metric_name -> detector_name -> list of values across seeds
    all_scores: dict[str, dict[str, list[float]]] = {
        m: {d: [] for d in detector_names} for m in ("f1", "precision", "recall", "fpr")
    }

    for seed in range(n_seeds):
        print(f"  Seed {seed}/{n_seeds - 1} ...")
        dataset = generate_dataset(n_benign=n_benign, n_per_attack=n_per_attack, seed=seed)
        benign = _get_benign_sessions(dataset)
        train_sessions = benign[:50]

        alerts_map = _run_all_detectors(dataset, train_sessions)
        metrics_map = _collect_metrics(dataset, alerts_map)

        for name in detector_names:
            m = metrics_map[name]
            all_scores["f1"][name].append(m.f1)
            all_scores["precision"][name].append(m.precision)
            all_scores["recall"][name].append(m.recall)
            all_scores["fpr"][name].append(m.fpr)

    # Compute summary statistics
    summary: dict[str, dict] = {}
    for name in detector_names:
        summary[name] = {}
        for metric in ("f1", "precision", "recall", "fpr"):
            vals = np.array(all_scores[metric][name])
            summary[name][metric] = {"mean": float(vals.mean()), "std": float(vals.std())}

    # Paired significance tests: CALLISTO vs each baseline on F1
    callisto_f1 = np.array(all_scores["f1"]["CALLISTO"])
    sig_tests: dict[str, dict] = {}
    for baseline in ("Pro2Guard", "AMDM", "STAC"):
        baseline_f1 = np.array(all_scores["f1"][baseline])
        # Paired t-test
        t_stat, t_p = stats.ttest_rel(callisto_f1, baseline_f1)
        entry: dict = {
            "ttest_statistic": float(t_stat),
            "ttest_pvalue": float(t_p),
        }
        # Wilcoxon signed-rank (non-parametric); needs non-zero differences
        diffs = callisto_f1 - baseline_f1
        if np.all(diffs == 0):
            entry["wilcoxon_statistic"] = None
            entry["wilcoxon_pvalue"] = None
        else:
            try:
                w_stat, w_p = stats.wilcoxon(callisto_f1, baseline_f1)
                entry["wilcoxon_statistic"] = float(w_stat)
                entry["wilcoxon_pvalue"] = float(w_p)
            except ValueError:
                entry["wilcoxon_statistic"] = None
                entry["wilcoxon_pvalue"] = None
        sig_tests[f"CALLISTO_vs_{baseline}"] = entry

    # Print results table
    print("\n=== Statistical Significance Results ===\n")
    header = f"{'Detector':<14} {'F1':>14} {'Precision':>14} {'Recall':>14} {'FPR':>14}"
    print(header)
    print("-" * len(header))
    for name in detector_names:
        s = summary[name]
        row = f"{name:<14}"
        for metric in ("f1", "precision", "recall", "fpr"):
            m, sd = s[metric]["mean"], s[metric]["std"]
            row += f" {m:.3f}±{sd:.3f}".rjust(15)
        print(row)

    print("\nPaired tests (CALLISTO vs baseline) on F1:")
    for key, vals in sig_tests.items():
        tp = vals["ttest_pvalue"]
        wp = vals["wilcoxon_pvalue"]
        wp_str = f"{wp:.4f}" if wp is not None else "N/A"
        print(f"  {key}: t-test p={tp:.4f}, wilcoxon p={wp_str}")

    # Save to JSON
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    result = {
        "n_seeds": n_seeds,
        "summary": summary,
        "significance_tests": sig_tests,
        "raw_scores": {m: {d: vs for d, vs in dv.items()} for m, dv in all_scores.items()},
    }
    with open(out / "statistical_tests.json", "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved to {out / 'statistical_tests.json'}")
    return result


# ---------------------------------------------------------------------------
# 2. ROC curve and AUC analysis
# ---------------------------------------------------------------------------

def run_roc_analysis(
    n_benign: int = 100,
    n_per_attack: int = 30,
    seed: int = 42,
    output_dir: str = "./eval_results",
) -> dict:
    """Compute ROC curves and AUC for all detectors using continuous scores."""
    dataset = generate_dataset(n_benign=n_benign, n_per_attack=n_per_attack, seed=seed)
    benign = _get_benign_sessions(dataset)
    train_sessions = benign[:50]

    ground_truth = np.array([1 if _is_attack_session(s) else 0 for s in dataset])

    # --- Collect continuous scores per detector ---
    # CALLISTO: max alert score (already continuous)
    engine = CallistoEngine()
    engine.train_fingerprints(train_sessions)
    callisto_scores = []
    for s in dataset:
        alerts = engine.analyze_session(s)
        callisto_scores.append(_max_alert_score(alerts))

    # Pro2Guard: raw unsafe_reachability (continuous)
    p2g = Pro2GuardDetector(threshold=0.3)
    p2g.fit(train_sessions)
    p2g_scores = [p2g.score_session(s) for s in dataset]

    # AMDM: mean z-score (continuous)
    amdm = AMDMDetector(k_sigma=3.0, min_dims_anomalous=2)
    amdm.fit(train_sessions)
    amdm_scores = [amdm.score_session(s) for s in dataset]

    # STAC: chain match ratio (continuous)
    stac = STACDefenseDetector(max_gap=2)
    stac_scores = [stac.score_session(s) for s in dataset]

    all_scores = {
        "CALLISTO": np.array(callisto_scores),
        "Pro2Guard": np.array(p2g_scores),
        "AMDM": np.array(amdm_scores),
        "STAC": np.array(stac_scores),
    }

    roc_data: dict[str, dict] = {}

    for name, scores in all_scores.items():
        # Use actual score values as thresholds for proper ROC resolution
        unique_scores = np.unique(scores)
        thresholds = np.concatenate([[scores.max() + 1e-6], np.sort(unique_scores)[::-1], [-1e-6]])
        tpr_list, fpr_list = [], []
        for thresh in thresholds:
            predicted = (scores >= thresh).astype(int)
            tp = int(np.sum((predicted == 1) & (ground_truth == 1)))
            fp = int(np.sum((predicted == 1) & (ground_truth == 0)))
            fn = int(np.sum((predicted == 0) & (ground_truth == 1)))
            tn = int(np.sum((predicted == 0) & (ground_truth == 0)))
            tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            tpr_list.append(tpr)
            fpr_list.append(fpr)

        fpr_arr = np.array(fpr_list)
        tpr_arr = np.array(tpr_list)
        order = np.argsort(fpr_arr)
        fpr_sorted = fpr_arr[order]
        tpr_sorted = tpr_arr[order]
        auc = float(np.trapezoid(tpr_sorted, fpr_sorted))

        roc_data[name] = {
            "auc": round(auc, 4),
            "fpr": fpr_list,
            "tpr": tpr_list,
            "thresholds": thresholds.tolist(),
        }
        print(f"  {name}: AUC = {auc:.4f}")

    # Save
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "roc_analysis.json", "w") as f:
        json.dump(roc_data, f, indent=2)
    print(f"\nSaved to {out / 'roc_analysis.json'}")
    return roc_data


# ---------------------------------------------------------------------------
# Combined runner
# ---------------------------------------------------------------------------

def run_all_statistical(output_dir: str = "./eval_results") -> None:
    """Run both statistical significance tests and ROC analysis."""
    print("=== Running multi-seed statistical tests ===")
    run_statistical_tests(output_dir=output_dir)
    print("\n=== Running ROC/AUC analysis ===")
    run_roc_analysis(output_dir=output_dir)
    print("\nDone.")


if __name__ == "__main__":
    run_all_statistical()
