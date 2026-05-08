"""Case study analysis and text-based visualizations for the CALLISTO paper.

Implements four case studies demonstrating each core detection module:
1. CRS Shapley Attribution Analysis (privilege escalation)
2. MA-BOCPD Run-Length Evolution (behavior drift)
3. CSBF Distance Distribution (cross-session fingerprinting)
4. False Positive / False Negative Analysis (full pipeline)
"""

from __future__ import annotations

import time
import json
import numpy as np
from pathlib import Path

from callisto.config import CallistoConfig
from callisto.engine import CallistoEngine
from callisto.attacks.simulator import (
    generate_benign_session,
    generate_rate_flood,
    generate_priv_escalation,
    generate_data_exfil,
    generate_behavior_drift,
    generate_state_poison,
    generate_dataset,
)
from callisto.evaluation.metrics import evaluate_detector, EvalMetrics
from callisto.collector.models import Session, Alert, AttackType
from callisto.detection.causal import CausalResponsibilityScorer
from callisto.detection.changepoint import MABOCPD, MetaAdaptiveHazard
from callisto.detection.fingerprint import CrossSessionFingerprinter
from callisto.features.structural import StructuralExtractor
from callisto.features.semantic import SemanticExtractor


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEPARATOR = "=" * 72
_THIN_SEP = "-" * 72


def _bar(value: float, width: int = 10) -> str:
    """Render a value in [0, 1] as an ASCII bar."""
    filled = int(round(value * width))
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def _session_attack_type(session: Session) -> AttackType:
    """Return the dominant attack type for a session."""
    for e in session.events:
        if e.label != AttackType.BENIGN:
            return e.label
    return AttackType.BENIGN


# ---------------------------------------------------------------------------
# Case Study 1: CRS Shapley Attribution Analysis
# ---------------------------------------------------------------------------

def run_crs_case_study(
    engine: CallistoEngine,
    output_dir: Path,
) -> dict:
    """Analyze CRS Shapley attribution on a privilege escalation session.

    Builds the call DAG, computes per-node causal responsibility scores,
    and prints a text-based heatmap highlighting the critical path.
    """
    print(f"\n{_SEPARATOR}")
    print("CASE STUDY 1: CRS Shapley Attribution Analysis")
    print(f"{_SEPARATOR}\n")

    session = generate_priv_escalation(seed=42)
    calls = session.tool_calls

    print(f"Session:  {session.session_id}")
    print(f"Agent:    {session.agent_id}")
    print(f"Events:   {len(calls)}")
    print()

    # Build DAG and score
    graph, struct_feats = engine.structural.extract(calls)
    crs_result = engine.crs.score(graph)

    critical_set = set(crs_result.critical_path)

    # Print heatmap table
    header = f"{'Step':<6}{'Tool':<20}{'CRS Score':<18}{'Score':>6}"
    print(header)
    print(_THIN_SEP)

    step_results = []
    for i, event in enumerate(calls):
        score = crs_result.scores.get(event.event_id, 0.0)
        is_critical = event.event_id in critical_set
        marker = "  <- CRITICAL" if is_critical else ""
        bar = _bar(score)
        line = f"{i + 1:<6}{event.tool_name:<20}{bar}  {score:.2f}{marker}"
        print(line)
        step_results.append({
            "step": i + 1,
            "event_id": event.event_id,
            "tool": event.tool_name,
            "crs_score": round(score, 4),
            "is_critical": is_critical,
            "label": event.label.value,
        })

    print()
    print(f"Max CRS score:   {crs_result.max_score:.4f}")
    print(f"Critical path:   {len(crs_result.critical_path)} nodes")
    print(f"Graph nodes:     {struct_feats.num_nodes}")
    print(f"Graph edges:     {struct_feats.num_edges}")
    print(f"Longest path:    {struct_feats.longest_path_len}")

    # Critical path detail
    if crs_result.critical_path:
        print(f"\nCritical path nodes (CRS >= {engine.crs.threshold}):")
        for eid in crs_result.critical_path:
            tool = graph.nodes[eid].get("tool", "?")
            score = crs_result.scores[eid]
            print(f"  {eid}  {tool:<20} {score:.4f}")

    results = {
        "session_id": session.session_id,
        "num_events": len(calls),
        "max_crs_score": round(crs_result.max_score, 4),
        "critical_path_len": len(crs_result.critical_path),
        "graph_nodes": struct_feats.num_nodes,
        "graph_edges": struct_feats.num_edges,
        "steps": step_results,
    }

    out_path = output_dir / "crs_case_study.json"
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nResults saved to {out_path}")
    return results


# ---------------------------------------------------------------------------
# Case Study 2: MA-BOCPD Run-Length Evolution
# ---------------------------------------------------------------------------

def run_bocpd_case_study(
    engine: CallistoEngine,
    output_dir: Path,
) -> dict:
    """Analyze BOCPD changepoint detection on a behavior drift session.

    Feeds each event embedding through the BOCPD detector and prints a
    text-based timeline showing changepoint probability and MAP run length.
    """
    print(f"\n{_SEPARATOR}")
    print("CASE STUDY 2: MA-BOCPD Run-Length Evolution")
    print(f"{_SEPARATOR}\n")

    session = generate_behavior_drift(seed=42)
    calls = session.tool_calls

    print(f"Session:  {session.session_id}")
    print(f"Agent:    {session.agent_id}")
    print(f"Events:   {len(calls)}")
    print(f"Threshold: {engine.bocpd.threshold}")
    print()

    engine.bocpd.reset()

    header = f"{'Step':<6}{'Tool':<20}{'P(cp)':>8}{'RL_MAP':>8}  "
    print(header)
    print(_THIN_SEP)

    step_results = []
    changepoints_detected = []

    for i, event in enumerate(calls):
        emb = engine.semantic.extract_event(event).to_vector()
        cp_result = engine.bocpd.update(emb)

        marker = ""
        if cp_result.is_changepoint:
            marker = "  <- CHANGEPOINT DETECTED"
            changepoints_detected.append(i + 1)

        line = (
            f"{i + 1:<6}{event.tool_name:<20}"
            f"{cp_result.changepoint_prob:>8.3f}"
            f"{cp_result.run_length_map:>8}"
            f"{marker}"
        )
        print(line)
        step_results.append({
            "step": i + 1,
            "event_id": event.event_id,
            "tool": event.tool_name,
            "changepoint_prob": round(cp_result.changepoint_prob, 4),
            "run_length_map": cp_result.run_length_map,
            "is_changepoint": cp_result.is_changepoint,
            "label": event.label.value,
        })

    print()
    print(f"Changepoints detected at steps: {changepoints_detected or 'none'}")

    # Print probability timeline as ASCII sparkline
    probs = [s["changepoint_prob"] for s in step_results]
    max_p = max(probs) if probs else 1.0
    print(f"\nChangepoint probability timeline (max={max_p:.3f}):")
    spark_width = 50
    for i, s in enumerate(step_results):
        p = s["changepoint_prob"]
        bar_len = int(round((p / max(max_p, 1e-9)) * spark_width))
        cp_mark = " *" if s["is_changepoint"] else ""
        print(f"  {i + 1:>3} |{'#' * bar_len}{cp_mark}")

    results = {
        "session_id": session.session_id,
        "num_events": len(calls),
        "threshold": engine.bocpd.threshold,
        "changepoints_at": changepoints_detected,
        "num_changepoints": len(changepoints_detected),
        "steps": step_results,
    }

    out_path = output_dir / "bocpd_case_study.json"
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nResults saved to {out_path}")
    return results


# ---------------------------------------------------------------------------
# Case Study 3: CSBF Distance Distribution
# ---------------------------------------------------------------------------

def run_csbf_case_study(
    engine: CallistoEngine,
    output_dir: Path,
) -> dict:
    """Analyze CSBF fingerprint distances for benign vs attack sessions.

    Trains on benign sessions, then compares both benign and attack sessions
    against the learned fingerprint. Prints distribution statistics and an
    ASCII histogram of Mahalanobis distances.
    """
    print(f"\n{_SEPARATOR}")
    print("CASE STUDY 3: CSBF Distance Distribution")
    print(f"{_SEPARATOR}\n")

    # Generate sessions
    benign_sessions = [
        generate_benign_session(seed=1000 + i) for i in range(30)
    ]
    attack_generators = [
        generate_rate_flood,
        generate_priv_escalation,
        generate_data_exfil,
        generate_behavior_drift,
        generate_state_poison,
    ]
    attack_sessions = []
    for i, gen in enumerate(attack_generators):
        for j in range(2):
            attack_sessions.append(gen(seed=2000 + i * 10 + j))

    # Train CSBF on first 20 benign sessions
    csbf = CrossSessionFingerprinter(
        distance_threshold=engine.csbf.distance_threshold,
        min_history=5,
    )
    train_sessions = benign_sessions[:20]
    for s in train_sessions:
        csbf.fit_session(s)

    print(f"Training sessions:  {len(train_sessions)} (benign)")
    print(f"Test benign:        {len(benign_sessions)} total")
    print(f"Test attack:        {len(attack_sessions)}")
    print()

    # Compare all sessions
    benign_distances = []
    attack_distances = []
    all_comparisons = []

    for s in benign_sessions:
        result = csbf.compare(s)
        benign_distances.append(result.distance)
        all_comparisons.append({
            "session_id": s.session_id,
            "type": "benign",
            "distance": round(result.distance, 4),
            "threshold": round(result.threshold, 4),
            "is_anomalous": bool(result.is_anomalous),
        })

    for s in attack_sessions:
        result = csbf.compare(s)
        attack_distances.append(result.distance)
        atype = _session_attack_type(s)
        all_comparisons.append({
            "session_id": s.session_id,
            "type": atype.value,
            "distance": round(result.distance, 4),
            "threshold": round(result.threshold, 4),
            "is_anomalous": bool(result.is_anomalous),
        })

    benign_arr = np.array(benign_distances)
    attack_arr = np.array(attack_distances)
    threshold = all_comparisons[0]["threshold"]

    # Print distribution summary
    print("Distribution Summary:")
    print(_THIN_SEP)
    print(f"  {'':>12}{'Mean':>10}{'Std':>10}{'Min':>10}{'Max':>10}")
    print(
        f"  {'Benign':>12}"
        f"{benign_arr.mean():>10.3f}"
        f"{benign_arr.std():>10.3f}"
        f"{benign_arr.min():>10.3f}"
        f"{benign_arr.max():>10.3f}"
    )
    print(
        f"  {'Attack':>12}"
        f"{attack_arr.mean():>10.3f}"
        f"{attack_arr.std():>10.3f}"
        f"{attack_arr.min():>10.3f}"
        f"{attack_arr.max():>10.3f}"
    )
    print(f"\n  Threshold:  {threshold:.3f}")

    # ASCII histogram
    all_dists = np.concatenate([benign_arr, attack_arr])
    hist_min = 0.0
    hist_max = max(float(all_dists.max()) * 1.1, threshold * 1.5)
    n_bins = 20
    bin_edges = np.linspace(hist_min, hist_max, n_bins + 1)

    benign_counts, _ = np.histogram(benign_arr, bins=bin_edges)
    attack_counts, _ = np.histogram(attack_arr, bins=bin_edges)
    max_count = max(int(benign_counts.max()), int(attack_counts.max()), 1)
    bar_width = 30

    print(f"\nDistance Histogram (B=benign, A=attack, |=threshold):")
    print(_THIN_SEP)
    for i in range(n_bins):
        lo, hi = bin_edges[i], bin_edges[i + 1]
        b_len = int(round(benign_counts[i] / max_count * bar_width))
        a_len = int(round(attack_counts[i] / max_count * bar_width))
        thresh_in_bin = lo <= threshold < hi
        marker = " |<- threshold" if thresh_in_bin else ""
        print(
            f"  {lo:>6.2f}-{hi:<6.2f} "
            f"B{'#' * b_len:<{bar_width}s} "
            f"A{'#' * a_len:<{bar_width}s}"
            f"{marker}"
        )

    # Separation quality
    if len(benign_arr) > 0 and len(attack_arr) > 0:
        pooled_std = np.sqrt(
            (benign_arr.std() ** 2 + attack_arr.std() ** 2) / 2.0
        )
        if pooled_std > 1e-9:
            cohens_d = (attack_arr.mean() - benign_arr.mean()) / pooled_std
        else:
            cohens_d = 0.0
        print(f"\n  Cohen's d (separation): {cohens_d:.3f}")

    results = {
        "n_train": len(train_sessions),
        "n_benign_test": len(benign_sessions),
        "n_attack_test": len(attack_sessions),
        "threshold": round(threshold, 4),
        "benign_stats": {
            "mean": round(float(benign_arr.mean()), 4),
            "std": round(float(benign_arr.std()), 4),
            "min": round(float(benign_arr.min()), 4),
            "max": round(float(benign_arr.max()), 4),
        },
        "attack_stats": {
            "mean": round(float(attack_arr.mean()), 4),
            "std": round(float(attack_arr.std()), 4),
            "min": round(float(attack_arr.min()), 4),
            "max": round(float(attack_arr.max()), 4),
        },
        "comparisons": all_comparisons,
    }

    out_path = output_dir / "csbf_case_study.json"
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nResults saved to {out_path}")
    return results


# ---------------------------------------------------------------------------
# Case Study 4: False Positive / False Negative Analysis
# ---------------------------------------------------------------------------

def run_fp_fn_analysis(
    engine: CallistoEngine,
    sessions: list[Session],
    output_dir: Path,
) -> dict:
    """Analyze false positives and false negatives from the full pipeline.

    For each FP: shows which module triggered and the session tool sequence.
    For each FN: shows the attack type and possible reasons for the miss.
    """
    print(f"\n{_SEPARATOR}")
    print("CASE STUDY 4: False Positive / False Negative Analysis")
    print(f"{_SEPARATOR}\n")

    alerts_per_session: list[list[Alert]] = []
    for s in sessions:
        alerts = engine.analyze_session(s)
        alerts_per_session.append(alerts)

    metrics = evaluate_detector(sessions, alerts_per_session)

    print(f"Dataset:    {len(sessions)} sessions")
    print(f"TP={metrics.tp}  FP={metrics.fp}  TN={metrics.tn}  FN={metrics.fn}")
    print(f"Precision:  {metrics.precision:.4f}")
    print(f"Recall:     {metrics.recall:.4f}")
    print(f"F1:         {metrics.f1:.4f}")
    print(f"FPR:        {metrics.fpr:.4f}")

    # Collect FPs and FNs
    false_positives = []
    false_negatives = []

    for session, alerts in zip(sessions, alerts_per_session):
        is_attack = any(e.label != AttackType.BENIGN for e in session.events)
        is_detected = len(alerts) > 0

        if not is_attack and is_detected:
            false_positives.append((session, alerts))
        elif is_attack and not is_detected:
            false_negatives.append((session, alerts))

    # --- False Positives ---
    print(f"\n{'FALSE POSITIVES':=^72}")
    print(f"Count: {len(false_positives)}\n")

    fp_details = []
    for idx, (session, alerts) in enumerate(false_positives[:10]):
        calls = session.tool_calls
        tool_seq = [c.tool_name for c in calls]
        modules = sorted(set(a.source_module for a in alerts))
        max_score = max(a.score for a in alerts) if alerts else 0.0

        print(f"  FP-{idx + 1}: {session.session_id}")
        print(f"    Triggered by: {', '.join(modules)}")
        print(f"    Max score:    {max_score:.3f}")
        print(f"    Tool count:   {len(calls)}")
        print(f"    Tool seq:     {' -> '.join(tool_seq[:12])}", end="")
        if len(tool_seq) > 12:
            print(f" ... (+{len(tool_seq) - 12} more)")
        else:
            print()
        for a in alerts[:3]:
            print(f"    Alert: [{a.source_module}] {a.explanation[:80]}")
        print()

        fp_details.append({
            "session_id": session.session_id,
            "modules_triggered": modules,
            "max_score": round(max_score, 4),
            "num_calls": len(calls),
            "tool_sequence": tool_seq,
            "alerts": [
                {
                    "module": a.source_module,
                    "score": round(a.score, 4),
                    "explanation": a.explanation,
                }
                for a in alerts
            ],
        })

    if len(false_positives) > 10:
        print(f"  ... and {len(false_positives) - 10} more FPs")

    # --- False Negatives ---
    print(f"\n{'FALSE NEGATIVES':=^72}")
    print(f"Count: {len(false_negatives)}\n")

    fn_details = []
    for idx, (session, _) in enumerate(false_negatives[:10]):
        calls = session.tool_calls
        atype = _session_attack_type(session)
        attack_events = [e for e in calls if e.label != AttackType.BENIGN]
        tool_seq = [c.tool_name for c in calls]
        attack_tools = [e.tool_name for e in attack_events]

        # Hypothesize why it was missed
        reasons = []
        if len(attack_events) <= 2:
            reasons.append("few attack events (low signal)")
        if all(t in ("read_file", "search", "list_files", "get_info", "summarize")
               for t in attack_tools):
            reasons.append("attack uses only benign-looking tools")
        if len(calls) > 30 and len(attack_events) < 4:
            reasons.append("attack diluted in long benign session")
        if not reasons:
            reasons.append("attack pattern below detection thresholds")

        print(f"  FN-{idx + 1}: {session.session_id}")
        print(f"    Attack type:    {atype.value}")
        print(f"    Attack events:  {len(attack_events)} / {len(calls)} total")
        print(f"    Attack tools:   {', '.join(attack_tools)}")
        print(f"    Possible cause: {'; '.join(reasons)}")
        print()

        fn_details.append({
            "session_id": session.session_id,
            "attack_type": atype.value,
            "num_attack_events": len(attack_events),
            "num_total_events": len(calls),
            "attack_tools": attack_tools,
            "tool_sequence": tool_seq,
            "possible_causes": reasons,
        })

    if len(false_negatives) > 10:
        print(f"  ... and {len(false_negatives) - 10} more FNs")

    results = {
        "metrics": {
            "tp": metrics.tp,
            "fp": metrics.fp,
            "tn": metrics.tn,
            "fn": metrics.fn,
            "precision": round(metrics.precision, 4),
            "recall": round(metrics.recall, 4),
            "f1": round(metrics.f1, 4),
            "fpr": round(metrics.fpr, 4),
        },
        "false_positives": fp_details,
        "false_negatives": fn_details,
    }

    out_path = output_dir / "fp_fn_analysis.json"
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nResults saved to {out_path}")
    return results


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def run_case_studies(
    seed: int = 42,
    output_dir: str = "./eval_results",
) -> dict:
    """Run all four case studies end-to-end.

    Creates the engine, generates a training/test dataset, trains the
    fingerprint baseline, then executes each case study in sequence.
    Combined results are saved to a single JSON file.
    """
    np.random.seed(seed)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    print(_SEPARATOR)
    print("CALLISTO Case Study Analysis")
    print(_SEPARATOR)
    print(f"Seed:       {seed}")
    print(f"Output dir: {out.resolve()}")

    # --- Setup ---
    config = CallistoConfig(seed=seed)
    engine = CallistoEngine(config)

    # Generate dataset for training and FP/FN analysis
    print("\nGenerating dataset ...")
    t0 = time.time()
    dataset = generate_dataset(
        n_benign=60, n_per_attack=15, seed=seed,
    )
    n_attack = sum(
        1 for s in dataset
        if any(e.label != AttackType.BENIGN for e in s.events)
    )
    print(f"  {len(dataset)} sessions ({len(dataset) - n_attack} benign, {n_attack} attack)")

    # Train fingerprints on benign sessions
    benign_train = [
        s for s in dataset
        if all(e.label == AttackType.BENIGN for e in s.events)
    ][:40]
    print(f"  Training CSBF on {len(benign_train)} benign sessions ...")
    engine.train_fingerprints(benign_train)
    print(f"  Setup completed in {time.time() - t0:.1f}s")

    # --- Run case studies ---
    combined: dict = {}

    combined["crs"] = run_crs_case_study(engine, out)
    combined["bocpd"] = run_bocpd_case_study(engine, out)
    combined["csbf"] = run_csbf_case_study(engine, out)
    combined["fp_fn"] = run_fp_fn_analysis(engine, dataset, out)

    # --- Save combined results ---
    combined_path = out / "case_studies_combined.json"
    combined_path.write_text(json.dumps(combined, indent=2), encoding="utf-8")

    print(f"\n{_SEPARATOR}")
    print("All case studies complete.")
    print(f"Combined results: {combined_path}")
    print(_SEPARATOR)

    return combined


if __name__ == "__main__":
    run_case_studies()
