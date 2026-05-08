"""Ablation study for CALLISTO detection system.

Systematically disables each detection module and measures impact on F1/FPR.
"""

from __future__ import annotations

import json
import time
import numpy as np
from pathlib import Path

from callisto.config import CallistoConfig
from callisto.engine import CallistoEngine
from callisto.attacks.simulator import generate_dataset
from callisto.evaluation.metrics import (
    evaluate_detector, per_attack_metrics, EvalMetrics,
)
from callisto.collector.models import Session, Alert


def _format(m: EvalMetrics) -> dict:
    return {
        "precision": round(m.precision, 4),
        "recall": round(m.recall, 4),
        "f1": round(m.f1, 4),
        "fpr": round(m.fpr, 4),
        "accuracy": round(m.accuracy, 4),
        "tp": m.tp, "fp": m.fp, "tn": m.tn, "fn": m.fn,
    }


class AblationEngine(CallistoEngine):
    """CallistoEngine subclass that selectively enables/disables detection modules."""

    def __init__(
        self,
        config: CallistoConfig | None = None,
        *,
        enable_temporal: bool = True,
        enable_crs: bool = True,
        enable_bocpd: bool = True,
        enable_csbf: bool = True,
    ):
        super().__init__(config)
        self.enable_temporal = enable_temporal
        self.enable_crs = enable_crs
        self.enable_bocpd = enable_bocpd
        self.enable_csbf = enable_csbf

    def analyze_session(self, session: Session) -> list[Alert]:
        """Run detection pipeline with selective module enablement."""
        calls = session.tool_calls
        if not calls:
            return []

        alerts: list[Alert] = []

        # Layer 2: Feature extraction (always needed)
        graph, struct_feats = self.structural.extract(calls)

        # Layer 3: Temporal anomaly detection
        if self.enable_temporal:
            alerts.extend(self._detect_temporal_anomalies(session, calls))

        # Layer 3A: CRS on the call DAG
        if self.enable_crs:
            crs_alert = self.crs.detect(graph)
            if crs_alert:
                crs_alert.session_id = session.session_id
                alerts.append(crs_alert)

        # Layer 3B: MA-BOCPD on behavioral embeddings
        if self.enable_bocpd:
            self.bocpd.reset()
            for event in calls:
                emb = self.semantic.extract_event(event).to_vector()
                bocpd_alert = self.bocpd.detect(emb, session_id=session.session_id)
                if bocpd_alert:
                    alerts.append(bocpd_alert)

        # Layer 3C: CSBF cross-session fingerprint
        if self.enable_csbf:
            csbf_alert = self.csbf.detect(session)
            if csbf_alert:
                alerts.append(csbf_alert)

        # Layer 4: Response
        alerts = self.ranker.process(alerts)
        for a in alerts:
            self.breaker.record_alert(a)

        return alerts


# Each variant: (name, flags dict)
ABLATION_VARIANTS: list[tuple[str, dict[str, bool]]] = [
    ("CALLISTO (full)", dict(enable_temporal=True, enable_crs=True, enable_bocpd=True, enable_csbf=True)),
    ("w/o CRS",         dict(enable_temporal=True, enable_crs=False, enable_bocpd=True, enable_csbf=True)),
    ("w/o MA-BOCPD",    dict(enable_temporal=True, enable_crs=True, enable_bocpd=False, enable_csbf=True)),
    ("w/o CSBF",        dict(enable_temporal=True, enable_crs=True, enable_bocpd=True, enable_csbf=False)),
    ("w/o Temporal",    dict(enable_temporal=False, enable_crs=True, enable_bocpd=True, enable_csbf=True)),
    ("Only CRS",        dict(enable_temporal=False, enable_crs=True, enable_bocpd=False, enable_csbf=False)),
    ("Only MA-BOCPD",   dict(enable_temporal=False, enable_crs=False, enable_bocpd=True, enable_csbf=False)),
    ("Only CSBF",       dict(enable_temporal=False, enable_crs=False, enable_bocpd=False, enable_csbf=True)),
    ("Only Temporal",   dict(enable_temporal=True, enable_crs=False, enable_bocpd=False, enable_csbf=False)),
]


def run_ablation_study(
    n_benign: int = 100,
    n_per_attack: int = 30,
    seed: int = 42,
    output_dir: str = "./eval_results",
) -> dict:
    print("=" * 72)
    print("  CALLISTO Ablation Study")
    print("  Measuring per-module contribution to detection performance")
    print("=" * 72)

    # --- 1. Generate dataset ---
    print("\n[1] Generating dataset...")
    sessions = generate_dataset(n_benign=n_benign, n_per_attack=n_per_attack, seed=seed)
    benign = [s for s in sessions if all(e.label.value == "benign" for e in s.events)]
    n_attack = len(sessions) - len(benign)
    print(f"  Total: {len(sessions)} sessions ({len(benign)} benign, {n_attack} attack)")

    # --- 2. Split benign for training ---
    benign_train = benign[:50]
    config = CallistoConfig(seed=seed)
    results: dict[str, dict] = {}

    # --- 3. Run each ablation variant ---
    for idx, (name, flags) in enumerate(ABLATION_VARIANTS, start=2):
        step = idx
        print(f"\n[{step}] Running {name}...")
        engine = AblationEngine(config, **flags)
        engine.train_fingerprints(benign_train)

        t0 = time.time()
        alerts = [engine.analyze_session(s) for s in sessions]
        elapsed = time.time() - t0

        m = evaluate_detector(sessions, alerts)
        pa = per_attack_metrics(sessions, alerts)
        results[name] = {
            "flags": flags,
            "overall": _format(m),
            "per_attack": {k: _format(v) for k, v in pa.items()},
            "runtime_ms": round(elapsed * 1000, 1),
            "ms_per_session": round(elapsed / len(sessions) * 1000, 2),
        }
        print(f"  F1={m.f1:.4f}  Prec={m.precision:.4f}  Rec={m.recall:.4f}  FPR={m.fpr:.4f}")

    # --- 4. Summary table ---
    print("\n" + "=" * 82)
    print(f"{'Variant':<20} {'Precision':>9} {'Recall':>9} {'F1':>9} {'FPR':>9} {'ms/sess':>9}")
    print("-" * 82)
    for name, r in results.items():
        o = r["overall"]
        ms = r["ms_per_session"]
        print(f"{name:<20} {o['precision']:>9.4f} {o['recall']:>9.4f} {o['f1']:>9.4f} {o['fpr']:>9.4f} {ms:>9.2f}")
    print("=" * 82)

    # --- 5. Per-attack F1 breakdown ---
    print("\n--- Per-Attack F1 Breakdown ---")
    attack_names = set()
    for r in results.values():
        attack_names.update(r["per_attack"].keys())
    attack_names = sorted(attack_names - {"benign"})

    variant_names = list(results.keys())
    header = f"{'Attack':<20}"
    for vn in variant_names:
        header += f" {vn:>16}"
    print(header)
    print("-" * (20 + 17 * len(variant_names)))
    for atype in attack_names:
        row = f"{atype:<20}"
        for vn in variant_names:
            pa = results[vn].get("per_attack", {})
            if atype in pa:
                row += f" {pa[atype]['f1']:>16.4f}"
            else:
                row += f" {'N/A':>16}"
        print(row)

    # --- 6. Save results to JSON ---
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "ablation_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {out / 'ablation_results.json'}")

    return results


if __name__ == "__main__":
    run_ablation_study()
