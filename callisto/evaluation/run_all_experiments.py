"""Master experiment runner — orchestrates all CALLISTO paper experiments."""

from __future__ import annotations

import json
import time
from pathlib import Path


def run_all_experiments(output_dir: str = "./eval_results") -> dict:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    results = {}
    t_total = time.time()

    # 1. Comparative evaluation
    print("\n" + "=" * 72)
    print("  [1/8] Comparative Evaluation")
    print("=" * 72)
    from callisto.evaluation.comparative_eval import run_comparative_evaluation
    results["comparative"] = run_comparative_evaluation(output_dir=output_dir)

    # 2. Ablation study
    print("\n" + "=" * 72)
    print("  [2/8] Ablation Study")
    print("=" * 72)
    from callisto.evaluation.ablation import run_ablation_study
    results["ablation"] = run_ablation_study(output_dir=output_dir)

    # 3. Statistical significance + ROC/AUC
    print("\n" + "=" * 72)
    print("  [3/8] Statistical Significance + ROC/AUC")
    print("=" * 72)
    from callisto.evaluation.statistical import run_all_statistical
    results["statistical"] = run_all_statistical(output_dir=output_dir)

    # 4. Hyperparameter sensitivity
    print("\n" + "=" * 72)
    print("  [4/8] Hyperparameter Sensitivity Analysis")
    print("=" * 72)
    from callisto.evaluation.sensitivity import run_sensitivity_analysis
    results["sensitivity"] = run_sensitivity_analysis(output_dir=output_dir)

    # 5. Adversarial robustness
    print("\n" + "=" * 72)
    print("  [5/8] Adversarial Robustness")
    print("=" * 72)
    from callisto.evaluation.adversarial import run_adversarial_experiments
    results["adversarial"] = run_adversarial_experiments(output_dir=output_dir)

    # 6. Scalability + latency + memory
    print("\n" + "=" * 72)
    print("  [6/8] Scalability & Performance")
    print("=" * 72)
    from callisto.evaluation.scalability import run_all_scalability
    results["scalability"] = run_all_scalability(output_dir=output_dir)

    # 7. Case studies
    print("\n" + "=" * 72)
    print("  [7/8] Case Studies")
    print("=" * 72)
    from callisto.evaluation.case_study import run_case_studies
    results["case_study"] = run_case_studies(output_dir=output_dir)

    # 8. Cross-scenario generalization
    print("\n" + "=" * 72)
    print("  [8/8] Cross-Scenario Generalization")
    print("=" * 72)
    from callisto.evaluation.cross_scenario import run_cross_scenario_experiments
    results["cross_scenario"] = run_cross_scenario_experiments(output_dir=output_dir)

    elapsed = time.time() - t_total
    print("\n" + "=" * 72)
    print(f"  ALL EXPERIMENTS COMPLETE — {elapsed:.1f}s total")
    print("=" * 72)

    with open(out / "all_experiments.json", "w") as f:
        json.dump({"total_time_s": round(elapsed, 1)}, f, indent=2, default=str)

    return results


if __name__ == "__main__":
    run_all_experiments()
