#!/usr/bin/env python3
"""
AgentDojo Injection Prompt Detection Test

Feeds AgentDojo's 35 injection prompts through CALLISTO's detection engine
and reports detection rates. No external LLM API keys needed.

Usage:
    .venv/bin/python tests/agentdojo_detection_test.py
"""

import json
import sys
import time
from pathlib import Path

# Add callisto_agent to path
script_dir = Path(__file__).parent.parent
sys.path.insert(0, str(script_dir / "openclaw_plugin" / "callisto-skill" / "python"))

from callisto_agent import CallistoAgent

# Load injection prompts
PROMPTS_FILE = Path("/tmp/agentdojo_injection_prompts.json")
with open(PROMPTS_FILE) as f:
    prompts = json.load(f)


def run_detection():
    agent = CallistoAgent(threshold=3)
    session_id = "agentdojo-test-session"

    results = []
    detected = 0
    missed = 0

    for p in prompts:
        goal = p["goal"]

        # Construct a tool call parameter from the injection goal
        # Most injections manifest as shell commands or tool parameters
        parameters = {
            "command": goal,
            "tool_hint": "shell",
        }

        result = agent.detect(
            tool_name="Exec",
            parameters=parameters,
            session_id=session_id,
        )

        has_alert = len(result.alerts) > 0 or result.status == "blocked"
        is_high = any(
            a.get("risk_level") in ("HIGH", "CRITICAL")
            for a in result.alerts
        )

        entry = {
            "suite": p["suite"],
            "id": p["id"],
            "difficulty": p["difficulty"],
            "goal": goal[:100],
            "detected": has_alert,
            "is_high": is_high,
            "status": result.status,
            "circuit_breaker": result.circuit_breaker,
            "alerts": result.alerts,
        }
        results.append(entry)

        if has_alert:
            detected += 1
        else:
            missed += 1

    # Print summary
    total = len(prompts)
    print("=" * 70)
    print(f"AgentDojo Injection Detection Test")
    print(f"Total prompts: {total}")
    print(f"Detected: {detected} ({detected/total*100:.1f}%)")
    print(f"Missed: {missed} ({missed/total*100:.1f}%)")
    print("=" * 70)

    # Breakdown by suite
    suites = {}
    for r in results:
        s = r["suite"]
        if s not in suites:
            suites[s] = {"total": 0, "detected": 0}
        suites[s]["total"] += 1
        if r["detected"]:
            suites[s]["detected"] += 1

    print("\nBy suite:")
    for s, stats in sorted(suites.items()):
        pct = stats["detected"] / stats["total"] * 100
        print(f"  {s}: {stats['detected']}/{stats['total']} ({pct:.0f}%)")

    # Breakdown by difficulty
    diffs = {}
    for r in results:
        d = r["difficulty"]
        if d not in diffs:
            diffs[d] = {"total": 0, "detected": 0}
        diffs[d]["total"] += 1
        if r["detected"]:
            diffs[d]["detected"] += 1

    print("\nBy difficulty:")
    for d in ["EASY", "MEDIUM", "HARD"]:
        if d in diffs:
            stats = diffs[d]
            pct = stats["detected"] / stats["total"] * 100
            print(f"  {d}: {stats['detected']}/{stats['total']} ({pct:.0f}%)")

    # Detailed results
    print("\n" + "=" * 70)
    print("Detailed results:")
    print("=" * 70)
    for r in results:
        status = "DETECTED" if r["detected"] else "MISSED"
        marker = "+" if r["detected"] else "-"
        print(f"  [{marker}] [{r['suite']}] {r['id']} ({r['difficulty']}): {status}")
        if r["alerts"]:
            for a in r["alerts"]:
                print(f"      {a.get('risk_level', '?')} {a.get('attack_type', '?')}: {a.get('explanation', '')[:80]}")
        print(f"      goal: {r['goal'][:80]}")
        print()

    # Save full results
    out = Path("/tmp/agentdojo_detection_results.json")
    with open(out, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"Full results saved to {out}")


if __name__ == "__main__":
    run_detection()
