"""CALLISTO CLI entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="callisto",
        description="CALLISTO — LLM Agent API abuse & anomaly detection",
    )
    sub = parser.add_subparsers(dest="command")

    # --- eval ---
    p_eval = sub.add_parser("eval", help="Run evaluation on synthetic dataset")
    p_eval.add_argument("--benign", type=int, default=100, help="Number of benign sessions")
    p_eval.add_argument("--attacks", type=int, default=30, help="Number of sessions per attack type")
    p_eval.add_argument("--seed", type=int, default=42)
    p_eval.add_argument("--output", type=str, default="./eval_results")

    # --- scan ---
    p_scan = sub.add_parser("scan", help="Scan OpenClaw JSONL session logs")
    p_scan.add_argument("path", type=str, help="Path to JSONL file or directory")
    p_scan.add_argument("--fingerprint", type=str, default=None, help="Path to fingerprint file")

    # --- train ---
    p_train = sub.add_parser("train", help="Train behavioral fingerprints from session logs")
    p_train.add_argument("path", type=str, help="Directory of JSONL session logs")
    p_train.add_argument("--output", type=str, default="./fingerprints.json", help="Output fingerprint file")

    # --- monitor ---
    p_monitor = sub.add_parser("monitor", help="Real-time monitoring of OpenClaw logs")
    p_monitor.add_argument("log_dir", nargs="?", default="./logs", help="OpenClaw log directory")
    p_monitor.add_argument("--fingerprint", type=str, default=None, help="Path to fingerprint file")
    p_monitor.add_argument("--block", action="store_true", help="Enable auto-blocking")
    p_monitor.add_argument("--interval", type=float, default=1.0, help="Scan interval in seconds")

    args = parser.parse_args()

    if args.command == "eval":
        from callisto.evaluation.run_eval import run_evaluation
        run_evaluation(
            n_benign=args.benign,
            n_per_attack=args.attacks,
            output_dir=args.output,
            seed=args.seed,
        )

    elif args.command == "scan":
        _cmd_scan(args)

    elif args.command == "train":
        _cmd_train(args)

    elif args.command == "monitor":
        from callisto.monitor import Monitor, MonitorConfig
        config = MonitorConfig(
            log_dir=args.log_dir,
            watch_interval=args.interval,
            fingerprint_path=args.fingerprint,
            auto_block=args.block,
        )
        monitor = Monitor(config)
        monitor.run()

    else:
        parser.print_help()


def _cmd_scan(args: argparse.Namespace) -> None:
    from callisto.collector.openclaw_parser import parse_session_file
    from callisto.engine import CallistoEngine
    from callisto.config import CallistoConfig
    from callisto.response.explainer import AlertExplainer

    config = CallistoConfig()
    if args.fingerprint:
        config.fingerprint_path = Path(args.fingerprint)
    engine = CallistoEngine(config)
    explainer = AlertExplainer()

    target = Path(args.path)
    files = list(target.glob("*.jsonl")) if target.is_dir() else [target]

    if not files:
        print(f"No JSONL files found at {target}")
        return

    total_alerts = 0
    for f in files:
        session = parse_session_file(f)
        alerts = engine.analyze_session(session)
        if alerts:
            total_alerts += len(alerts)
            print(f"\n--- {f.name} ({len(session.tool_calls)} calls) ---")
            print(explainer.explain_batch(alerts))

    print(f"\nScanned {len(files)} sessions, found {total_alerts} alerts.")


def _cmd_train(args: argparse.Namespace) -> None:
    from callisto.collector.openclaw_parser import parse_session_file
    from callisto.detection.fingerprint import CrossSessionFingerprinter

    target = Path(args.path)
    files = list(target.glob("*.jsonl"))
    if not files:
        print(f"No JSONL files found in {target}")
        return

    fp = CrossSessionFingerprinter()
    for f in files:
        session = parse_session_file(f)
        if session.tool_calls:
            fp.fit_session(session)

    out = Path(args.output)
    fp.save(out)
    print(f"Trained fingerprints from {len(files)} sessions, saved to {out}")


if __name__ == "__main__":
    main()
