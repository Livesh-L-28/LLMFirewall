"""CLI entrypoint for llmfirewall.benchmarks.

Supports:
    python -m llmfirewall.benchmarks evaluate --dataset <path>
    python -m llmfirewall.benchmarks --dataset <path>
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from llmfirewall.benchmarks.evaluator import BenchmarkRunner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m llmfirewall.benchmarks",
        description="LLMFirewall-Core Independent Security Evaluation & Benchmark Runner",
    )

    subparsers = parser.add_subparsers(dest="command", help="Benchmark subcommands")

    # 'evaluate' subcommand
    eval_parser = subparsers.add_parser("evaluate", help="Evaluate a security dataset")
    eval_parser.add_argument(
        "--dataset",
        "-d",
        required=True,
        help="Path to evaluation dataset JSON file",
    )
    eval_parser.add_argument(
        "--extended",
        action="store_true",
        help="Enable extended development heuristics (multilingual, contextual, obfuscation)",
    )
    eval_parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON to stdout",
    )
    eval_parser.add_argument(
        "--output",
        "-o",
        help="Path to write Markdown or JSON benchmark report",
    )
    eval_parser.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help="Concurrency workers for throughput testing (default: 4)",
    )

    # Top-level direct arguments as fallback
    parser.add_argument(
        "--dataset",
        "-d",
        help="Path to evaluation dataset JSON file",
    )
    parser.add_argument(
        "--extended",
        action="store_true",
        help="Enable extended development heuristics (multilingual, contextual, obfuscation)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON to stdout",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Path to write Markdown or JSON benchmark report",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help="Concurrency workers for throughput testing (default: 4)",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    dataset_path = getattr(args, "dataset", None)
    if not dataset_path:
        parser.print_help()
        return 2

    runner = BenchmarkRunner(use_extended_rules=args.extended)
    try:
        report = runner.evaluate_dataset(
            dataset_path=dataset_path,
            concurrency=args.concurrency,
        )
    except Exception as e:
        print(f"Error evaluating dataset: {e}", file=sys.stderr)
        return 1

    # Format output
    if args.json:
        out_str = json.dumps(report.to_dict(), indent=2)
        print(out_str)
    else:
        out_str = report.to_markdown()
        print(out_str)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if args.output.endswith(".json"):
            out_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        else:
            out_path.write_text(report.to_markdown(), encoding="utf-8")
        print(f"\n[OK] Benchmark report saved to: {out_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
