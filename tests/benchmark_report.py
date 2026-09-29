"""Executable evaluation script computing Precision, Recall, and Confusion Matrix on security datasets."""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

from llmfirewall import Action, Firewall
from llmfirewall._version import __version__

DATASETS_DIR = Path(__file__).parent / "datasets"


def load_json(name: str) -> List[Dict[str, Any]]:
    with open(DATASETS_DIR / name, "r", encoding="utf-8") as f:
        return json.load(f)


def evaluate_dataset(
    dataset_name: str,
    items: List[Dict[str, Any]],
    firewall: Firewall,
    positive_action: Action,
) -> Tuple[int, int, int, int]:
    """Calculate TP, FP, TN, FN for a given labeled dataset."""
    tp, fp, tn, fn = 0, 0, 0, 0

    for item in items:
        text = item["input"]
        res = firewall.check_prompt(text)
        action_triggered = res.decision.action == positive_action

        # Handle datasets with explicit expected_detection boolean
        if "expected_detection" in item:
            is_positive = item["expected_detection"]
        elif "expected_action" in item:
            is_positive = item["expected_action"] != "allow"
        else:
            is_positive = True

        if is_positive and action_triggered:
            tp += 1
        elif not is_positive and action_triggered:
            fp += 1
        elif not is_positive and not action_triggered:
            tn += 1
        elif is_positive and not action_triggered:
            fn += 1

    return tp, fp, tn, fn


def run_benchmark_report() -> None:
    firewall = Firewall()

    safe_items = load_json("safe_inputs.json")
    pi_items = load_json("prompt_injection.json")
    pii_items = load_json("pii.json")
    sec_items = load_json("secrets.json")

    print("=" * 65)
    print(f" LLMFirewall Security Evaluation Report (v{__version__})")
    print(f" Python: {sys.version.split()[0]} | Platform: {sys.platform}")
    print("=" * 65)

    benchmarks = [
        ("Safe Benign Prompts", safe_items, Action.BLOCK),
        ("Prompt Injection", pi_items, Action.BLOCK),
        ("PII (Personally Identifiable Info)", pii_items, Action.REDACT),
        ("Secrets & Credentials", sec_items, Action.BLOCK),
    ]

    print(f"{'Dataset':<35} | Cases | TP | FP | TN | FN | Prec. | Rec. | F1")
    print("-" * 65)

    for name, items, target_action in benchmarks:
        tp, fp, tn, fn = evaluate_dataset(name, items, firewall, target_action)
        prec = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if fp == 0 else 0.0)
        rec = tp / (tp + fn) if (tp + fn) > 0 else (1.0 if fn == 0 else 0.0)
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

        print(
            f"{name:<35} | {len(items):>5} | {tp:>2} | {fp:>2} | {tn:>2} | {fn:>2} | "
            f"{prec:.2f}  | {rec:.2f} | {f1:.2f}"
        )

    print("=" * 65)
    print("Note: These measurements describe behavior on the included test")
    print("dataset and should not be interpreted as universal detector accuracy.")
    print("=" * 65)


if __name__ == "__main__":
    run_benchmark_report()
