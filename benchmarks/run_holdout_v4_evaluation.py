#!/usr/bin/env python3
"""Run Independent Evaluation on Holdout v4 Dataset.

Evaluates LLMFirewall-Core against the Holdout v4 evaluation dataset (80 samples)
across three distinct splits: Development (20), Validation (20), and Final Evaluation (40).
Computes Accuracy, Precision, Recall, F1 Score, False Positive Rate (FPR), and False Negative Rate (FNR).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from llmfirewall import Action, Firewall


def evaluate_split(samples: list[dict[str, Any]], fw: Firewall, split_name: str) -> dict[str, Any]:
    tp = tn = fp = fn = 0
    failures = []
    category_stats: dict[str, dict[str, int]] = {}

    for s in samples:
        cat = s["category"]
        if cat not in category_stats:
            category_stats[cat] = {"total": 0, "correct": 0}
        category_stats[cat]["total"] += 1

        res = fw.scan(s["text"], direction="input")
        is_blocked = res.is_blocked or res.action == Action.BLOCK

        if s["expected"] == "block":
            if is_blocked:
                tp += 1
                category_stats[cat]["correct"] += 1
            else:
                fn += 1
                failures.append({"type": "FALSE_NEGATIVE", "id": s["id"], "cat": cat, "text": s["text"]})
        else:
            if not is_blocked:
                tn += 1
                category_stats[cat]["correct"] += 1
            else:
                fp += 1
                failures.append({"type": "FALSE_POSITIVE", "id": s["id"], "cat": cat, "text": s["text"]})

    total = len(samples)
    acc = (tp + tn) / total if total > 0 else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return {
        "split": split_name,
        "total": total,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr,
        "category_stats": category_stats,
        "failures": failures,
    }


def main() -> None:
    dataset_path = Path("benchmarks/datasets/holdout_v4_evaluation_dataset.json")
    with open(dataset_path, "rb") as f:
        content = f.read()
    sha256 = hashlib.sha256(content).hexdigest()
    samples: list[dict[str, Any]] = json.loads(content.decode("utf-8"))

    fw = Firewall()

    dev_samples = [s for s in samples if s.get("split") == "development"]
    val_samples = [s for s in samples if s.get("split") == "validation"]
    eval_samples = [s for s in samples if s.get("split") == "final_evaluation"]

    res_dev = evaluate_split(dev_samples, fw, "Development")
    res_val = evaluate_split(val_samples, fw, "Validation")
    res_eval = evaluate_split(eval_samples, fw, "Final Evaluation")
    res_total = evaluate_split(samples, fw, "Overall Dataset (v4)")

    print("=" * 70)
    print(" LLMFirewall-Core Holdout v4 Independent Security Evaluation")
    print("=" * 70)
    print(f"Dataset Path:   {dataset_path}")
    print(f"SHA-256:        {sha256}")
    print(f"Total Samples:  {len(samples)}")
    print("-" * 70)
    for res in [res_dev, res_val, res_eval, res_total]:
        print(f"\n--- Split: {res['split']} (N={res['total']}) ---")
        print(f"TP: {res['tp']}, TN: {res['tn']}, FP: {res['fp']} (FPR: {res['fpr']*100:.1f}%), FN: {res['fn']} (FNR: {res['fnr']*100:.1f}%)")
        print(f"Accuracy:  {res['accuracy']*100:.1f}%")
        print(f"Precision: {res['precision']*100:.1f}%")
        print(f"Recall:    {res['recall']*100:.1f}%")
        print(f"F1 Score:  {res['f1']*100:.1f}%")

    print("\n" + "=" * 70)
    print("Category Breakdown (Overall):")
    for cat, stats in sorted(res_total["category_stats"].items()):
        pct = stats["correct"] / stats["total"] * 100
        print(f"  {cat:<32}: {stats['correct']}/{stats['total']} ({pct:5.1f}%)")

    if res_total["failures"]:
        print("\nFailures Detail:")
        for fail in res_total["failures"]:
            print(f"  [{fail['type']}] ({fail['id']}) {fail['cat']}: {fail['text']}")
    else:
        print("\nZero failures detected across all samples!")
    print("=" * 70)


if __name__ == "__main__":
    main()
