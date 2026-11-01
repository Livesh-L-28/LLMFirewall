"""LLMFirewall Benchmarks & Detection Reliability Package."""

from llmfirewall.benchmarks.evaluator import (
    BenchmarkReport,
    BenchmarkRunner,
    ConfusionMatrix,
    evaluate_dataset,
)

__all__ = [
    "BenchmarkReport",
    "BenchmarkRunner",
    "ConfusionMatrix",
    "evaluate_dataset",
]
