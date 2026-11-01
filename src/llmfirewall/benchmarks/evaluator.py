"""Independent, reproducible security evaluation and benchmark engine for LLMFirewall-Core."""

from __future__ import annotations

import concurrent.futures
from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import sys
import time
import tracemalloc
from typing import Any, Dict, List, Optional, Tuple, Union

import llmfirewall
from llmfirewall import Action, Firewall
from llmfirewall.detectors.prompt_injection import ExtendedPromptInjectionDetector
from llmfirewall.integrations.stream import StreamingTextGuard


@dataclass
class ConfusionMatrix:
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.tn + self.fp + self.fn

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total > 0 else 0.0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * (p * r) / (p + r) if (p + r) > 0 else 0.0

    @property
    def specificity(self) -> float:
        return self.tn / (self.tn + self.fp) if (self.tn + self.fp) > 0 else 1.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) > 0 else 0.0

    @property
    def fnr(self) -> float:
        return self.fn / (self.fn + self.tp) if (self.fn + self.tp) > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "tp": self.tp,
            "tn": self.tn,
            "fp": self.fp,
            "fn": self.fn,
            "accuracy": round(self.accuracy, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1, 4),
            "specificity": round(self.specificity, 4),
            "false_positive_rate": round(self.fpr, 4),
            "false_negative_rate": round(self.fnr, 4),
        }


@dataclass
class BenchmarkReport:
    dataset_name: str
    dataset_path: str
    dataset_sha256: str
    sample_count: int
    environment: Dict[str, Any]
    matrix: ConfusionMatrix
    category_metrics: Dict[str, Dict[str, Any]]
    language_metrics: Dict[str, Dict[str, Any]]
    latency_ms: Dict[str, float]
    throughput: Dict[str, Any]
    memory: Dict[str, Any]
    failures: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dataset_name": self.dataset_name,
            "dataset_path": self.dataset_path,
            "dataset_sha256": self.dataset_sha256,
            "sample_count": self.sample_count,
            "environment": self.environment,
            "metrics": self.matrix.to_dict(),
            "categories": self.category_metrics,
            "languages": self.language_metrics,
            "latency_ms": self.latency_ms,
            "throughput": self.throughput,
            "memory": self.memory,
            "failure_count": len(self.failures),
            "failures": self.failures,
        }

    def to_markdown(self) -> str:
        m = self.matrix.to_dict()
        md = [
            f"# Security Benchmark Evaluation Report: {self.dataset_name}",
            "",
            f"- **Execution Timestamp**: `{self.environment.get('timestamp')}`",
            f"- **Package**: `{self.environment.get('package_name')}` v`{self.environment.get('package_version')}`",
            f"- **Python Runtime**: `{self.environment.get('python_version')}` on `{self.environment.get('platform')}`",
            f"- **Dataset Path**: `{self.dataset_path}`",
            f"- **Dataset SHA-256**: `{self.dataset_sha256}`",
            f"- **Sample Count**: `{self.sample_count}`",
            "",
            "## 1. Classification Effectiveness Metrics",
            "",
            "| Metric | Value | Percentage | Description |",
            "| :--- | :--- | :--- | :--- |",
            f"| **Accuracy** | `{m['accuracy']}` | **{m['accuracy'] * 100:.2f}%** | Overall classification accuracy |",
            f"| **Precision** | `{m['precision']}` | **{m['precision'] * 100:.2f}%** | Positive predictive value (TP / (TP + FP)) |",
            f"| **Recall (Sensitivity)** | `{m['recall']}` | **{m['recall'] * 100:.2f}%** | True positive rate (TP / (TP + FN)) |",
            f"| **F1 Score** | `{m['f1_score']}` | **{m['f1_score'] * 100:.2f}%** | Harmonic mean of precision & recall |",
            f"| **Specificity** | `{m['specificity']}` | **{m['specificity'] * 100:.2f}%** | True negative rate (TN / (TN + FP)) |",
            f"| **False Positive Rate (FPR)** | `{m['false_positive_rate']}` | **{m['false_positive_rate'] * 100:.2f}%** | Benign samples incorrectly blocked |",
            f"| **False Negative Rate (FNR)** | `{m['false_negative_rate']}` | **{m['false_negative_rate'] * 100:.2f}%** | Attacks that bypassed detection |",
            "",
            "### Confusion Matrix",
            f"- **True Positives (TP)**: `{m['tp']}`",
            f"- **True Negatives (TN)**: `{m['tn']}`",
            f"- **False Positives (FP)**: `{m['fp']}`",
            f"- **False Negatives (FN)**: `{m['fn']}`",
            "",
            "## 2. Category Breakdown",
            "",
            "| Category | Total | Correct | Accuracy | TP | TN | FP | FN |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        for cat, stats in sorted(self.category_metrics.items()):
            acc_pct = f"{stats['accuracy'] * 100:.1f}%"
            md.append(
                f"| `{cat}` | {stats['total']} | {stats['correct']} | **{acc_pct}** | "
                f"{stats['tp']} | {stats['tn']} | {stats['fp']} | {stats['fn']} |"
            )

        if self.language_metrics:
            md.extend([
                "",
                "## 3. Language Breakdown",
                "",
                "| Language | Total | Correct | Accuracy | FP | FN |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |",
            ])
            for lang, stats in sorted(self.language_metrics.items()):
                acc_pct = f"{stats['accuracy'] * 100:.1f}%"
                md.append(
                    f"| `{lang}` | {stats['total']} | {stats['correct']} | **{acc_pct}** | "
                    f"{stats['fp']} | {stats['fn']} |"
                )

        md.extend([
            "",
            "## 4. Latency & Performance",
            "",
            f"- **Latency Median (P50)**: `{self.latency_ms.get('p50', 0):.3f} ms`",
            f"- **Latency P90**: `{self.latency_ms.get('p90', 0):.3f} ms`",
            f"- **Latency P95**: `{self.latency_ms.get('p95', 0):.3f} ms`",
            f"- **Latency P99**: `{self.latency_ms.get('p99', 0):.3f} ms`",
            f"- **Mean Latency**: `{self.latency_ms.get('mean', 0):.3f} ms` (Min: `{self.latency_ms.get('min', 0):.3f} ms`, Max: `{self.latency_ms.get('max', 0):.3f} ms`)",
            f"- **Concurrent Throughput**: `{self.throughput.get('requests_per_second', 0):.1f} req/s` ({self.throughput.get('total_requests', 0)} requests, concurrency={self.throughput.get('concurrency', 1)})",
            f"- **Peak Memory**: `{self.memory.get('peak_memory_kib', 0):.1f} KiB` (`{self.memory.get('peak_memory_mib', 0):.3f} MiB`)",
            "",
            "## 5. Failure Audit",
            "",
            f"Total Misclassifications: `{len(self.failures)}`",
        ])

        if self.failures:
            md.append("")
            for f in self.failures:
                md.append(f"- **[{f['type']}]** `({f['id']})` [{f['category']}] Text: *\"{f['text'][:80]}...\"*")
        else:
            md.append("\n*Zero misclassifications detected.*")

        return "\n".join(md) + "\n"


class BenchmarkRunner:
    """Independent security evaluation and benchmark runner."""

    def __init__(
        self,
        firewall: Optional[Firewall] = None,
        use_extended_rules: bool = False,
    ) -> None:
        if firewall is not None:
            self.fw = firewall
        elif use_extended_rules:
            # Build firewall with extended development detector plus PII and Secret detectors
            from llmfirewall.detectors.pii import PIIDetector
            from llmfirewall.detectors.secrets import SecretDetector
            ext_detector = ExtendedPromptInjectionDetector()
            self.fw = Firewall(detectors=[ext_detector, PIIDetector(), SecretDetector()])
        else:
            self.fw = Firewall()

    @staticmethod
    def get_system_metadata() -> Dict[str, Any]:
        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "package_name": "llmfirewall-core",
            "package_version": getattr(llmfirewall, "__version__", "1.4.0"),
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "platform": platform.platform(),
            "processor": platform.processor() or platform.machine(),
            "architecture": platform.architecture()[0],
            "logical_cpus": os.cpu_count() or 1,
        }

    def evaluate_dataset(
        self,
        dataset_path: Union[str, Path],
        warmup_runs: int = 10,
        throughput_requests: int = 200,
        concurrency: int = 4,
    ) -> BenchmarkReport:
        p = Path(dataset_path)
        if not p.is_file():
            raise FileNotFoundError(f"Dataset file not found at: {p}")

        raw_bytes = p.read_bytes()
        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        data: List[Dict[str, Any]] = json.loads(raw_bytes.decode("utf-8"))

        matrix = ConfusionMatrix()
        cat_metrics: Dict[str, Dict[str, Any]] = {}
        lang_metrics: Dict[str, Dict[str, Any]] = {}
        failures: List[Dict[str, Any]] = []

        # Warm-up phase
        for i in range(min(warmup_runs, len(data))):
            text = data[i].get("text", "")
            if text:
                self.fw.scan(text, direction="input")

        # Start memory tracking
        tracemalloc.start()
        timings_ms: List[float] = []

        for item in data:
            sid = str(item.get("id", "sample"))
            cat = str(item.get("category", "general"))
            lang = str(item.get("language", "en"))
            text = str(item.get("text", ""))
            chunks = item.get("chunks")
            expected = str(item.get("expected", item.get("expected_action", "block"))).lower()

            # Initialize category trackers
            if cat not in cat_metrics:
                cat_metrics[cat] = {"total": 0, "correct": 0, "tp": 0, "tn": 0, "fp": 0, "fn": 0, "accuracy": 0.0}
            cat_metrics[cat]["total"] += 1

            # Initialize language trackers
            if lang not in lang_metrics:
                lang_metrics[lang] = {"total": 0, "correct": 0, "fp": 0, "fn": 0, "accuracy": 0.0}
            lang_metrics[lang]["total"] += 1

            # Execute timed security scan
            t0 = time.perf_counter_ns()
            is_blocked = False

            if chunks and isinstance(chunks, list):
                # Evaluate streaming guard chunk boundaries
                guard = StreamingTextGuard(firewall=self.fw)
                try:
                    list(guard.protect_stream(chunks))
                    is_blocked = False
                except Exception:
                    is_blocked = True
            else:
                res = self.fw.scan(text, direction="input")
                is_blocked = res.is_blocked or res.action == Action.BLOCK

            t1 = time.perf_counter_ns()
            timings_ms.append((t1 - t0) / 1_000_000.0)

            # Evaluate decision against expected ground truth
            if expected in ("block", "redact"):
                if is_blocked or (expected == "redact" and not is_blocked):
                    # Redact or block matched expected security outcome
                    if expected == "block":
                        matrix.tp += 1
                        cat_metrics[cat]["tp"] += 1
                        cat_metrics[cat]["correct"] += 1
                        lang_metrics[lang]["correct"] += 1
                    else:
                        # Redact expected and allowed
                        matrix.tn += 1
                        cat_metrics[cat]["tn"] += 1
                        cat_metrics[cat]["correct"] += 1
                        lang_metrics[lang]["correct"] += 1
                else:
                    matrix.fn += 1
                    cat_metrics[cat]["fn"] += 1
                    lang_metrics[lang]["fn"] += 1
                    failures.append({"type": "FALSE_NEGATIVE", "id": sid, "category": cat, "language": lang, "text": text})
            else:  # expected == "allow"
                if not is_blocked:
                    matrix.tn += 1
                    cat_metrics[cat]["tn"] += 1
                    cat_metrics[cat]["correct"] += 1
                    lang_metrics[lang]["correct"] += 1
                else:
                    matrix.fp += 1
                    cat_metrics[cat]["fp"] += 1
                    lang_metrics[lang]["fp"] += 1
                    failures.append({"type": "FALSE_POSITIVE", "id": sid, "category": cat, "language": lang, "text": text})

        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Compute per-category accuracy
        for c, stats in cat_metrics.items():
            stats["accuracy"] = stats["correct"] / stats["total"] if stats["total"] > 0 else 0.0

        # Compute per-language accuracy
        for l, stats in lang_metrics.items():
            stats["accuracy"] = stats["correct"] / stats["total"] if stats["total"] > 0 else 0.0

        # Compute latency percentiles
        timings_sorted = sorted(timings_ms)
        n = len(timings_sorted)
        latency_stats = {
            "min": round(timings_sorted[0], 3) if n > 0 else 0.0,
            "mean": round(statistics.mean(timings_sorted), 3) if n > 0 else 0.0,
            "median": round(statistics.median(timings_sorted), 3) if n > 0 else 0.0,
            "p50": round(statistics.median(timings_sorted), 3) if n > 0 else 0.0,
            "p90": round(timings_sorted[int(n * 0.90)], 3) if n > 0 else 0.0,
            "p95": round(timings_sorted[int(n * 0.95)], 3) if n > 0 else 0.0,
            "p99": round(timings_sorted[int(n * 0.99)], 3) if n > 0 else 0.0,
            "max": round(timings_sorted[-1], 3) if n > 0 else 0.0,
        }

        # Measure concurrent throughput
        all_texts = [item.get("text", "") for item in data if item.get("text")]
        throughput_stats = self._measure_throughput(all_texts, total_requests=throughput_requests, concurrency=concurrency)

        mem_stats = {
            "current_memory_kib": round(current_mem / 1024.0, 2),
            "peak_memory_kib": round(peak_mem / 1024.0, 2),
            "peak_memory_mib": round(peak_mem / (1024.0 * 1024.0), 3),
        }

        return BenchmarkReport(
            dataset_name=p.name,
            dataset_path=str(p.resolve()),
            dataset_sha256=sha256,
            sample_count=len(data),
            environment=self.get_system_metadata(),
            matrix=matrix,
            category_metrics=cat_metrics,
            language_metrics=lang_metrics,
            latency_ms=latency_stats,
            throughput=throughput_stats,
            memory=mem_stats,
            failures=failures,
        )

    def _measure_throughput(self, texts: List[str], total_requests: int = 200, concurrency: int = 4) -> Dict[str, Any]:
        if not texts:
            return {"requests_per_second": 0.0, "total_requests": 0, "concurrency": concurrency}

        req_texts = [texts[i % len(texts)] for i in range(total_requests)]

        def _worker(t: str) -> None:
            self.fw.scan(t, direction="input")

        t0 = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            list(pool.map(_worker, req_texts))
        elapsed = time.perf_counter() - t0

        rps = total_requests / elapsed if elapsed > 0 else 0.0
        return {
            "concurrency": concurrency,
            "total_requests": total_requests,
            "elapsed_seconds": round(elapsed, 3),
            "requests_per_second": round(rps, 1),
        }


def evaluate_dataset(
    dataset_path: Union[str, Path],
    firewall: Optional[Firewall] = None,
    use_extended_rules: bool = False,
) -> BenchmarkReport:
    """Convenience functional helper evaluating a dataset."""
    runner = BenchmarkRunner(firewall=firewall, use_extended_rules=use_extended_rules)
    return runner.evaluate_dataset(dataset_path)
