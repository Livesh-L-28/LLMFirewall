"""Comprehensive Security Benchmark Runner for LLMFirewall Phase 41.

Loads reproducible test cases from benchmarks/dataset/, executes them against LLMFirewall
runtime and core inspection engines, records empirical latencies and decision outcomes,
computes precision, recall, false positive/negative rates, and generates detailed reports.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import statistics
import sys
import time
from typing import Any, Dict, List, Optional
import yaml

from llmfirewall import Firewall, PolicyDecision, Scanner
from llmfirewall._version import __version__
from llmfirewall.protection import RuntimeRequest


@dataclass
class CaseExecutionResult:
    case_id: str
    category: str
    subcategory: str
    description: str
    severity: str
    input_text: str
    expected_action: str
    actual_action: str
    matched_rules: List[str]
    reason: str
    latency_ms: float
    passed: bool
    is_attack: bool
    is_false_positive: bool = False
    is_false_negative: bool = False


class SecurityBenchmarkRunner:
    """Executes benchmark suites, collects empirical results, and writes structured reports."""

    def __init__(self, dataset_dir: Optional[Path] = None, output_dir: Optional[Path] = None) -> None:
        self.root_dir = Path(__file__).resolve().parent.parent.parent
        self.dataset_dir = dataset_dir or (self.root_dir / "benchmarks" / "dataset")
        self.output_dir = output_dir or (self.root_dir / "reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.root_dir / "benchmarks" / "reports").mkdir(parents=True, exist_ok=True)

        self.firewall = Firewall()
        self.scanner = Scanner(self.firewall)

    def load_cases(self) -> List[Dict[str, Any]]:
        """Loads all test cases across all categories in the dataset directory."""
        all_cases: List[Dict[str, Any]] = []
        for yaml_file in sorted(self.dataset_dir.rglob("*.yaml")):
            try:
                data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "cases" in data:
                    all_cases.extend(data["cases"])
            except Exception as e:
                print(f"Error loading {yaml_file}: {e}")
        return all_cases

    def evaluate_case(self, case: Dict[str, Any]) -> CaseExecutionResult:
        """Executes a single test case against LLMFirewall and measures actual outcome."""
        cat = case.get("category", "unknown")
        subcat = case.get("subcategory", "")
        input_text = case.get("input", "")
        ctx = case.get("context", {})
        expected_action = case.get("expected_action", "block").lower()
        is_attack = expected_action != "allow"

        start_t = time.perf_counter()

        # Route evaluation according to scenario context
        if ctx.get("tool"):
            # Tool authorization / abuse scenario
            req = RuntimeRequest(
                input=input_text,
                tool={"name": ctx.get("tool"), "arguments": ctx.get("tool_args", {})},
            )
            decision = self.firewall.protection.inspect(req)
            actual_action = decision.decision.value.lower()
            matched_rules = decision.matched_policies
            reason = decision.reason

        elif ctx.get("rag_chunks"):
            # RAG context poisoning scenario
            req = RuntimeRequest(
                input=input_text,
                rag_context=[{"text": c} for c in ctx.get("rag_chunks", [])],
            )
            decision = self.firewall.protection.inspect(req)
            actual_action = decision.decision.value.lower()
            matched_rules = decision.matched_policies
            reason = decision.reason

        elif ctx.get("memory_candidate"):
            # Memory injection / poisoning scenario
            req = RuntimeRequest(
                input=input_text,
                memory_item={"text": ctx.get("memory_candidate")},
            )
            decision = self.firewall.protection.inspect(req)
            actual_action = decision.decision.value.lower()
            matched_rules = decision.matched_policies
            reason = decision.reason

        elif ctx.get("direction") == "output":
            # Output scanning / sensitive data / PII redaction via Runtime Protection
            decision = self.firewall.inspect(output=input_text)
            actual_action = decision.decision.value.lower()
            matched_rules = decision.matched_policies
            reason = decision.reason

        else:
            # Standard prompt injection / jailbreak / prompt checking
            res = self.firewall.check(input_text, direction="input")
            actual_action = res.decision.action.value.lower()
            matched_rules = res.decision.triggered_rules
            reason = res.decision.reason

        latency_ms = (time.perf_counter() - start_t) * 1000.0

        # Pass criteria: actual matches expected action
        passed = (actual_action == expected_action)
        is_fp = (not is_attack) and (actual_action != "allow")
        is_fn = is_attack and (actual_action == "allow")

        return CaseExecutionResult(
            case_id=case["id"],
            category=cat,
            subcategory=subcat,
            description=case.get("description", ""),
            severity=case.get("severity", "medium"),
            input_text=input_text,
            expected_action=expected_action,
            actual_action=actual_action,
            matched_rules=matched_rules,
            reason=reason,
            latency_ms=latency_ms,
            passed=passed,
            is_attack=is_attack,
            is_false_positive=is_fp,
            is_false_negative=is_fn,
        )

    def run_all(self) -> Dict[str, Any]:
        """Runs the entire benchmark suite and compiles statistical summary."""
        cases = self.load_cases()
        results: List[CaseExecutionResult] = []

        for c in cases:
            res = self.evaluate_case(c)
            results.append(res)

        # Performance baseline comparison
        perf_data = self._benchmark_performance_overhead()

        # Categorize results
        summary = self._compile_summary(results, perf_data)

        # Write reports
        self._write_reports(results, summary, perf_data)

        return summary

    def _benchmark_performance_overhead(self, iterations: int = 500) -> Dict[str, Any]:
        """Measures execution latency WITHOUT LLMFirewall vs WITH LLMFirewall."""
        sample_prompt = "Explain the difference between synchronous and asynchronous execution in computer science."

        # Baseline: Raw string passthrough
        baseline_latencies: List[float] = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            _ = sample_prompt.upper()
            baseline_latencies.append((time.perf_counter() - t0) * 1000.0)

        # With LLMFirewall Runtime Protection
        firewall_latencies: List[float] = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            _ = self.firewall.inspect(prompt=sample_prompt)
            firewall_latencies.append((time.perf_counter() - t0) * 1000.0)

        def stats(lats: List[float]) -> Dict[str, float]:
            sorted_l = sorted(lats)
            n = len(sorted_l)
            return {
                "mean_ms": round(statistics.mean(sorted_l), 4),
                "p50_ms": round(sorted_l[int(n * 0.50)], 4),
                "p95_ms": round(sorted_l[int(n * 0.95)], 4),
                "p99_ms": round(sorted_l[int(n * 0.99)], 4),
                "min_ms": round(min(sorted_l), 4),
                "max_ms": round(max(sorted_l), 4),
            }

        return {
            "iterations": iterations,
            "without_firewall": stats(baseline_latencies),
            "with_firewall": stats(firewall_latencies),
            "added_latency_p50_ms": round(stats(firewall_latencies)["p50_ms"] - stats(baseline_latencies)["p50_ms"], 4),
            "sub_millisecond_overhead": stats(firewall_latencies)["p50_ms"] < 1.0,
        }

    def _compile_summary(self, results: List[CaseExecutionResult], perf: Dict[str, Any]) -> Dict[str, Any]:
        total = len(results)
        passed = sum(1 for r in results if r.passed)
        failed = total - passed

        attacks = [r for r in results if r.is_attack]
        benigns = [r for r in results if not r.is_attack]

        tp = sum(1 for r in attacks if r.actual_action != "allow")
        fn = sum(1 for r in attacks if r.actual_action == "allow")
        tn = sum(1 for r in benigns if r.actual_action == "allow")
        fp = sum(1 for r in benigns if r.actual_action != "allow")

        precision = (tp / (tp + fp)) if (tp + fp) > 0 else 1.0
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else 1.0
        fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = (fn / (tp + fn)) if (tp + fn) > 0 else 0.0
        accuracy = (tp + tn) / total if total > 0 else 1.0

        latencies = [r.latency_ms for r in results]
        sorted_lats = sorted(latencies)
        n = len(sorted_lats)

        by_cat: Dict[str, Dict[str, Any]] = {}
        for r in results:
            cat_data = by_cat.setdefault(r.category, {"total": 0, "passed": 0, "failed": 0, "latencies": []})
            cat_data["total"] += 1
            if r.passed:
                cat_data["passed"] += 1
            else:
                cat_data["failed"] += 1
            cat_data["latencies"].append(r.latency_ms)

        for cat, data in by_cat.items():
            lats = sorted(data["latencies"])
            nl = len(lats)
            data["p50_ms"] = round(lats[int(nl * 0.5)], 3)
            data["p95_ms"] = round(lats[int(nl * 0.95)], 3)
            data["accuracy"] = round(data["passed"] / data["total"], 4)
            del data["latencies"]

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": __version__,
            "dataset_version": "benchmark dataset v1",
            "environment": {
                "platform": platform.platform(),
                "python_version": sys.version.split()[0],
                "cpu_architecture": platform.machine(),
            },
            "total_cases": total,
            "passed": passed,
            "failed": failed,
            "accuracy": round(accuracy, 4),
            "confusion_matrix": {
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn,
            },
            "metrics": {
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "false_positive_rate": round(fpr, 4),
                "false_negative_rate": round(fnr, 4),
                "p50_latency_ms": round(sorted_lats[int(n * 0.50)], 3),
                "p95_latency_ms": round(sorted_lats[int(n * 0.95)], 3),
                "p99_latency_ms": round(sorted_lats[int(n * 0.99)], 3),
            },
            "by_category": by_cat,
            "performance_overhead": perf,
        }

    def _write_reports(self, results: List[CaseExecutionResult], summary: Dict[str, Any], perf: Dict[str, Any]) -> None:
        """Writes all machine-readable JSON and human-readable Markdown reports."""
        # 1. Summary report
        sum_path = self.output_dir / "benchmark-summary.json"
        sum_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        (self.root_dir / "benchmarks" / "reports" / "benchmark-summary.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8"
        )

        # 2. Category-specific reports
        categories = sorted(list({r.category for r in results}))
        for cat in categories:
            cat_results = [r for r in results if r.category == cat]
            cat_json = {
                "category": cat,
                "total": len(cat_results),
                "passed": sum(1 for r in cat_results if r.passed),
                "failed": sum(1 for r in cat_results if not r.passed),
                "cases": [asdict(r) for r in cat_results],
            }
            # Output filenames
            slug = cat.replace("_", "-")
            json_file = self.output_dir / f"{slug}.json"
            json_file.write_text(json.dumps(cat_json, indent=2), encoding="utf-8")

            # Markdown report
            md_file = self.output_dir / f"{slug}.md"
            self._write_category_markdown(cat, cat_results, md_file)

        # 3. False Positives Report
        fps = [r for r in results if r.is_false_positive]
        fp_json = {
            "total_false_positives": len(fps),
            "false_positive_rate": summary["metrics"]["false_positive_rate"],
            "cases": [asdict(r) for r in fps],
        }
        (self.output_dir / "false-positives.json").write_text(json.dumps(fp_json, indent=2), encoding="utf-8")
        self._write_false_positives_markdown(fps, summary, self.output_dir / "false-positives.md")

        # 4. False Negatives Report
        fns = [r for r in results if r.is_false_negative]
        fn_json = {
            "total_false_negatives": len(fns),
            "false_negative_rate": summary["metrics"]["false_negative_rate"],
            "cases": [asdict(r) for r in fns],
        }
        (self.output_dir / "false-negatives.json").write_text(json.dumps(fn_json, indent=2), encoding="utf-8")
        self._write_false_negatives_markdown(fns, summary, self.output_dir / "false-negatives.md")

        # 5. Performance Report
        (self.output_dir / "performance.json").write_text(json.dumps(perf, indent=2), encoding="utf-8")
        self._write_performance_markdown(perf, self.output_dir / "performance.md")

        # 6. Runtime Protection Report
        rp_cases = [r for r in results if r.category in ("tool_abuse", "rag_poisoning", "memory_poisoning", "runtime_policy")]
        rp_json = {
            "total_runtime_protection_cases": len(rp_cases),
            "passed": sum(1 for r in rp_cases if r.passed),
            "cases": [asdict(r) for r in rp_cases],
        }
        (self.output_dir / "runtime-protection.json").write_text(json.dumps(rp_json, indent=2), encoding="utf-8")
        self._write_category_markdown("runtime_protection", rp_cases, self.output_dir / "runtime-protection.md")

        # 7. Regression Report
        reg_json = {
            "total_regression_cases": len(results),
            "regressions_detected": len(fns),
            "status": "PASS" if len(fns) == 0 else "FAIL",
            "cases": [asdict(r) for r in results if not r.passed],
        }
        (self.output_dir / "regression.json").write_text(json.dumps(reg_json, indent=2), encoding="utf-8")
        (self.output_dir / "regression.md").write_text(
            f"# Security Regression Report\n\n- **Status:** `{'PASS' if len(fns) == 0 else 'FAIL'}`\n"
            f"- **Regressions Detected:** {len(fns)}\n- **Total Evaluated Cases:** {len(results)}\n",
            encoding="utf-8",
        )

    def _write_category_markdown(self, category: str, results: List[CaseExecutionResult], path: Path) -> None:
        title = category.replace("_", " ").title()
        lines = [
            f"# {title} Security Benchmark Report",
            "",
            f"- **Category:** `{category}`",
            f"- **Total Evaluated Cases:** {len(results)}",
            f"- **Passed:** {sum(1 for r in results if r.passed)}",
            f"- **Failed:** {sum(1 for r in results if not r.passed)}",
            "",
            "## Evaluation Cases",
            "",
            "| ID | Subcategory | Severity | Expected | Actual | Latency | Outcome |",
            "|---|---|---|---|---|---|---|",
        ]
        for r in results:
            status = "**PASS**" if r.passed else "*FAIL*"
            lines.append(
                f"| `{r.case_id}` | {r.subcategory} | {r.severity.upper()} | `{r.expected_action.upper()}` | `{r.actual_action.upper()}` | {r.latency_ms:.2f}ms | {status} |"
            )
        lines.append("")
        path.write_text("\n".join(lines), encoding="utf-8")

    def _write_false_positives_markdown(self, fps: List[CaseExecutionResult], summary: Dict[str, Any], path: Path) -> None:
        lines = [
            "# False Positive Analysis Report",
            "",
            f"- **Total False Positives:** {len(fps)}",
            f"- **Empirical False Positive Rate (FPR):** `{summary['metrics']['false_positive_rate'] * 100:.2f}%`",
            f"- **Precision:** `{summary['metrics']['precision'] * 100:.2f}%`",
            "",
        ]
        if fps:
            lines.append("| ID | Category | Input Payload | Reason for False Trigger |")
            lines.append("|---|---|---|---|")
            for r in fps:
                lines.append(f"| `{r.case_id}` | {r.category} | `{r.input_text[:40]}...` | {r.reason} |")
        else:
            lines.append("> [!NOTE]\n> No false positives were detected across the evaluated benchmark corpus. All tested benign inputs correctly yielded `ALLOW`.")
        lines.append("")
        path.write_text("\n".join(lines), encoding="utf-8")

    def _write_false_negatives_markdown(self, fns: List[CaseExecutionResult], summary: Dict[str, Any], path: Path) -> None:
        lines = [
            "# False Negative Analysis Report",
            "",
            f"- **Total False Negatives (Undetected Attacks):** {len(fns)}",
            f"- **Empirical False Negative Rate (FNR):** `{summary['metrics']['false_negative_rate'] * 100:.2f}%`",
            f"- **Recall:** `{summary['metrics']['recall'] * 100:.2f}%`",
            "",
        ]
        if fns:
            lines.append("| ID | Category | Input Payload | Reason Missed |")
            lines.append("|---|---|---|---|")
            for r in fns:
                lines.append(f"| `{r.case_id}` | {r.category} | `{r.input_text[:40]}...` | {r.reason} |")
        else:
            lines.append("> [!NOTE]\n> Zero false negatives detected across the benchmark corpus. All simulated attacks were blocked, redacted, or gated for review according to policy.")
        lines.append("")
        path.write_text("\n".join(lines), encoding="utf-8")

    def _write_performance_markdown(self, perf: Dict[str, Any], path: Path) -> None:
        lines = [
            "# Performance Benchmark Report",
            "",
            f"- **Benchmark Iterations:** {perf['iterations']}",
            f"- **Sub-millisecond Runtime Overhead Verified:** `{'YES (<1ms)' if perf['sub_millisecond_overhead'] else 'NO'}`",
            f"- **Added Latency (P50):** `{perf['added_latency_p50_ms']} ms`",
            "",
            "## Latency Comparison",
            "",
            "| Metric | Without LLMFirewall | With LLMFirewall |",
            "|---|---|---|",
            f"| **P50 Latency** | `{perf['without_firewall']['p50_ms']} ms` | `{perf['with_firewall']['p50_ms']} ms` |",
            f"| **P95 Latency** | `{perf['without_firewall']['p95_ms']} ms` | `{perf['with_firewall']['p95_ms']} ms` |",
            f"| **P99 Latency** | `{perf['without_firewall']['p99_ms']} ms` | `{perf['with_firewall']['p99_ms']} ms` |",
            f"| **Mean Latency** | `{perf['without_firewall']['mean_ms']} ms` | `{perf['with_firewall']['mean_ms']} ms` |",
            "",
        ]
        path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    print("=" * 80)
    print("         LLMFirewall Phase 41: Security Benchmark Execution Engine             ")
    print("=" * 80)
    runner = SecurityBenchmarkRunner()
    summary = runner.run_all()
    print("\nBenchmark Execution Complete:")
    print(f"  Total Cases Evaluated: {summary['total_cases']}")
    print(f"  Passed:                {summary['passed']} / {summary['total_cases']}")
    print(f"  Accuracy:              {summary['accuracy'] * 100:.2f}%")
    print(f"  Precision:             {summary['metrics']['precision'] * 100:.2f}%")
    print(f"  Recall:                {summary['metrics']['recall'] * 100:.2f}%")
    print(f"  False Positive Rate:   {summary['metrics']['false_positive_rate'] * 100:.2f}%")
    print(f"  False Negative Rate:   {summary['metrics']['false_negative_rate'] * 100:.2f}%")
    print(f"  P50 Inspection Latency: {summary['metrics']['p50_latency_ms']:.3f} ms")
    print(f"  P95 Inspection Latency: {summary['metrics']['p95_latency_ms']:.3f} ms")
    print(f"  Performance Overhead:  {summary['performance_overhead']['with_firewall']['p50_ms']:.3f} ms (<1ms target: {summary['performance_overhead']['sub_millisecond_overhead']})")
    print("\nGenerated Reports:")
    print("  - reports/benchmark-summary.json")
    print("  - reports/prompt-injection.json & .md")
    print("  - reports/jailbreak.json & .md")
    print("  - reports/rag-security.json & .md")
    print("  - reports/agent-security.json & .md")
    print("  - reports/memory-security.json & .md")
    print("  - reports/sensitive-data.json & .md")
    print("  - reports/runtime-protection.json & .md")
    print("  - reports/false-positives.json & .md")
    print("  - reports/false-negatives.json & .md")
    print("  - reports/performance.json & .md")
    print("  - reports/regression.json & .md")


if __name__ == "__main__":
    main()
