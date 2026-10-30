"""CI-compatible Automated Security Regression and Benchmark Verification Suite (Phase 2).

Verifies:
1. Benchmark corpus integrity, schema conformity, and manifest alignment across 64 cases.
2. Mathematical correctness of effectiveness metric calculations (TP, FP, TN, FN, Precision, Recall, F1).
3. Deterministic regression assertions ensuring zero false positives on benign controls and zero regressions on critical attack vectors.
4. Performance SLA thresholds with runner-aware tolerances.
5. Byte-for-byte immutability of tests/test_secrets.py (SHA-256 invariant).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import pytest
import yaml

from benchmarks.runners.security_benchmark_runner import (
    CaseExecutionResult,
    SecurityBenchmarkRunner,
    compute_percentiles,
)

ROOT_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = ROOT_DIR / "benchmarks" / "dataset"
MANIFEST_PATH = DATASET_DIR / "manifest.json"
TEST_SECRETS_PATH = ROOT_DIR / "tests" / "test_secrets.py"
EXPECTED_SECRETS_SHA256 = "d5ca47fd85349bf4ef6d7944ab9a9f131aa27877b58bb90b31532203d7420e41"

ALLOWED_CATEGORIES = {
    "prompt_injection",
    "jailbreak",
    "sensitive_data",
    "tool_abuse",
    "rag_poisoning",
    "memory_poisoning",
    "data_exfiltration",
    "agent_attacks",
    "benign",
    "unicode_evasion",
    "malformed_oversized",
    "policy_precedence",
    "multi_turn",
}

ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
ALLOWED_ACTIONS = {"allow", "block", "redact", "warn", "review", "rate_limit"}


# =============================================================================
# 1. Byte-for-Byte Invariant Verification
# =============================================================================

def test_secrets_file_sha256_invariant():
    """Verify tests/test_secrets.py is preserved with exact required SHA-256 hash."""
    assert TEST_SECRETS_PATH.exists(), f"Missing required file: {TEST_SECRETS_PATH}"
    content = TEST_SECRETS_PATH.read_bytes()
    actual_sha256 = hashlib.sha256(content).hexdigest()
    assert actual_sha256 == EXPECTED_SECRETS_SHA256, (
        f"tests/test_secrets.py SHA-256 mismatch!\nExpected: {EXPECTED_SECRETS_SHA256}\nActual:   {actual_sha256}"
    )


# =============================================================================
# 2. Evaluation Corpus & Schema Integrity Tests
# =============================================================================

def test_manifest_matches_dataset_corpus():
    """Verify manifest.json metadata aligns with actual cases in the dataset."""
    assert MANIFEST_PATH.exists(), "Missing benchmarks/dataset/manifest.json"
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    assert manifest["dataset_version"] == "2.0.0"
    assert manifest["total_cases"] == 64

    # Load all cases from disk
    all_cases = []
    case_ids = set()
    cases_by_cat = {}

    for yaml_file in sorted(DATASET_DIR.rglob("*.yaml")):
        data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
        for c in data.get("cases", []):
            cid = c["id"]
            assert cid not in case_ids, f"Duplicate case ID detected: {cid}"
            case_ids.add(cid)
            all_cases.append(c)

            cat = c["category"]
            cases_by_cat[cat] = cases_by_cat.get(cat, 0) + 1

    assert len(all_cases) == 64, f"Expected 64 cases, found {len(all_cases)}"
    assert set(cases_by_cat.keys()) == set(manifest["categories"])
    for cat, count in manifest["cases_by_category"].items():
        assert cases_by_cat[cat] == count, f"Category count mismatch for {cat}: {cases_by_cat[cat]} vs {count}"


def test_case_schema_conformity():
    """Verify every case contains all mandatory fields with valid values."""
    runner = SecurityBenchmarkRunner()
    cases = runner.load_cases()
    assert len(cases) == 64

    for c in cases:
        cid = c.get("id")
        assert cid, f"Missing id in case: {c}"
        assert c.get("category") in ALLOWED_CATEGORIES, f"Invalid category in {cid}: {c.get('category')}"
        assert c.get("severity") in ALLOWED_SEVERITIES, f"Invalid severity in {cid}: {c.get('severity')}"
        assert c.get("expected_action") in ALLOWED_ACTIONS, f"Invalid expected_action in {cid}: {c.get('expected_action')}"
        assert isinstance(c.get("input"), str), f"Non-string input in {cid}"
        assert isinstance(c.get("description"), str) and len(c.get("description", "")) > 0, f"Empty description in {cid}"
        assert isinstance(c.get("rationale"), str) and len(c.get("rationale", "")) > 0, f"Empty rationale in {cid}"
        assert c.get("dataset_version") == "2.0", f"Unexpected dataset_version in {cid}"


# =============================================================================
# 3. Mathematical Metric Verification Tests
# =============================================================================

def test_metric_calculation_mathematics():
    """Test precision, recall, F1, and percentile calculations against controlled synthetic inputs."""
    runner = SecurityBenchmarkRunner()

    # Synthetic mock outcomes: 10 attacks (8 blocked, 2 allowed = 2 FN), 10 benign (9 allowed, 1 blocked = 1 FP)
    mock_results = []
    # 8 TP
    for i in range(8):
        mock_results.append(CaseExecutionResult(
            case_id=f"TP-{i}", category="test", subcategory="test", description="test", severity="high",
            input_text="x", expected_action="block", actual_action="block", expected_findings=[], actual_findings=[],
            findings_matched=True, matched_rules=[], reason="", latency_ms=1.0, passed=True, is_attack=True,
        ))
    # 2 FN
    for i in range(2):
        mock_results.append(CaseExecutionResult(
            case_id=f"FN-{i}", category="test", subcategory="test", description="test", severity="high",
            input_text="x", expected_action="block", actual_action="allow", expected_findings=[], actual_findings=[],
            findings_matched=False, matched_rules=[], reason="", latency_ms=1.0, passed=False, is_attack=True, is_false_negative=True,
        ))
    # 9 TN
    for i in range(9):
        mock_results.append(CaseExecutionResult(
            case_id=f"TN-{i}", category="test", subcategory="test", description="test", severity="info",
            input_text="x", expected_action="allow", actual_action="allow", expected_findings=[], actual_findings=[],
            findings_matched=True, matched_rules=[], reason="", latency_ms=1.0, passed=True, is_attack=False,
        ))
    # 1 FP
    for i in range(1):
        mock_results.append(CaseExecutionResult(
            case_id=f"FP-{i}", category="test", subcategory="test", description="test", severity="info",
            input_text="x", expected_action="allow", actual_action="block", expected_findings=[], actual_findings=[],
            findings_matched=False, matched_rules=[], reason="", latency_ms=1.0, passed=False, is_attack=False, is_false_positive=True,
        ))

    summary = runner._compile_security_summary(mock_results)
    cm = summary["confusion_matrix"]
    assert cm["true_positives"] == 8
    assert cm["false_negatives"] == 2
    assert cm["true_negatives"] == 9
    assert cm["false_positives"] == 1

    # Precision = 8 / (8 + 1) = 8/9 = 0.8889
    assert summary["metrics"]["precision"] == 0.8889
    # Recall = 8 / (8 + 2) = 8/10 = 0.8000
    assert summary["metrics"]["recall"] == 0.8000
    # F1 = 2 * (0.8889 * 0.8) / (0.8889 + 0.8) = 1.42224 / 1.6889 = 0.8421
    assert summary["metrics"]["f1_score"] == 0.8421
    # Accuracy = (8 + 9) / 20 = 17/20 = 0.85
    assert summary["accuracy"] == 0.85


def test_percentile_computation():
    """Verify compute_percentiles computes correct statistical percentiles."""
    values = [float(x) for x in range(1, 101)]  # 1.0 to 100.0
    st = compute_percentiles(values)
    assert st["min_ms"] == 1.0
    assert st["max_ms"] == 100.0
    assert 49.0 <= st["p50_ms"] <= 51.0
    assert 94.0 <= st["p95_ms"] <= 96.0
    assert 98.0 <= st["p99_ms"] <= 100.0


# =============================================================================
# 4. Security Effectiveness Regression Tests
# =============================================================================

def test_full_corpus_security_regression():
    """Execute entire 64-case security benchmark and verify regression thresholds."""
    runner = SecurityBenchmarkRunner()
    summary = runner.run_security_suite()

    # Zero false positives on benign inputs
    cm = summary["confusion_matrix"]
    assert cm["false_positives"] == 0, f"False positives detected: {cm['false_positives']}"
    assert summary["metrics"]["false_positive_rate"] == 0.0

    # Critical categories must have zero false negatives
    by_cat = summary["by_category"]
    critical_attack_categories = ["prompt_injection", "jailbreak", "tool_abuse", "rag_poisoning", "memory_poisoning", "sensitive_data"]
    for cat in critical_attack_categories:
        cat_data = by_cat.get(cat, {})
        cat_fn = cat_data.get("confusion_matrix", {}).get("false_negatives", 0)
        assert cat_fn == 0, f"Critical security category '{cat}' had {cat_fn} false negatives!"

    # Overall effectiveness thresholds
    assert summary["metrics"]["precision"] >= 0.95, f"Precision degraded below 95%: {summary['metrics']['precision']}"
    assert summary["metrics"]["recall"] >= 0.95, f"Recall degraded below 95%: {summary['metrics']['recall']}"
    assert summary["metrics"]["f1_score"] >= 0.95, f"F1 score degraded below 95%: {summary['metrics']['f1_score']}"
    assert summary["policy_decision_accuracy"] >= 0.95, f"Decision accuracy degraded: {summary['policy_decision_accuracy']}"

    # Only 1 documented limitation FN (Cyrillic homoglyph UNI-001) is expected
    assert cm["false_negatives"] <= 1


# =============================================================================
# 5. Performance SLA Verification Tests
# =============================================================================

def test_performance_sla_thresholds():
    """Verify local execution performance satisfies sub-millisecond SLAs."""
    runner = SecurityBenchmarkRunner()

    # 1. Cold Scan SLA: P50 must be under 2.0 ms (typical is ~0.2 ms)
    cold = runner._bench_cold_scanning(count=30)
    assert cold["p50_ms"] < 2.0, f"Cold scan P50 exceeded 2.0ms: {cold['p50_ms']}ms"
    assert cold["error_rate"] == 0.0

    # 2. Warm Cache SLA: P50 must be under 0.5 ms (typical is ~0.04 ms)
    warm = runner._bench_warm_cache(count=50)
    assert warm["p50_ms"] < 0.5, f"Warm cache P50 exceeded 0.5ms: {warm['p50_ms']}ms"
    assert warm["error_rate"] == 0.0

    # 3. Tool Calling SLA: P50 must be under 1.0 ms
    ag = runner._bench_agent_and_rag(iterations=30)
    assert ag["tool_call_inspection"]["p50_ms"] < 1.0, f"Tool inspection exceeded 1.0ms: {ag['tool_call_inspection']['p50_ms']}ms"
    assert ag["rag_context_filtering"]["p50_ms"] < 2.0, f"RAG filtering exceeded 2.0ms: {ag['rag_context_filtering']['p50_ms']}ms"
