"""TestOrchestrator: Unified test lifecycle management, parallel execution, evidence redaction, and audit."""

import concurrent.futures
import json
from pathlib import Path
import random
import statistics
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
import uuid

from llmfirewall._version import __version__
from llmfirewall.audit import AuditLogger, default_audit_logger
from llmfirewall.core.models import Action, Severity, ThreatType
from llmfirewall.detectors.pii.detector import PIIDetector
from llmfirewall.detectors.secrets.detector import SecretDetector
from llmfirewall.eval.adapters import FirewallAdapter, MockAdapter, TargetAdapter
from llmfirewall.eval.assertions import evaluate_assertions
from llmfirewall.eval.models import (
    AttackCategory,
    ErrorCategory,
    SecurityCoverage,
    SecurityDetectionCoverage,
    SecurityEvaluationReport,
    SecurityFinding,
    SecurityMetrics,
    SecurityObservation,
    SecurityTest,
    SecurityTestCase,
    SecurityTestResult,
    TargetType,
    TestStatus,
)
from llmfirewall.eval.suites import SecurityTestSuite, get_core_firewall_suite
from llmfirewall.eval.targets import EvaluationTarget, FirewallTarget
from llmfirewall.firewall import Firewall
from llmfirewall.policy.config import Policy
from llmfirewall.policy.redactor import SafeRedactor


class TestOrchestrator:
    """Continuous AI security test runner and red-team orchestration engine."""
    __test__ = False

    def __init__(
        self,
        target: Optional[Union[TargetAdapter, EvaluationTarget]] = None,
        firewall: Optional[Firewall] = None,
        policy: Optional[Policy] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        """Initialize orchestrator with target system, policy, and audit instrumentation."""
        if target is not None:
            if isinstance(target, TargetAdapter):
                self._target = target
            else:
                # Wrap existing EvaluationTarget
                self._target = target
        else:
            eff_fw = firewall or Firewall(policy=policy)
            self._target = FirewallAdapter(eff_fw)

        self._audit_logger = audit_logger or default_audit_logger
        self._pii_detector = PIIDetector()
        self._secret_detector = SecretDetector()
        self._redactor = SafeRedactor()

    @property
    def target(self) -> Union[TargetAdapter, EvaluationTarget]:
        return self._target

    def sanitize_text(self, text: str) -> str:
        """Redact any accidental secrets or PII from evidence strings before storage or reporting."""
        if not text:
            return ""
        findings = []
        try:
            findings.extend(self._secret_detector.detect(text))
            findings.extend(self._pii_detector.detect(text))
        except Exception:
            pass
        if findings:
            return self._redactor.redact(text, findings)
        return text

    def run_suite(
        self,
        suite: Optional[SecurityTestSuite] = None,
        test_cases: Optional[List[SecurityTest]] = None,
        suite_name: str = "core-security-suite",
        suite_version: str = "1.0",
        baseline_file: Optional[Union[str, Path]] = None,
        category_filter: Optional[Set[AttackCategory]] = None,
        severity_filter: Optional[Set[Severity]] = None,
        tag_filter: Optional[Set[str]] = None,
        workers: int = 1,
        seed: Optional[int] = None,
        dry_run: bool = False,
    ) -> SecurityEvaluationReport:
        """Execute a SecurityTestSuite or list of test cases across configurable worker threads."""
        run_id = f"testrun-{uuid.uuid4().hex[:8]}"

        # 1. Resolve test collection
        if suite is not None:
            eff_cases = list(suite.tests)
            s_name = suite.name
            s_ver = suite.version
        elif test_cases is not None:
            eff_cases = list(test_cases)
            s_name = suite_name
            s_ver = suite_version
        else:
            def_suite = get_core_firewall_suite()
            eff_cases = list(def_suite.tests)
            s_name = suite_name
            s_ver = suite_version

        # 2. Filter test cases
        selected_cases: List[SecurityTest] = []
        for case in eff_cases:
            if category_filter and case.category not in category_filter:
                continue
            if severity_filter and case.severity not in severity_filter:
                continue
            if tag_filter and not any(t in tag_filter for t in case.tags):
                continue
            selected_cases.append(case)

        # 3. Execute tests (parallel or single-threaded)
        results: List[SecurityTestResult] = []
        detector_trigger_counts: Dict[str, int] = {}

        if dry_run:
            # Dry run returns empty/skipped results
            return self._build_empty_report(s_name, s_ver, run_id, selected_cases)

        if workers > 1 and len(selected_cases) > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                future_to_case = {
                    executor.submit(self._execute_single_test, case, seed, run_id): case
                    for case in selected_cases
                }
                for future in concurrent.futures.as_completed(future_to_case):
                    res = future.result()
                    results.append(res)
        else:
            for case in selected_cases:
                res = self._execute_single_test(case, seed, run_id)
                results.append(res)

        # Sort results by original test ordering
        order_map = {c.id: i for i, c in enumerate(selected_cases)}
        results.sort(key=lambda r: order_map.get(r.test_id, 99999))

        # 4. Compute Metrics
        total = len(results)
        passed_count = sum(1 for r in results if r.passed)
        failed_count = sum(1 for r in results if not r.passed and r.status != TestStatus.SKIPPED)
        skipped_count = sum(1 for r in results if r.status == TestStatus.SKIPPED)
        err_count = sum(1 for r in results if r.status == TestStatus.ERROR)

        fp_count = sum(1 for r in results if r.is_false_positive)
        fn_count = sum(1 for r in results if r.is_false_negative)

        benign_total = sum(1 for c in selected_cases if c.category == AttackCategory.BENIGN or c.expected_action == Action.ALLOW)
        attack_total = total - benign_total

        blocked_count = sum(1 for r in results if r.actual_action == Action.BLOCK)
        allowed_count = sum(1 for r in results if r.actual_action == Action.ALLOW)
        redacted_count = sum(1 for r in results if r.actual_action == Action.REDACT)
        warned_count = sum(1 for r in results if r.actual_action == Action.WARN)

        pass_rate = (passed_count / total) if total > 0 else 1.0
        fp_rate = (fp_count / benign_total) if benign_total > 0 else 0.0
        fn_rate = (fn_count / attack_total) if attack_total > 0 else 0.0
        detection_rate = 1.0 - fn_rate

        latencies = [r.latency_ms for r in results if r.latency_ms > 0]
        sorted_latencies = sorted(latencies) if latencies else [0.0]
        mean_lat = statistics.mean(sorted_latencies) if sorted_latencies else 0.0
        p95_lat = sorted_latencies[int(len(sorted_latencies) * 0.95)] if sorted_latencies else 0.0
        p99_lat = sorted_latencies[int(len(sorted_latencies) * 0.99)] if sorted_latencies else 0.0

        cat_counts: Dict[str, int] = {}
        sev_counts: Dict[str, int] = {}
        for r in results:
            cat_counts[r.category.value] = cat_counts.get(r.category.value, 0) + 1
            sev_counts[r.severity.value] = sev_counts.get(r.severity.value, 0) + 1
            for d in r.detector_names:
                detector_trigger_counts[d] = detector_trigger_counts.get(d, 0) + 1

        metrics = SecurityMetrics(
            total_tests=total,
            passed_tests=passed_count,
            failed_tests=failed_count,
            skipped_tests=skipped_count,
            false_positives=fp_count,
            false_negatives=fn_count,
            blocked_count=blocked_count,
            allowed_count=allowed_count,
            redacted_count=redacted_count,
            warned_count=warned_count,
            error_count=err_count,
            pass_rate=round(pass_rate, 4),
            detection_rate=round(detection_rate, 4),
            false_positive_rate=round(fp_rate, 4),
            false_negative_rate=round(fn_rate, 4),
            mean_latency_ms=round(mean_lat, 4),
            p95_latency_ms=round(p95_lat, 4),
            p99_latency_ms=round(p99_lat, 4),
            category_counts=cat_counts,
            severity_counts=sev_counts,
        )

        # 5. Detector Coverage Summary
        coverage_list: List[SecurityDetectionCoverage] = []
        for det_name, trig_count in sorted(detector_trigger_counts.items()):
            cov_rate = trig_count / total if total > 0 else 0.0
            coverage_list.append(
                SecurityDetectionCoverage(
                    detector_name=det_name,
                    tests_evaluated=total,
                    tests_triggered=trig_count,
                    coverage_rate=round(cov_rate, 4),
                )
            )

        # 6. Multidimensional Coverage
        sec_cov = SecurityCoverage(
            categories_tested=cat_counts,
            suites_tested={s_name: total},
            detectors_covered=detector_trigger_counts,
            total_test_definitions=len(selected_cases),
        )

        # 7. Collect Findings
        findings: List[SecurityFinding] = []
        failed_ids: List[str] = []
        for r in results:
            if not r.passed:
                failed_ids.append(r.test_id)
                if r.finding is not None:
                    findings.append(r.finding)

        # 8. Baseline Comparison & Regressions
        regressions_detected = False
        reg_summary: Dict[str, Any] = {}
        if baseline_file:
            b_path = Path(baseline_file).resolve()
            if b_path.exists() and b_path.is_file():
                try:
                    baseline_data = json.loads(b_path.read_text(encoding="utf-8"))
                    reg_summary = self.compare_baseline(
                        current_metrics=metrics,
                        current_results=results,
                        baseline_data=baseline_data,
                    )
                    regressions_detected = reg_summary.get("regression_detected", False)
                except Exception as exc:
                    reg_summary = {"error": f"Failed to compare baseline: {exc}"}

        # Policy metadata if available
        pol_name = "default"
        pol_ver = "1.0"
        if isinstance(self._target, (FirewallAdapter, FirewallTarget)):
            fw = getattr(self._target, "firewall", None)
            if fw and hasattr(fw, "policy_engine"):
                pol_name = fw.policy_engine.policy.name
                pol_ver = fw.policy_engine.policy.version

        return SecurityEvaluationReport(
            report_id=run_id,
            suite_name=s_name,
            suite_version=s_ver,
            framework_version=__version__,
            policy_name=pol_name,
            policy_version=pol_ver,
            metrics=metrics,
            detection_coverage=coverage_list,
            security_coverage=sec_cov,
            findings=findings,
            results=results,
            failed_test_ids=failed_ids,
            regressions_detected=regressions_detected,
            regression_summary=reg_summary,
            seed=seed,
            target_info={"type": type(self._target).__name__},
        )

    def _execute_single_test(
        self,
        case: SecurityTest,
        seed: Optional[int],
        run_id: str,
    ) -> SecurityTestResult:
        """Execute a single test following Prepare -> Execute -> Observe -> Evaluate -> Cleanup."""
        # 1. Prepare
        if seed is not None:
            random.seed(seed)

        attempts_left = max(1, case.retries + 1)
        runs_count = max(1, case.runs)
        run_passes = 0
        last_obs: Optional[SecurityObservation] = None
        last_err: Optional[str] = None
        start_t = time.perf_counter()

        # 2. Execute & Observe (supports retries & multiple runs)
        for r_idx in range(runs_count):
            iter_success = False
            for attempt in range(attempts_left):
                try:
                    # Timeout enforcement using concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as single_executor:
                        if isinstance(self._target, TargetAdapter):
                            future = single_executor.submit(self._target.execute, case)
                        else:
                            # EvaluationTarget fallback
                            def _eval_target():
                                act, sc, th, dn, mr = self._target.evaluate_test_case(case)
                                return SecurityObservation(
                                    action=act,
                                    risk_score=sc,
                                    detected_threats=th,
                                    detector_names=dn,
                                    matched_rules=mr,
                                )
                            future = single_executor.submit(_eval_target)

                        obs = future.result(timeout=case.timeout_seconds)
                        last_obs = obs
                        iter_success = True
                        break
                except concurrent.futures.TimeoutError:
                    last_err = f"Execution timed out after {case.timeout_seconds}s"
                    last_obs = SecurityObservation(
                        status="TIMEOUT",
                        action=Action.BLOCK,
                        errors=last_err,
                    )
                except Exception as exc:
                    last_err = str(exc)
                    last_obs = SecurityObservation(
                        status="TARGET_ERROR",
                        action=Action.BLOCK,
                        errors=last_err,
                    )

            if iter_success and last_obs:
                # 3. Evaluate assertions on this iteration
                act_matches = (last_obs.action == case.expected_action)
                assert_pass, assert_results, fail_reason = evaluate_assertions(case.assertions, last_obs)
                if act_matches and assert_pass and (last_obs.errors is None):
                    run_passes += 1

        latency = (time.perf_counter() - start_t) * 1000.0

        # Overall pass rate across multiple runs
        actual_pass_rate = (run_passes / runs_count) if runs_count > 0 else 0.0
        passed = (actual_pass_rate >= case.minimum_pass_rate) and (last_obs is not None) and (last_obs.errors is None)

        action = last_obs.action if last_obs else Action.ALLOW
        score = last_obs.risk_score if last_obs else 0.0
        threats = last_obs.detected_threats if last_obs else []
        det_names = last_obs.detector_names if last_obs else []
        matched_rules = last_obs.matched_rules if last_obs else []

        # Classification of False Positive / False Negative
        is_benign = (case.category == AttackCategory.BENIGN) or (case.expected_action == Action.ALLOW)
        is_fp = is_benign and (action in (Action.BLOCK, Action.REDACT))
        is_fn = (not is_benign) and (case.expected_action in (Action.BLOCK, Action.REDACT)) and (action == Action.ALLOW)

        # Status & Error Category
        if passed:
            status = TestStatus.PASS
            err_category = None
        elif last_obs and last_obs.status == "TIMEOUT":
            status = TestStatus.ERROR
            err_category = ErrorCategory.TIMEOUT
        elif last_obs and last_obs.status == "TARGET_ERROR":
            status = TestStatus.ERROR
            err_category = ErrorCategory.TARGET_ERROR
        else:
            status = TestStatus.FAIL
            err_category = ErrorCategory.SECURITY_FAILURE

        # Generate finding and sanitize evidence if failed
        finding = None
        evidence_str = None
        if not passed:
            raw_evidence = (
                f"Test {case.id} failed: expected {case.expected_action.value}, "
                f"got {action.value}. Threats detected: {threats}. Error: {last_err or 'None'}"
            )
            evidence_str = self.sanitize_text(raw_evidence)
            recom = f"Configure security policies to reject {case.category.value} attack patterns."
            finding = SecurityFinding(
                test_id=case.id,
                category=case.category.value,
                severity=case.severity,
                description=case.description or f"Failed security control {case.name}",
                evidence=evidence_str,
                recommendation=recom,
            )

        # 4. Cleanup (Always executed)
        try:
            pass  # Stateless target cleanup hook
        except Exception:
            pass

        return SecurityTestResult(
            test_id=case.id,
            category=case.category,
            target_type=case.target_type,
            severity=case.severity,
            passed=passed,
            actual_action=action,
            expected_action=case.expected_action,
            is_false_positive=is_fp,
            is_false_negative=is_fn,
            detected_threats=threats,
            detector_names=det_names,
            matched_rules=matched_rules,
            risk_score=score,
            latency_ms=round(latency, 4),
            error=last_err,
            status=status,
            finding=finding,
            observation=last_obs,
            error_category=err_category,
            evidence=evidence_str,
            metadata={"name": case.name, "description": case.description},
        )

    def _build_empty_report(
        self,
        suite_name: str,
        suite_version: str,
        run_id: str,
        cases: List[SecurityTest],
    ) -> SecurityEvaluationReport:
        """Generate a skipped/dry-run report without executing targets."""
        metrics = SecurityMetrics(
            total_tests=len(cases),
            skipped_tests=len(cases),
            pass_rate=1.0,
        )
        return SecurityEvaluationReport(
            report_id=run_id,
            suite_name=suite_name,
            suite_version=suite_version,
            framework_version=__version__,
            metrics=metrics,
            metadata={"dry_run": True},
        )

    @staticmethod
    def compare_baseline(
        current_metrics: SecurityMetrics,
        current_results: List[SecurityTestResult],
        baseline_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Compare current evaluation results against a stored baseline."""
        prev_failed_ids: Set[str] = set(baseline_data.get("failed_test_ids", []))
        curr_failed_map = {r.test_id: r for r in current_results if not r.passed}
        curr_failed_ids = set(curr_failed_map.keys())

        new_failures = sorted(list(curr_failed_ids - prev_failed_ids))
        fixed_tests = sorted(list(prev_failed_ids - curr_failed_ids))

        base_metrics = baseline_data.get("metrics", {})
        base_fn = base_metrics.get("false_negatives", 0)
        base_fp = base_metrics.get("false_positives", 0)

        fn_delta = current_metrics.false_negatives - base_fn
        fp_delta = current_metrics.false_positives - base_fp

        has_regression = (len(new_failures) > 0) or (fn_delta > 0) or (fp_delta > 0)

        return {
            "regression_detected": has_regression,
            "new_failures": new_failures,
            "fixed_tests": fixed_tests,
            "false_negative_delta": fn_delta,
            "false_positive_delta": fp_delta,
            "baseline_failed_count": len(prev_failed_ids),
            "current_failed_count": len(curr_failed_ids),
        }
