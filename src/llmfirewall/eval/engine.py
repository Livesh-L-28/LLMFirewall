"""Test runner, metrics computation, and security regression detection engine."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from llmfirewall.core.models import Severity
from llmfirewall.eval.models import (
    AttackCategory,
    SecurityEvaluationReport,
    SecurityMetrics,
    SecurityTest,
    SecurityTestCase,
    SecurityTestResult,
)
from llmfirewall.eval.orchestrator import TestOrchestrator
from llmfirewall.eval.suites import SecurityTestSuite
from llmfirewall.eval.targets import EvaluationTarget
from llmfirewall.firewall import Firewall
from llmfirewall.policy.config import Policy


class SecurityEvaluationEngine(TestOrchestrator):
    """Orchestrates security evaluation, red-team simulation, and regression analysis.
    
    Maintains 100% backward compatibility with Phase 23 while leveraging Phase 30 continuous
    test orchestration, multi-worker execution, and evidence redaction.
    """

    def __init__(
        self,
        target: Optional[EvaluationTarget] = None,
        firewall: Optional[Firewall] = None,
        policy: Optional[Policy] = None,
    ) -> None:
        super().__init__(target=target, firewall=firewall, policy=policy)

    def run_suite(
        self,
        test_cases: Optional[List[SecurityTestCase]] = None,
        suite_name: str = "core-security-suite",
        suite_version: str = "1.0",
        baseline_file: Optional[Union[str, Path]] = None,
        category_filter: Optional[Set[AttackCategory]] = None,
        severity_filter: Optional[Set[Severity]] = None,
        tag_filter: Optional[Set[str]] = None,
        suite: Optional[SecurityTestSuite] = None,
        workers: int = 1,
        seed: Optional[int] = None,
        dry_run: bool = False,
    ) -> SecurityEvaluationReport:
        """Execute a collection of SecurityTestCases and compute transparent metrics and regressions."""
        return super().run_suite(
            suite=suite,
            test_cases=test_cases,
            suite_name=suite_name,
            suite_version=suite_version,
            baseline_file=baseline_file,
            category_filter=category_filter,
            severity_filter=severity_filter,
            tag_filter=tag_filter,
            workers=workers,
            seed=seed,
            dry_run=dry_run,
        )
