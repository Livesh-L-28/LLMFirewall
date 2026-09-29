"""Public module exports for Continuous AI Security Testing, Evaluation, and Red-Team Engine."""

from llmfirewall.eval.adapters import (
    AgentAdapter,
    CallableAdapter,
    FirewallAdapter,
    HTTPTargetAdapter,
    MockAdapter,
    RAGAdapter,
    TargetAdapter,
)
from llmfirewall.eval.assertions import (
    evaluate_assertion,
    evaluate_assertions,
)
from llmfirewall.eval.engine import SecurityEvaluationEngine
from llmfirewall.eval.generators import (
    AgentCapabilityGenerator,
    BoundedFuzzer,
    PIIGenerator,
    PromptInjectionGenerator,
    RAGPoisoningGenerator,
    SecretGenerator,
    SecurityTestGenerator,
    ToolSecurityGenerator,
)
from llmfirewall.eval.mock_tools import MockToolRegistry
from llmfirewall.eval.models import (
    AssertionType,
    AttackCategory,
    DeclarativeAssertion,
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
from llmfirewall.eval.orchestrator import TestOrchestrator
from llmfirewall.eval.payloads import (
    create_mutations,
    get_builtin_security_test_cases,
)
from llmfirewall.eval.reporting import (
    format_html_report,
    format_human_report,
    format_json_report,
    format_junit_report,
    format_sarif_report,
)
from llmfirewall.eval.suites import (
    BUILTIN_SUITES,
    SecurityTestSuite,
    get_agent_capability_suite,
    get_configuration_integrity_suite,
    get_core_firewall_suite,
    get_full_red_team_suite,
    get_memory_security_suite,
    get_pii_suite,
    get_prompt_injection_suite,
    get_rag_security_suite,
    get_regression_suite,
    get_secret_suite,
    get_supply_chain_suite,
    get_tool_security_suite,
)
from llmfirewall.eval.targets import (
    EvaluationTarget,
    FirewallTarget,
)

__all__ = [
    # Core Engine & Orchestrator
    "TestOrchestrator",
    "SecurityEvaluationEngine",
    # Models
    "SecurityTest",
    "SecurityTestCase",
    "SecurityTestResult",
    "SecurityObservation",
    "SecurityFinding",
    "SecurityCoverage",
    "SecurityMetrics",
    "SecurityDetectionCoverage",
    "SecurityEvaluationReport",
    "AttackCategory",
    "TargetType",
    "TestStatus",
    "ErrorCategory",
    "AssertionType",
    "DeclarativeAssertion",
    # Adapters & Targets
    "EvaluationTarget",
    "FirewallTarget",
    "TargetAdapter",
    "FirewallAdapter",
    "MockAdapter",
    "HTTPTargetAdapter",
    "CallableAdapter",
    "AgentAdapter",
    "RAGAdapter",
    # Mock Tools
    "MockToolRegistry",
    # Suites
    "SecurityTestSuite",
    "BUILTIN_SUITES",
    "get_core_firewall_suite",
    "get_prompt_injection_suite",
    "get_pii_suite",
    "get_secret_suite",
    "get_tool_security_suite",
    "get_agent_capability_suite",
    "get_rag_security_suite",
    "get_memory_security_suite",
    "get_supply_chain_suite",
    "get_configuration_integrity_suite",
    "get_regression_suite",
    "get_full_red_team_suite",
    # Generators & Fuzzers
    "SecurityTestGenerator",
    "PromptInjectionGenerator",
    "PIIGenerator",
    "SecretGenerator",
    "ToolSecurityGenerator",
    "AgentCapabilityGenerator",
    "RAGPoisoningGenerator",
    "BoundedFuzzer",
    "create_mutations",
    "get_builtin_security_test_cases",
    # Assertions
    "evaluate_assertion",
    "evaluate_assertions",
    # Reporting
    "format_human_report",
    "format_json_report",
    "format_sarif_report",
    "format_junit_report",
    "format_html_report",
]
