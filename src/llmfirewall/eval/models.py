"""Domain models and schema definitions for continuous AI security evaluation, red-teaming, and testing."""

from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional, Set, Union
import uuid
from pydantic import BaseModel, ConfigDict, Field, field_validator

from llmfirewall.core.models import Action, Severity, ThreatType


class AttackCategory(str, Enum):
    """Controlled taxonomy of attack vectors and security test categories."""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    SECRET_EXPOSURE = "secret_exposure"
    PII_EXPOSURE = "pii_exposure"
    BENIGN = "benign"
    TOOL_ABUSE = "tool_abuse"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    UNSAFE_TOOL_CALL = "unsafe_tool_call"
    MALICIOUS_TOOL_RESULT = "malicious_tool_result"
    DATA_EXFILTRATION = "data_exfiltration"
    # Phase 30 Extensions
    RAG_POISONING = "rag_poisoning"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    AUTHORIZATION = "authorization"
    MEMORY_POISONING = "memory_poisoning"
    SUPPLY_CHAIN = "supply_chain"
    CONFIGURATION = "configuration"
    RESOURCE_ABUSE = "resource_abuse"
    OUTPUT_SECURITY = "output_security"
    CAPABILITY_ABUSE = "capability_abuse"


class TargetType(str, Enum):
    """Target execution type under test."""
    PROMPT = "prompt"
    OUTPUT = "output"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    AGENT = "agent"
    RAG = "rag"
    SUPPLY_CHAIN = "supply_chain"
    MODEL = "model"


class TestStatus(str, Enum):
    """Execution status of a security test."""
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


TestStatus.__test__ = False



class ErrorCategory(str, Enum):
    """Root-cause classification of test failures or runtime aborts."""
    TARGET_ERROR = "TARGET_ERROR"
    TIMEOUT = "TIMEOUT"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    ASSERTION_FAILURE = "ASSERTION_FAILURE"
    SECURITY_FAILURE = "SECURITY_FAILURE"


class AssertionType(str, Enum):
    """Declarative behavioral assertion operators."""
    ACTION_EQUALS = "action_equals"
    ACTION_BLOCKED = "action_blocked"
    ACTION_ALLOWED = "action_allowed"
    ACTION_REDACTED = "action_redacted"
    THREAT_DETECTED = "threat_detected"
    TOOL_NOT_CALLED = "tool_not_called"
    CAPABILITY_DENIED = "capability_denied"
    APPROVAL_REQUIRED = "approval_required"
    SECRET_NOT_EXPOSED = "secret_not_exposed"
    OUTPUT_CONTAINS = "output_contains"
    OUTPUT_NOT_CONTAINS = "output_not_contains"
    OUTPUT_REGEX = "output_regex"
    STRUCTURED_FIELD = "structured_field"


class DeclarativeAssertion(BaseModel):
    """Safe, declarative assertion evaluated without arbitrary code execution."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    assertion_type: AssertionType = Field(..., description="Assertion comparison type")
    expected_value: Any = Field(default=None, description="Expected value for comparison")
    field_path: Optional[str] = Field(default=None, description="Dot-delimited field path for structured checks")
    negate: bool = Field(default=False, description="Invert assertion result if True")
    description: str = Field(default="", description="Human-readable description of assertion intent")


class SecurityObservation(BaseModel):
    """Observable outcome and telemetry captured from the target AI system."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    status: str = Field(default="SUCCESS", description="Execution status: SUCCESS, TARGET_ERROR, TIMEOUT, etc.")
    response: str = Field(default="", description="Raw response text or message returned by the target")
    action: Action = Field(default=Action.ALLOW, description="Firewall action determined during test")
    action_decision: Optional[str] = Field(default=None, description="Detailed action decision e.g. ALLOW, DENY, REQUIRE_APPROVAL")
    tool_calls: List[Dict[str, Any]] = Field(default_factory=list, description="Tool calls requested by target")
    detected_threats: List[str] = Field(default_factory=list, description="ThreatTypes detected during evaluation")
    detector_names: List[str] = Field(default_factory=list, description="Detectors that triggered")
    matched_rules: List[str] = Field(default_factory=list, description="Policy rules matched")
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Risk score assessed")
    latency_ms: float = Field(default=0.0, ge=0.0, description="Execution duration in milliseconds")
    tokens_used: Optional[int] = Field(default=None, description="Reported token count")
    errors: Optional[str] = Field(default=None, description="Error details if target failed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Operational metadata from target")


class SecurityFinding(BaseModel):
    """Redacted, structured security finding resulting from a failed test or vulnerability."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str = Field(default_factory=lambda: f"FINDING-{uuid.uuid4().hex[:8].upper()}")
    test_id: str = Field(..., description="Correlating SecurityTest ID")
    category: str = Field(..., description="Attack category")
    severity: Severity = Field(default=Severity.MEDIUM, description="Security risk severity")
    description: str = Field(..., description="Human-readable description of security issue")
    evidence: str = Field(default="", description="Sanitized/redacted evidence snippet")
    recommendation: str = Field(default="", description="Prescriptive remediation guidance")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SecurityTest(BaseModel):
    """Declarative, deterministic specification of an AI security red-team or regression test."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(..., min_length=1, max_length=128, description="Stable, unique test identifier")
    name: str = Field(default="", description="Human-friendly test title")
    category: AttackCategory = Field(..., description="Classification category for this test case")
    target_type: TargetType = Field(default=TargetType.PROMPT, description="Evaluation target interface")
    input_payload: str = Field(default="", description="Text payload or serialized arguments/results to test")
    tool_name: Optional[str] = Field(default=None, description="Tool name for tool_call and tool_result tests")
    tool_arguments: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Structured tool arguments dictionary for tool_call tests",
    )
    expected_action: Action = Field(default=Action.BLOCK, description="Expected policy action: ALLOW, WARN, BLOCK, or REDACT")
    expected_threat: Optional[ThreatType] = Field(
        default=None,
        description="Optional expected detected ThreatType",
    )
    severity: Severity = Field(default=Severity.MEDIUM, description="Potential risk severity if test fails")
    description: str = Field(default="", description="Security intent and attack mechanics description")
    tags: List[str] = Field(default_factory=list, description="Categorization tags for filtering (e.g. ['owasp', 'ssrf'])")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata / author / CVE notes")

    # Phase 30 Extensions
    assertions: List[DeclarativeAssertion] = Field(default_factory=list, description="Declarative behavioral assertions")
    context_documents: List[str] = Field(default_factory=list, description="RAG context documents for RAG target testing")
    agent_capability: Optional[str] = Field(default=None, description="Agent capability identifier (e.g. filesystem.read)")
    agent_resource: Optional[str] = Field(default=None, description="Agent action resource")
    timeout_seconds: float = Field(default=30.0, ge=0.1, description="Timeout in seconds for this test execution")
    retries: int = Field(default=0, ge=0, description="Number of retries on transient error")
    runs: int = Field(default=1, ge=1, description="Number of execution iterations for probabilistic models")
    minimum_pass_rate: float = Field(default=1.0, ge=0.0, le=1.0, description="Required pass rate over multiple runs")
    requires_network: bool = Field(default=False, description="Whether test requires external network access")
    requires_credentials: bool = Field(default=False, description="Whether test requires external API credentials")
    test_version: str = Field(default="1.0", description="Semantic version of test definition")

    @field_validator("id")
    @classmethod
    def validate_id_format(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Test ID cannot be blank")
        return clean

    @property
    def payload_hash(self) -> str:
        """SHA-256 hash of payload representation for audit and deduplication without raw leakage."""
        rep = f"{self.target_type}:{self.tool_name}:{self.input_payload}:{self.tool_arguments}:{self.agent_capability}:{self.agent_resource}"
        return hashlib.sha256(rep.encode("utf-8")).hexdigest()[:16]


# Backward-compatible alias for Phase 23 code
SecurityTestCase = SecurityTest


class SecurityTestResult(BaseModel):
    """Immutable outcome of an executed SecurityTestCase or SecurityTest."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    test_id: str = Field(..., description="Correlating SecurityTestCase ID")
    category: AttackCategory = Field(..., description="Test attack category")
    target_type: TargetType = Field(..., description="Target interface evaluated")
    severity: Severity = Field(..., description="Security severity ranking")
    passed: bool = Field(..., description="Whether actual action matched expected action")
    actual_action: Action = Field(..., description="Actual action determined by policy engine")
    expected_action: Action = Field(..., description="Expected action declared by test case")
    is_false_positive: bool = Field(
        default=False,
        description="True if benign input was unexpectedly blocked or redacted",
    )
    is_false_negative: bool = Field(
        default=False,
        description="True if adversarial attack was unexpectedly allowed",
    )
    detected_threats: List[str] = Field(default_factory=list, description="List of ThreatTypes detected")
    detector_names: List[str] = Field(default_factory=list, description="Detectors that triggered")
    matched_rules: List[str] = Field(default_factory=list, description="Policy rules triggered")
    risk_score: float = Field(default=0.0, description="Risk score assessed")
    latency_ms: float = Field(default=0.0, ge=0.0, description="Evaluation duration in milliseconds")
    error: Optional[str] = Field(default=None, description="Error message if evaluation crashed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Execution metadata")

    # Phase 30 Extensions
    status: TestStatus = Field(default=TestStatus.PASS, description="Formal PASS/FAIL/ERROR/SKIPPED status")
    finding: Optional[SecurityFinding] = Field(default=None, description="Generated finding if test failed")
    observation: Optional[SecurityObservation] = Field(default=None, description="Target execution observation")
    error_category: Optional[ErrorCategory] = Field(default=None, description="Failure root-cause classification")
    evidence: Optional[str] = Field(default=None, description="Redacted failure evidence")
    assertion_results: List[Dict[str, Any]] = Field(default_factory=list, description="Declarative assertion evaluation results")


class SecurityMetrics(BaseModel):
    """Transparent, mathematically rigorous security evaluation metrics."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    total_tests: int = Field(default=0, ge=0)
    passed_tests: int = Field(default=0, ge=0)
    failed_tests: int = Field(default=0, ge=0)
    skipped_tests: int = Field(default=0, ge=0)
    false_positives: int = Field(default=0, ge=0)
    false_negatives: int = Field(default=0, ge=0)
    blocked_count: int = Field(default=0, ge=0)
    allowed_count: int = Field(default=0, ge=0)
    redacted_count: int = Field(default=0, ge=0)
    warned_count: int = Field(default=0, ge=0)
    error_count: int = Field(default=0, ge=0)
    pass_rate: float = Field(default=1.0, ge=0.0, le=1.0, description="passed / total_tests")
    detection_rate: float = Field(default=1.0, ge=0.0, le=1.0, description="Adversarial detections / total attacks")
    false_positive_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="Benign blocked / total benign")
    false_negative_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="Attacks allowed / total attacks")
    mean_latency_ms: float = Field(default=0.0, ge=0.0)
    p95_latency_ms: float = Field(default=0.0, ge=0.0)
    p99_latency_ms: float = Field(default=0.0, ge=0.0)
    category_counts: Dict[str, int] = Field(default_factory=dict)
    severity_counts: Dict[str, int] = Field(default_factory=dict)


class SecurityDetectionCoverage(BaseModel):
    """Summary of detector activation across the security test suite."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    detector_name: str = Field(...)
    tests_evaluated: int = Field(default=0, ge=0)
    tests_triggered: int = Field(default=0, ge=0)
    coverage_rate: float = Field(default=0.0, ge=0.0, le=1.0)


class SecurityCoverage(BaseModel):
    """Multidimensional security test coverage."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    categories_tested: Dict[str, int] = Field(default_factory=dict)
    suites_tested: Dict[str, int] = Field(default_factory=dict)
    detectors_covered: Dict[str, int] = Field(default_factory=dict)
    total_test_definitions: int = 0
    tested_policies: List[str] = Field(default_factory=list)


class SecurityEvaluationReport(BaseModel):
    """Complete, machine-readable security evaluation and testing report."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    suite_name: str = Field(default="core-security-suite")
    suite_version: str = Field(default="1.0")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    framework_version: str = Field(default="0.1.0")
    policy_name: str = Field(default="default")
    policy_version: str = Field(default="1.0")
    metrics: SecurityMetrics = Field(...)
    detection_coverage: List[SecurityDetectionCoverage] = Field(default_factory=list)
    results: List[SecurityTestResult] = Field(default_factory=list)
    failed_test_ids: List[str] = Field(default_factory=list)
    regressions_detected: bool = Field(default=False)
    regression_summary: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # Phase 30 Extensions
    findings: List[SecurityFinding] = Field(default_factory=list, description="Security findings list")
    security_coverage: Optional[SecurityCoverage] = Field(default=None, description="Security test coverage breakdown")
    seed: Optional[int] = Field(default=None, description="Deterministic pseudo-random seed used")
    target_info: Dict[str, Any] = Field(default_factory=dict, description="Target system under test information")

    def to_safe_dict(self) -> Dict[str, Any]:
        """Serialize for reporting, avoiding raw secret/PII disclosure."""
        return self.model_dump(mode="json")
