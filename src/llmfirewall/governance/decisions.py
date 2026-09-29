"""Governance decision enums, reason codes, and evaluation result models for Phase 31."""

from enum import Enum
import time
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.models import Severity

if TYPE_CHECKING:
    from llmfirewall.governance.baseline import BaselineDiff
    from llmfirewall.governance.findings import GovernanceFinding
    from llmfirewall.governance.manifest import SecurityReleaseManifest


class GovernanceDecision(str, Enum):
    """Deterministic release governance decision.
    
    Invariants:
    - PASS: All required configured security gates are satisfied by verified evidence.
    - FAIL: One or more required security controls failed test/policy evaluation.
    - REVIEW: Evidence indicates acceptable risk boundaries or missing optional data requiring explicit human authorization.
    - BLOCK: Release is strictly prohibited by configured security policy.
    - NOT_EVALUATED: Required evidence or prerequisites are missing or unverified.
    """
    PASS = "PASS"
    FAIL = "FAIL"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"
    NOT_EVALUATED = "NOT_EVALUATED"


class ReasonCode(str, Enum):
    """Stable, machine-readable governance evaluation reason codes."""
    REQUIRED_GATE_FAILED = "REQUIRED_GATE_FAILED"
    CRITICAL_FINDING = "CRITICAL_FINDING"
    HIGH_SEVERITY_FINDING = "HIGH_SEVERITY_FINDING"
    SEVERITY_THRESHOLD_EXCEEDED = "SEVERITY_THRESHOLD_EXCEEDED"
    PASS_RATE_BELOW_THRESHOLD = "PASS_RATE_BELOW_THRESHOLD"
    MISSING_REQUIRED_TEST = "MISSING_REQUIRED_TEST"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"
    BASELINE_REGRESSION = "BASELINE_REGRESSION"
    MODEL_CHANGED = "MODEL_CHANGED"
    POLICY_CHANGED = "POLICY_CHANGED"
    CONFIGURATION_DRIFT = "CONFIGURATION_DRIFT"
    CAPABILITY_EXPANSION = "CAPABILITY_EXPANSION"
    PROMPT_CHANGED = "PROMPT_CHANGED"
    DEPENDENCY_CHANGED = "DEPENDENCY_CHANGED"
    RAG_PROVENANCE_CHANGED = "RAG_PROVENANCE_CHANGED"
    WAIVER_EXPIRED = "WAIVER_EXPIRED"
    UNAUTHORIZED_FINDING = "UNAUTHORIZED_FINDING"
    OVERRIDE_APPLIED = "OVERRIDE_APPLIED"
    TAMPERING_DETECTED = "TAMPERING_DETECTED"
    ALL_CONTROLS_SATISFIED = "ALL_CONTROLS_SATISFIED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class GateEvaluationResult(BaseModel):
    """Outcome of evaluating an individual SecurityGate."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    gate_id: str = Field(..., description="Unique gate identifier.")
    gate_type: str = Field(..., description="Type of gate evaluated (test, model, drift, etc.).")
    decision: GovernanceDecision = Field(..., description="Gate evaluation decision.")
    passed: bool = Field(..., description="True if gate criteria were satisfied or waived.")
    reason: str = Field(..., description="Deterministic human-readable rationale.")
    reason_codes: List[ReasonCode] = Field(default_factory=list, description="Machine-readable reason codes.")
    evidence_used: List[str] = Field(default_factory=list, description="Identifiers of evidence records evaluated.")
    policy_rule: Optional[str] = Field(default=None, description="Specific policy rule triggered if applicable.")
    details: Dict[str, Any] = Field(default_factory=dict, description="Structured evaluation details (no secrets).")


class GovernanceResult(BaseModel):
    """Immutable, comprehensive result of evaluating a release candidate against security governance policy.
    
    Security Invariants:
    1. Determinism: Identical inputs yield identical decisions and reason codes.
    2. Evidence-Based: Decisions cite specific evaluated gates and reason codes.
    3. Explicit Overrides: Overrides are prominently documented without erasing underlying failed gate evidence.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    release_id: str = Field(..., description="Correlating release candidate identifier.")
    decision: GovernanceDecision = Field(..., description="Overall governance release decision.")
    passed: bool = Field(..., description="True if release is permitted to proceed (PASS or authorized override).")
    blocked: bool = Field(..., description="True if release is prohibited from proceeding (BLOCK or non-overridden FAIL).")
    review_required: bool = Field(..., description="True if manual human review is required before release.")
    failed_gates: List[GateEvaluationResult] = Field(default_factory=list, description="List of failed gates.")
    passed_gates: List[GateEvaluationResult] = Field(default_factory=list, description="List of passed gates.")
    review_items: List[GateEvaluationResult] = Field(default_factory=list, description="Gates requiring human review.")
    missing_evidence: List[str] = Field(default_factory=list, description="Required evidence identifiers that were missing.")
    findings: List[Any] = Field(default_factory=list, description="Evaluated GovernanceFinding objects.")
    baseline_changes: Optional[Any] = Field(default=None, description="BaselineDiff if baseline comparison was performed.")
    reason_codes: List[ReasonCode] = Field(default_factory=list, description="Machine-readable root reason codes.")
    override: Optional[Dict[str, Any]] = Field(default=None, description="Recorded emergency override details if applied.")
    manifest: Optional[Any] = Field(default=None, description="SecurityReleaseManifest.")
    evaluated_at: float = Field(default_factory=time.time, description="Evaluation timestamp.")
    policy_version: str = Field(default="unknown", description="Evaluated policy version.")
    profile: str = Field(default="production", description="Evaluated release profile.")

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to clean dictionary omitting secrets."""
        return self.model_dump(mode="json")
