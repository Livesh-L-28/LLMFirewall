"""Core domain models and contracts for LLMFirewall."""

from datetime import datetime, timezone
from enum import Enum
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ThreatType(str, Enum):
    """Categorization of security threats identified during inspection."""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    PII = "pii"
    SECRET = "secret"
    TOXICITY = "toxicity"
    MALICIOUS_URL = "malicious_url"
    HALLUCINATION = "hallucination"
    POLICY_VIOLATION = "policy_violation"
    CUSTOM = "custom"


class Severity(str, Enum):
    """Severity ratings for findings and aggregated risks.
    
    Comparable values allow threshold comparisons in risk/policy rules.
    """
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def level(self) -> int:
        """Numeric rank for severity comparisons."""
        ranks = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return ranks[self]

    def __ge__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.level >= other.level

    def __gt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.level > other.level

    def __le__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.level <= other.level

    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.level < other.level


class Action(str, Enum):
    """Action determined by the policy engine."""
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    REDACT = "redact"


# Backward compatibility alias
DecisionAction = Action


class Finding(BaseModel):
    """Represents an atomic detection event emitted by a detector.
    
    Adheres strictly to 'Detectors detect.'
    Does NOT contain policy decisions or blocking commands.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique finding ID")
    detector_name: str = Field(..., min_length=1, description="Identifier of the emitting detector")
    threat_type: ThreatType = Field(..., description="Standardized classification of threat")
    description: str = Field(..., min_length=1, description="Human-readable explanation of detection")
    severity: Severity = Field(..., description="Severity level assessed by detector")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    start_pos: Optional[int] = Field(default=None, ge=0, description="Character start offset in scanned text")
    end_pos: Optional[int] = Field(default=None, ge=0, description="Character end offset in scanned text")
    matched_text: Optional[str] = Field(default=None, description="Actual text segment matched (if safe)")
    replacement_text: Optional[str] = Field(default=None, description="Suggested redaction placeholder")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary detector metadata")

    @model_validator(mode="after")
    def validate_positions(self) -> "Finding":
        if self.start_pos is not None and self.end_pos is not None:
            if self.start_pos > self.end_pos:
                raise ValueError(f"start_pos ({self.start_pos}) cannot be greater than end_pos ({self.end_pos})")
        return self

    @property
    def category(self) -> str:
        """Convenience property for backward compatibility."""
        return self.threat_type.value


class RiskScore(BaseModel):
    """Quantified risk assessment produced by Risk Engine."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    score: float = Field(..., ge=0.0, le=1.0, description="Aggregated risk score between 0.0 and 1.0")
    max_severity: Severity = Field(..., description="Highest severity observed among findings")
    category_scores: Dict[str, float] = Field(default_factory=dict, description="Risk sub-scores per category")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional scoring metadata")


class PolicyDecision(BaseModel):
    """The decision produced by the Policy Engine."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    action: Action = Field(..., description="Policy action determined")
    reason: str = Field(..., description="Explanation of why action was selected")
    triggered_rules: List[str] = Field(default_factory=list, description="IDs of rules triggered")
    redacted_text: Optional[str] = Field(default=None, description="Text with sensitive spans redacted")
    policy_id: Optional[str] = Field(default=None, description="Unique identifier of evaluated policy")
    policy_version: Optional[str] = Field(default=None, description="Version string of evaluated policy")
    explanations: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Structured rule-by-rule matching explanations",
    )
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Policy execution metadata")


# Safety Boundary: Max single request text length (5MB string = ~5 million characters)
MAX_SCAN_TEXT_LENGTH: int = 5 * 1024 * 1024


class ScanRequest(BaseModel):
    """Request payload sent to the LLMFirewall orchestrator."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique scan request ID")
    text: str = Field(..., max_length=MAX_SCAN_TEXT_LENGTH, description="The content to scan (prompt or LLM output)")
    direction: str = Field(default="input", description="'input' or 'output'")
    user_id: Optional[str] = Field(default=None, max_length=256, description="Identifier of calling user or tenant")
    session_id: Optional[str] = Field(default=None, max_length=256, description="Session or conversation identifier")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Contextual metadata for detectors")

    @field_validator("direction")
    @classmethod
    def validate_direction(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if cleaned not in ("input", "output"):
            raise ValueError(f"direction must be 'input' or 'output', got '{v}'")
        return cleaned


class ScanResult(BaseModel):
    """Complete, end-to-end outcome of a firewall scan."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique result ID")
    request_id: str = Field(..., description="Correlating ScanRequest ID")
    decision: PolicyDecision = Field(..., description="Policy decision evaluated")
    risk_score: RiskScore = Field(..., description="Aggregated risk score")
    findings: List[Finding] = Field(default_factory=list, description="All individual detector findings")
    original_text: str = Field(default="", description="Original unscanned content")
    processed_text: str = Field(default="", description="Sanitized/redacted text safe for downstream")
    execution_time_ms: float = Field(default=0.0, ge=0.0, description="Pipeline latency in milliseconds")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="UTC timestamp")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Result metadata")

    @property
    def action(self) -> Action:
        """The resolved policy action (ALLOW, WARN, REDACT, BLOCK)."""
        return self.decision.action

    @property
    def is_allowed(self) -> bool:
        """True if the policy action is ALLOW, WARN, or REDACT (non-blocking)."""
        return self.decision.action in (Action.ALLOW, Action.WARN, Action.REDACT)

    @property
    def is_blocked(self) -> bool:
        """True if the policy action is BLOCK."""
        return self.decision.action == Action.BLOCK

    @property
    def text(self) -> str:
        """The final safe text to pass downstream."""
        return self.processed_text

    def safe_dict(self) -> Dict[str, Any]:
        """Serialize for logging/export, omitting sensitive original text and matched secrets."""
        data = self.model_dump()
        # Omit raw text to avoid leaking secrets/PII in log aggregators
        data["original_text"] = "[OMITTED_FOR_SAFETY]"
        for finding in data.get("findings", []):
            if finding.get("matched_text"):
                finding["matched_text"] = "[REDACTED_FROM_AUDIT]"
        return data


# Backward compatibility alias
FirewallResult = ScanResult


class AuditEvent(BaseModel):
    """Immutable audit record emitted for telemetry, compliance, and SIEM integration.
    
    Safe by default: automatically omits raw text payloads and secret snippets.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique event identifier")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="UTC timestamp")
    scan_id: str = Field(..., description="Associated scan result ID")
    request_id: Optional[str] = Field(default=None, description="Correlating client ScanRequest ID")
    action_taken: Action = Field(..., description="Action taken by the firewall")
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Numerical risk score")
    max_severity: Severity = Field(..., description="Maximum severity identified")
    threat_types: List[ThreatType] = Field(default_factory=list, description="Unique threat types detected")
    detection_categories: List[str] = Field(
        default_factory=list,
        description="Granular detection sub-categories (e.g. email, phone, api_key)",
    )
    detector_names: List[str] = Field(
        default_factory=list,
        description="Names of detectors that produced findings",
    )
    findings_count: int = Field(default=0, ge=0, description="Total number of findings")
    user_id: Optional[str] = Field(default=None, description="User/tenant identifier")
    session_id: Optional[str] = Field(default=None, description="Session ID")
    triggered_rules: List[str] = Field(default_factory=list, description="List of policy rules triggered")
    policy_id: Optional[str] = Field(default=None, description="Identifier of evaluated security policy")
    policy_version: Optional[str] = Field(default=None, description="Version of evaluated security policy")
    latency_ms: float = Field(default=0.0, ge=0.0, description="Scan execution latency in milliseconds")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Sanitized audit metadata")

    @classmethod
    def from_scan(
        cls,
        request: ScanRequest,
        result: ScanResult,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "AuditEvent":
        """Factory method to construct an audit event from a ScanRequest and ScanResult."""
        unique_threats = sorted(list({f.threat_type for f in result.findings}))
        detector_names = sorted(list({f.detector_name for f in result.findings}))
        categories = sorted(
            list(
                {
                    f.metadata.get("pii_category")
                    or f.metadata.get("rule_id")
                    or f.category
                    for f in result.findings
                }
            )
        )
        combined_meta = dict(metadata or {})
        return cls(
            scan_id=result.id,
            request_id=request.id,
            action_taken=result.decision.action,
            risk_score=result.risk_score.score,
            max_severity=result.risk_score.max_severity,
            threat_types=unique_threats,
            detection_categories=categories,
            detector_names=detector_names,
            findings_count=len(result.findings),
            user_id=request.user_id,
            session_id=request.session_id,
            triggered_rules=result.decision.triggered_rules,
            policy_id=result.decision.policy_id,
            policy_version=result.decision.policy_version,
            latency_ms=result.execution_time_ms,
            metadata=combined_meta,
        )
