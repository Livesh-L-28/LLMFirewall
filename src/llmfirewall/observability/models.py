"""Structured Security Event model, Event Taxonomy, Decision Tracing, and Anomaly Models.

Phase 24: Production Observability & Security Intelligence.
Guarantees:
- Strict Privacy: Zero raw prompts, secrets, or unmasked PII in events by default.
- Deterministic Traceability: Trace ID, request ID, event ID, component attribution.
- Immutable and serializable.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.models import Action, Finding, PolicyDecision, RiskScore, ScanRequest, ScanResult, Severity, ThreatType


class SecurityEventType(str, Enum):
    """Controlled taxonomy of production security events."""
    REQUEST_STARTED = "request_started"
    REQUEST_COMPLETED = "request_completed"
    DETECTOR_TRIGGERED = "detector_triggered"
    RISK_CALCULATED = "risk_calculated"
    POLICY_EVALUATED = "policy_evaluated"
    SECURITY_DECISION = "security_decision"
    TOOL_CALL = "tool_call"
    TOOL_BLOCKED = "tool_blocked"
    TOOL_ALLOWED = "tool_allowed"
    TOOL_RESULT_SCANNED = "tool_result_scanned"
    REDACTION_APPLIED = "redaction_applied"
    ANOMALY_DETECTED = "anomaly_detected"
    SECURITY_REGRESSION = "security_regression"
    CONFIGURATION_CHANGED = "configuration_changed"


class EventSeverity(str, Enum):
    """Event severity levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_action_and_severity(cls, action: Action, severity: Severity) -> "EventSeverity":
        if action == Action.BLOCK:
            return cls.HIGH if severity != Severity.CRITICAL else cls.CRITICAL
        if action == Action.WARN or action == Action.REDACT:
            return cls.WARNING
        if severity in (Severity.HIGH, Severity.CRITICAL):
            return cls.WARNING
        return cls.INFO


def hash_content(content: str) -> str:
    """Produce SHA-256 digest of input content for correlation without storing raw data."""
    if not content:
        return ""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class SecurityEvent(BaseModel):
    """Production-grade structured security event.
    
    Privacy Invariant:
    - Never stores raw prompt, completion, secrets, or unmasked PII by default.
    - Stores payload_hash (SHA-256) and payload_length (bytes) instead.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = Field(default=1, description="Version of the event schema.")
    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this discrete security event.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timezone-aware UTC timestamp when event occurred.",
    )
    event_type: SecurityEventType = Field(
        ...,
        description="Classified event type from the taxonomy.",
    )
    severity: EventSeverity = Field(
        default=EventSeverity.INFO,
        description="Operational severity of the security event.",
    )
    trace_id: str = Field(
        default_factory=lambda: f"trace-{uuid.uuid4().hex[:16]}",
        description="Distributed or root trace correlation identifier.",
    )
    request_id: str = Field(
        ...,
        description="Request-level correlation identifier.",
    )
    component: str = Field(
        default="firewall",
        description="Originating subsystem (e.g. firewall, detector, policy, risk, tool).",
    )
    action: Optional[Action] = Field(
        default=None,
        description="Enforced action (ALLOW, WARN, REDACT, BLOCK).",
    )
    risk_level: Optional[Severity] = Field(
        default=None,
        description="Assigned categorical risk level (INFO, LOW, MEDIUM, HIGH, CRITICAL).",
    )
    risk_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Quantified composite risk score in [0.0, 1.0].",
    )
    threat_types: List[str] = Field(
        default_factory=list,
        description="Threat types detected (e.g. PROMPT_INJECTION, SECRET, PII).",
    )
    detector_name: Optional[str] = Field(
        default=None,
        description="Specific detector name that triggered or was evaluated.",
    )
    policy_id: Optional[str] = Field(
        default=None,
        description="Identifier of the policy document or matching rule.",
    )
    policy_version: Optional[str] = Field(
        default=None,
        description="Version string of the policy.",
    )
    tool_name: Optional[str] = Field(
        default=None,
        description="Tool name if associated with agent tool security.",
    )
    duration_ms: float = Field(
        default=0.0,
        ge=0.0,
        description="Execution duration in milliseconds.",
    )
    payload_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 hash of payload text (never the raw content).",
    )
    payload_length: int = Field(
        default=0,
        ge=0,
        description="Character or byte count of payload.",
    )
    application_id: Optional[str] = Field(
        default=None,
        description="Application identifier for multi-application environments.",
    )
    environment: str = Field(
        default="production",
        description="Execution environment (development, staging, production).",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Sanitized contextual attributes. Strictly non-sensitive.",
    )

    @classmethod
    def from_scan(
        cls,
        request: ScanRequest,
        result: ScanResult,
        trace_id: Optional[str] = None,
        store_raw_content: bool = False,
        application_id: Optional[str] = None,
        environment: str = "production",
    ) -> "SecurityEvent":
        """Construct a structured SecurityEvent from a completed ScanResult."""
        action = result.decision.action
        max_sev = result.risk_score.max_severity
        ev_severity = EventSeverity.from_action_and_severity(action, max_sev)

        # Content hashing
        p_hash = hash_content(request.text) if request.text else None
        p_len = len(request.text) if request.text else 0

        # Unique threat types and detectors
        threats = sorted(list({f.threat_type.value if hasattr(f.threat_type, "value") else str(f.threat_type) for f in result.findings}))
        det_names = sorted(list({f.detector_name for f in result.findings}))
        primary_det = det_names[0] if det_names else None

        # Build clean metadata
        meta: Dict[str, Any] = {
            "direction": request.direction,
            "findings_count": len(result.findings),
            "triggered_rules": result.decision.triggered_rules,
            "detectors_triggered": det_names,
        }
        if store_raw_content:
            meta["raw_content"] = request.text

        event_type = SecurityEventType.SECURITY_DECISION
        if action == Action.BLOCK:
            ev_severity = EventSeverity.HIGH if max_sev != Severity.CRITICAL else EventSeverity.CRITICAL
        elif action == Action.REDACT:
            event_type = SecurityEventType.REDACTION_APPLIED

        return cls(
            event_type=event_type,
            severity=ev_severity,
            trace_id=trace_id or f"trace-{request.id[:16]}",
            request_id=request.id,
            component="firewall",
            action=action,
            risk_level=max_sev,
            risk_score=result.risk_score.score,
            threat_types=threats,
            detector_name=primary_det,
            policy_id=result.decision.policy_id,
            policy_version=result.decision.policy_version,
            duration_ms=result.execution_time_ms,
            payload_hash=p_hash,
            payload_length=p_len,
            application_id=application_id,
            environment=environment,
            metadata=meta,
        )


class DecisionTraceStep(BaseModel):
    """Individual execution step within a deterministic decision trace."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    step_number: int
    component: str
    action_or_finding: str
    details: Dict[str, Any] = Field(default_factory=dict)
    duration_ms: float = 0.0


class DecisionTrace(BaseModel):
    """End-to-end explainable trace of a security decision.
    
    Answers:
    - What happened?
    - Why did it happen?
    - Which detector triggered?
    - Which policy matched?
    - What was the risk score?
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    trace_id: str
    request_id: str
    final_action: Action
    explanation: str
    steps: List[DecisionTraceStep] = Field(default_factory=list)
    risk_summary: Dict[str, Any] = Field(default_factory=dict)
    policy_summary: Dict[str, Any] = Field(default_factory=dict)
    total_duration_ms: float = 0.0

    @classmethod
    def from_scan_result(
        cls,
        request: ScanRequest,
        result: ScanResult,
        trace_id: Optional[str] = None,
    ) -> "DecisionTrace":
        steps: List[DecisionTraceStep] = []
        step_idx = 1

        # Step 1: Input Received
        steps.append(
            DecisionTraceStep(
                step_number=step_idx,
                component="request_handler",
                action_or_finding="request_received",
                details={
                    "direction": request.direction,
                    "payload_length": len(request.text),
                    "payload_hash": hash_content(request.text),
                },
                duration_ms=0.0,
            )
        )
        step_idx += 1

        # Step 2: Detectors
        if result.findings:
            for f in result.findings:
                rule_id = f.metadata.get("rule_id") if isinstance(f.metadata, dict) else None
                cat = getattr(f, "category", None) or f.metadata.get("category", f.threat_type.value)
                steps.append(
                    DecisionTraceStep(
                        step_number=step_idx,
                        component=f.detector_name,
                        action_or_finding="threat_detected",
                        details={
                            "threat_type": f.threat_type.value if hasattr(f.threat_type, "value") else str(f.threat_type),
                            "category": cat,
                            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                            "confidence": f.confidence,
                            "rule_id": rule_id,
                        },
                        duration_ms=0.0,
                    )
                )
                step_idx += 1
        else:
            steps.append(
                DecisionTraceStep(
                    step_number=step_idx,
                    component="detector_engine",
                    action_or_finding="no_threats_detected",
                    details={"findings_count": 0},
                    duration_ms=0.0,
                )
            )
            step_idx += 1

        # Step 3: Risk Evaluation
        steps.append(
            DecisionTraceStep(
                step_number=step_idx,
                component="risk_engine",
                action_or_finding="risk_calculated",
                details={
                    "composite_score": result.risk_score.score,
                    "max_severity": result.risk_score.max_severity.value,
                    "category_scores": result.risk_score.category_scores,
                },
                duration_ms=0.0,
            )
        )
        step_idx += 1

        # Step 4: Policy Enforcement
        steps.append(
            DecisionTraceStep(
                step_number=step_idx,
                component="policy_engine",
                action_or_finding=f"action_{result.decision.action.value.lower()}",
                details={
                    "policy_id": result.decision.policy_id,
                    "policy_version": result.decision.policy_version,
                    "triggered_rules": result.decision.triggered_rules,
                    "action": result.decision.action.value,
                },
                duration_ms=0.0,
            )
        )

        # Construct non-LLM, deterministic explanation string
        reasons = []
        if result.decision.action == Action.BLOCK:
            reasons.append(f"Blocked by policy '{result.decision.policy_id}'")
            if result.findings:
                threat_list = ", ".join(sorted({f.threat_type.value for f in result.findings}))
                reasons.append(f"Detected threats: [{threat_list}]")
            reasons.append(f"Risk level: {result.risk_score.max_severity.value} ({result.risk_score.score})")
        elif result.decision.action == Action.REDACT:
            reasons.append(f"Sensitive content sanitized by policy '{result.decision.policy_id}'")
            cats = sorted({getattr(f, "category", None) or f.metadata.get("category", f.threat_type.value) for f in result.findings})
            reasons.append(f"Redacted categories: {', '.join(cats)}")
        elif result.decision.action == Action.WARN:
            reasons.append(f"Warning issued by policy '{result.decision.policy_id}'")
        else:
            reasons.append("Request evaluated successfully with zero blocking violations.")

        explanation = "; ".join(reasons)

        return cls(
            trace_id=trace_id or f"trace-{request.id[:16]}",
            request_id=request.id,
            final_action=result.decision.action,
            explanation=explanation,
            steps=steps,
            risk_summary={
                "score": result.risk_score.score,
                "level": result.risk_score.max_severity.value,
                "categories": result.risk_score.category_scores,
            },
            policy_summary={
                "policy_id": result.decision.policy_id,
                "policy_version": result.decision.policy_version,
                "rules": result.decision.triggered_rules,
            },
            total_duration_ms=result.execution_time_ms,
        )


class AnomalyEvent(BaseModel):
    """Structured signal representing an observed anomaly in operational security behavior.
    
    Invariant:
    - Reports 'observed increase' or 'anomaly signal', never falsely asserting 'attack detected'
      without verified deterministic evidence.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    anomaly_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metric_name: str = Field(..., description="Target metric (e.g. block_rate, tool_denials, latency).")
    observed_value: float = Field(..., description="Current observed metric value.")
    baseline_value: float = Field(..., description="Baseline reference value.")
    deviation_percent: float = Field(..., description="Percentage change from baseline.")
    window_minutes: int = Field(default=60, description="Time window inspected.")
    severity: EventSeverity = Field(default=EventSeverity.WARNING)
    description: str = Field(..., description="Conservative factual description of observed change.")
