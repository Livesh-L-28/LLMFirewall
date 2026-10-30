"""Unified Security Event Schema & Incident Timeline Models.

Phase 4: Unified Security Event Correlation.
Guarantees:
- Schema Version 2.0: Canonical, stable schema with full backward-compatibility for SecurityEvent v1.0.
- Strict Privacy: Zero raw prompts, unredacted tokens, or plaintext secrets in event serialization.
- Deterministic Causal Ordering: Sequence numbers and parent_event_id links enable causal DAG construction.
- Strict Multi-Tenancy: Authoritative tenant_id ensures zero cross-tenant event contamination.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import uuid
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from llmfirewall.core.models import Action, Finding, ScanRequest, ScanResult, Severity, ThreatType
from llmfirewall.correlation.sanitizer import (
    REDACTED_CREDENTIAL_TOKEN,
    REDACTED_TEXT_TOKEN,
    sanitize_metadata,
    sanitize_string,
    sanitize_value,
)
from llmfirewall.observability.models import (
    DecisionTrace,
    DecisionTraceStep,
    EventSeverity,
    SecurityEvent,
    SecurityEventType,
)


class UnifiedSecurityEvent(BaseModel):
    """Canonical versioned security event schema (Schema v2.0).

    Provides complete attribution across prompt scanning, RAG retrieval, tool execution,
    policy evaluation, and multi-step agent reasoning.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(default="2.0", description="Event schema version.")
    event_id: str = Field(
        default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}",
        description="Globally unique identifier for this event.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timezone-aware UTC timestamp when event occurred.",
    )
    sequence_number: int = Field(
        default=0,
        ge=0,
        description="Monotonically increasing sequence number within a correlation session for causal ordering.",
    )
    event_type: SecurityEventType = Field(
        ...,
        description="Standardized event classification from the SecurityEventType taxonomy.",
    )
    severity: EventSeverity = Field(
        default=EventSeverity.INFO,
        description="Operational severity: DEBUG, INFO, WARNING, HIGH, CRITICAL.",
    )
    correlation_id: str = Field(
        ...,
        description="Authoritative identifier linking related events across a single request, multi-turn session, or workflow.",
    )
    request_id: str = Field(
        ...,
        description="Request-level correlation identifier.",
    )
    trace_id: Optional[str] = Field(
        default=None,
        description="Distributed tracing ID.",
    )
    workflow_id: Optional[str] = Field(
        default=None,
        description="Phase 3 workflow ID if event occurred within a multi-step agent workflow.",
    )
    tenant_id: Optional[str] = Field(
        default=None,
        description="Authoritative tenant identifier enforcing isolation boundaries.",
    )
    agent_id: Optional[str] = Field(
        default=None,
        description="Authorized agent identifier or persona.",
    )
    component: str = Field(
        default="firewall",
        description="Subsystem emitting the event (e.g. firewall, prompt_detector, rag_orchestrator, tool_enforcer).",
    )
    action: Optional[Action] = Field(
        default=None,
        description="Resolved security action (ALLOW, WARN, REDACT, BLOCK).",
    )
    outcome: str = Field(
        default="UNKNOWN",
        description="Deterministic outcome classification: ALLOWED, BLOCKED, REDACTED, WARNED, QUARANTINED, FAILED.",
    )
    safe_explanation: str = Field(
        default="",
        description="Human-readable and privacy-safe explanation of why the action was resolved (zero raw text).",
    )
    risk_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Quantified risk score in [0.0, 1.0].",
    )
    risk_level: Optional[Severity] = Field(
        default=None,
        description="Max severity of findings (INFO, LOW, MEDIUM, HIGH, CRITICAL).",
    )
    threat_types: List[str] = Field(
        default_factory=list,
        description="Unique threat types identified (e.g. PROMPT_INJECTION, SECRET, PII, PATH_TRAVERSAL).",
    )
    detector_name: Optional[str] = Field(
        default=None,
        description="Detector responsible for identifying threats.",
    )
    policy_id: Optional[str] = Field(
        default=None,
        description="Policy or rule ID that matched.",
    )
    policy_version: Optional[str] = Field(
        default=None,
        description="Policy version string.",
    )
    tool_name: Optional[str] = Field(
        default=None,
        description="Tool name if associated with agent tool execution.",
    )
    tool_call_id: Optional[str] = Field(
        default=None,
        description="Unique tool call execution identifier.",
    )
    parent_event_id: Optional[str] = Field(
        default=None,
        description="Direct causal parent event ID forming an explicit DAG.",
    )
    related_event_ids: List[str] = Field(
        default_factory=list,
        description="Associated event IDs in the same causal chain.",
    )
    error_type: Optional[str] = Field(
        default=None,
        description="Safe classification of any exception (class name without raw error message).",
    )
    duration_ms: float = Field(
        default=0.0,
        ge=0.0,
        description="Processing latency in milliseconds.",
    )
    payload_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 cryptographic digest of input/output text (never the raw content).",
    )
    payload_length: int = Field(
        default=0,
        ge=0,
        description="Character or byte length of the inspected payload.",
    )
    environment: str = Field(
        default="production",
        description="Deployment environment (development, staging, production).",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Sanitized contextual metadata dictionary (recursively scrubbed).",
    )

    @field_validator("safe_explanation", mode="after")
    @classmethod
    def _sanitize_explanation(cls, v: str) -> str:
        return sanitize_string(v) if v else ""

    @field_validator("metadata", mode="after")
    @classmethod
    def _sanitize_metadata_dict(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        return sanitize_metadata(v) if v else {}

    # -------------------------------------------------------------------------
    # Factory & Transformation Constructors
    # -------------------------------------------------------------------------

    @classmethod
    def from_security_event(
        cls,
        event: SecurityEvent,
        correlation_id: Optional[str] = None,
        sequence_number: int = 0,
        workflow_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
    ) -> "UnifiedSecurityEvent":
        """Convert a Phase 24 SecurityEvent (v1.0) to UnifiedSecurityEvent (v2.0)."""
        outcome = "UNKNOWN"
        if event.action == Action.BLOCK:
            outcome = "BLOCKED"
        elif event.action == Action.ALLOW:
            outcome = "ALLOWED"
        elif event.action == Action.REDACT:
            outcome = "REDACTED"
        elif event.action == Action.WARN:
            outcome = "WARNED"

        corr = correlation_id or event.trace_id or event.request_id

        return cls(
            schema_version="2.0",
            event_id=event.event_id,
            timestamp=event.timestamp,
            sequence_number=sequence_number,
            event_type=event.event_type,
            severity=event.severity,
            correlation_id=corr,
            request_id=event.request_id,
            trace_id=event.trace_id,
            workflow_id=workflow_id or event.metadata.get("workflow_id"),
            tenant_id=tenant_id or event.metadata.get("tenant_id"),
            agent_id=event.metadata.get("agent_id"),
            component=event.component,
            action=event.action,
            outcome=outcome,
            safe_explanation=f"Action {outcome} by {event.component} (detector: {event.detector_name or 'none'}).",
            risk_score=event.risk_score,
            risk_level=event.risk_level,
            threat_types=list(event.threat_types),
            detector_name=event.detector_name,
            policy_id=event.policy_id,
            policy_version=event.policy_version,
            tool_name=event.tool_name,
            parent_event_id=parent_event_id,
            duration_ms=event.duration_ms,
            payload_hash=event.payload_hash,
            payload_length=event.payload_length,
            environment=event.environment,
            metadata=sanitize_metadata(event.metadata),
        )

    @classmethod
    def from_scan_result(
        cls,
        request: ScanRequest,
        result: ScanResult,
        correlation_id: Optional[str] = None,
        sequence_number: int = 0,
        workflow_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
    ) -> "UnifiedSecurityEvent":
        """Construct a UnifiedSecurityEvent directly from a completed ScanResult."""
        action = result.decision.action
        max_sev = result.risk_score.max_severity
        ev_severity = EventSeverity.from_action_and_severity(action, max_sev)

        req_id = getattr(request, "request_id", None) or getattr(request, "id", None) or getattr(result, "request_id", None) or "req-unknown"
        corr = correlation_id or workflow_id or getattr(request, "session_id", None) or req_id
        eff_tenant = tenant_id or getattr(request, "tenant_id", None) or (request.metadata.get("tenant_id") if hasattr(request, "metadata") and isinstance(request.metadata, dict) else None) or getattr(request, "user_id", None)
        eff_agent = agent_id or (request.metadata.get("agent_id") if hasattr(request, "metadata") and isinstance(request.metadata, dict) else None)
        eff_wf = workflow_id or (request.metadata.get("workflow_id") if hasattr(request, "metadata") and isinstance(request.metadata, dict) else None)

        threat_names = [f.threat_type.value if hasattr(f.threat_type, "value") else str(f.threat_type) for f in result.findings]
        primary_det = result.findings[0].detector_name if result.findings else None

        content_hash = hashlib.sha256(request.text.encode("utf-8")).hexdigest() if request.text else None
        p_len = len(request.text) if request.text else 0

        outcome = "BLOCKED" if action == Action.BLOCK else ("REDACTED" if action == Action.REDACT else "ALLOWED")

        safe_reason = sanitize_string(result.decision.reason or "")
        if not safe_reason:
            if action == Action.BLOCK:
                threat_str = ", ".join(threat_names) if threat_names else "Policy Violation"
                safe_reason = f"Blocked by policy '{result.decision.policy_id}': threats detected: [{threat_str}]."
            elif action == Action.REDACT:
                safe_reason = f"Sanitized by policy '{result.decision.policy_id}'."
            else:
                safe_reason = "Evaluated successfully with zero blocking violations."

        return cls(
            schema_version="2.0",
            sequence_number=sequence_number,
            event_type=SecurityEventType.SECURITY_DECISION,
            severity=ev_severity,
            correlation_id=corr,
            request_id=req_id,
            trace_id=f"trace-{result.id[:12]}",
            workflow_id=eff_wf,
            tenant_id=eff_tenant,
            agent_id=eff_agent,
            component="firewall_scanner",
            action=action,
            outcome=outcome,
            safe_explanation=safe_reason,
            risk_score=result.risk_score.score,
            risk_level=max_sev,
            threat_types=threat_names,
            detector_name=primary_det,
            policy_id=result.decision.policy_id,
            policy_version=result.decision.policy_version,
            parent_event_id=parent_event_id,
            duration_ms=result.execution_time_ms,
            payload_hash=content_hash,
            payload_length=p_len,
            metadata=sanitize_metadata(request.metadata),
        )

    # -------------------------------------------------------------------------
    # Safe Serialization
    # -------------------------------------------------------------------------

    def safe_dict(self) -> Dict[str, Any]:
        """Produce a guaranteed privacy-safe dictionary suitable for SIEM, audits, and export."""
        dumped = self.model_dump(mode="json")
        # Ensure deep sanitization on any nested fields
        dumped["safe_explanation"] = sanitize_string(dumped.get("safe_explanation", ""))
        dumped["metadata"] = sanitize_metadata(dumped.get("metadata", {}))
        return dumped


class CorrelatedIncidentTimeline(BaseModel):
    """Chronologically sorted and causally linked timeline of security events."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    timeline_id: str = Field(default_factory=lambda: f"time-{uuid.uuid4().hex[:12]}")
    correlation_id: str = Field(..., description="Correlating identifier grouping these events.")
    tenant_id: Optional[str] = Field(default=None, description="Authoritative tenant ID.")
    workflow_id: Optional[str] = Field(default=None, description="Workflow ID if applicable.")
    request_id: Optional[str] = Field(default=None, description="Primary request ID.")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    total_duration_ms: float = 0.0

    events: List[UnifiedSecurityEvent] = Field(default_factory=list, description="Causally and chronologically ordered events.")
    total_events: int = Field(default=0, ge=0)
    max_severity: EventSeverity = Field(default=EventSeverity.INFO)
    final_action: Optional[Action] = None

    root_cause_event: Optional[UnifiedSecurityEvent] = None
    causal_chains: List[List[str]] = Field(default_factory=list, description="Chains of event IDs representing causal progression.")
    missing_events: List[str] = Field(default_factory=list, description="Detected missing events or sequence gaps.")
    is_incomplete: bool = Field(default=False, description="True if sequence gaps or dangling parent links were discovered.")
    diagnostic_summary: str = Field(default="", description="Human-readable executive summary of the incident timeline.")

    # -------------------------------------------------------------------------
    # Output Representations
    # -------------------------------------------------------------------------

    def safe_dict(self) -> Dict[str, Any]:
        """Produce privacy-safe machine-readable dictionary representation."""
        dumped = self.model_dump(mode="json")
        dumped["events"] = [e.safe_dict() if hasattr(e, "safe_dict") else e for e in self.events]
        dumped["diagnostic_summary"] = sanitize_string(self.diagnostic_summary)
        return dumped

    def to_markdown(self) -> str:
        """Produce formatted human-readable diagnostic report."""
        lines = [
            f"# Correlated Incident Timeline: `{self.correlation_id}`",
            "",
            f"- **Timeline ID**: `{self.timeline_id}`",
            f"- **Tenant**: `{self.tenant_id or 'Global / Non-Partitioned'}`",
            f"- **Workflow ID**: `{self.workflow_id or 'Single Request'}`",
            f"- **Total Events**: {self.total_events}",
            f"- **Peak Severity**: `{self.max_severity.value}`",
            f"- **Final Action**: `{self.final_action.value if self.final_action else 'NONE'}`",
            f"- **Trace Integrity**: `{'INCOMPLETE (gaps detected)' if self.is_incomplete else 'COMPLETE'}`",
            f"- **Duration**: `{self.total_duration_ms:.2f} ms`",
            "",
            "## Diagnostic Summary",
            sanitize_string(self.diagnostic_summary) if self.diagnostic_summary else "No anomalous incident patterns detected.",
            "",
        ]

        if self.missing_events:
            lines.extend([
                "### Incomplete Trace Warnings",
                *[f"- ⚠️ {sanitize_string(warn)}" for warn in self.missing_events],
                "",
            ])

        lines.extend([
            "## Chronological Causal Event Log",
            "",
            "| Seq | Timestamp | Event Type | Severity | Component | Action | Outcome | Safe Explanation |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ])

        for ev in self.events:
            ts_str = ev.timestamp.strftime("%H:%M:%S.%f")[:-3]
            act = ev.action.value if ev.action else "-"
            expl = sanitize_string(ev.safe_explanation).replace("|", "/")[:64]
            lines.append(
                f"| {ev.sequence_number} | {ts_str} | `{ev.event_type.value}` | `{ev.severity.value}` | `{ev.component}` | `{act}` | `{ev.outcome}` | {expl} |"
            )

        return "\n".join(lines) + "\n"
