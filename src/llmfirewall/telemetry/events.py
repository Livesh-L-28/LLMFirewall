"""Structured security telemetry events model and taxonomy."""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.models import (
    Action,
    ScanRequest,
    ScanResult,
    Severity,
)


class TelemetryEventType(str, Enum):
    """Stable event taxonomy for security telemetry."""
    SCAN = "firewall.scan"
    ALLOWED = "firewall.allowed"
    WARNED = "firewall.warned"
    BLOCKED = "firewall.blocked"
    REDACTED = "firewall.redacted"
    ERROR = "firewall.error"


class TelemetryEvent(BaseModel):
    """Structured security telemetry event model.
    
    Privacy Invariant:
    - Never stores raw prompt text, raw LLM outputs, raw secrets, or unmasked PII.
    - Captures operational metrics, threat categories, risk scores, and latency for SIEM/APM.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this telemetry event.",
    )
    event_type: TelemetryEventType = Field(
        ...,
        description="Canonical classification of this event.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the event was recorded.",
    )
    request_id: str = Field(
        ...,
        description="Correlation ID mapping to the client request.",
    )
    action: Action = Field(
        ...,
        description="Enforced policy decision action.",
    )
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Aggregated risk score in [0.0, 1.0].",
    )
    risk_level: Severity = Field(
        ...,
        description="Categorical risk severity level.",
    )
    threat_types: List[str] = Field(
        default_factory=list,
        description="List of detected ThreatType names.",
    )
    detection_categories: List[str] = Field(
        default_factory=list,
        description="Granular detection category names (e.g. email, api_key).",
    )
    findings_count: int = Field(
        default=0,
        ge=0,
        description="Total number of findings emitted.",
    )
    detector_names: List[str] = Field(
        default_factory=list,
        description="Names of detectors that produced findings.",
    )
    latency_ms: float = Field(
        default=0.0,
        ge=0.0,
        description="Total scan duration in milliseconds.",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Sanitized non-sensitive operational metadata.",
    )

    @classmethod
    def from_scan(
        cls,
        request: ScanRequest,
        result: ScanResult,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "TelemetryEvent":
        """Factory method constructing a telemetry event from a completed scan."""
        # Derive event_type from action
        action_map = {
            Action.ALLOW: TelemetryEventType.ALLOWED,
            Action.WARN: TelemetryEventType.WARNED,
            Action.BLOCK: TelemetryEventType.BLOCKED,
            Action.REDACT: TelemetryEventType.REDACTED,
        }
        event_type = action_map.get(result.decision.action, TelemetryEventType.SCAN)

        unique_threats = sorted(list({f.threat_type.value for f in result.findings}))
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

        safe_metadata = dict(metadata or {})
        safe_metadata["direction"] = request.direction
        if result.decision.policy_id:
            safe_metadata["policy_id"] = result.decision.policy_id
            safe_metadata["policy_version"] = result.decision.policy_version or "1.0"

        return cls(
            event_type=event_type,
            request_id=request.id,
            action=result.decision.action,
            risk_score=result.risk_score.score,
            risk_level=result.risk_score.max_severity,
            threat_types=unique_threats,
            detection_categories=categories,
            findings_count=len(result.findings),
            detector_names=detector_names,
            latency_ms=result.execution_time_ms,
            metadata=safe_metadata,
        )

    @classmethod
    def from_error(
        cls,
        request_id: str,
        error_message: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "TelemetryEvent":
        """Factory method constructing an error telemetry event."""
        safe_meta = dict(metadata or {})
        safe_meta["error_message"] = error_message
        return cls(
            event_type=TelemetryEventType.ERROR,
            request_id=request_id,
            action=Action.BLOCK,
            risk_score=1.0,
            risk_level=Severity.CRITICAL,
            threat_types=["error"],
            detection_categories=["system_error"],
            findings_count=0,
            detector_names=[],
            latency_ms=0.0,
            metadata=safe_meta,
        )
