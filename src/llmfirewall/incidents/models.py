"""Domain models, enums, timeline entries, and evidence tracking for Phase 38: AI Security Incident Response & Investigation."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Set, Union
import uuid
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from llmfirewall.compliance.models import sanitize_compliance_metadata


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------

class IncidentSeverity(str, Enum):
    """Severity ratings for security events and incidents."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class IncidentStatus(str, Enum):
    """Lifecycle stages of a security incident."""
    DETECTED = "DETECTED"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    REOPENED = "REOPENED"


class IncidentAction(str, Enum):
    """Supported operational actions on a security incident."""
    ACKNOWLEDGE = "ACKNOWLEDGE"
    ASSIGN = "ASSIGN"
    CONTAIN = "CONTAIN"
    ESCALATE = "ESCALATE"
    RESOLVE = "RESOLVE"
    CLOSE = "CLOSE"
    REOPEN = "REOPEN"


class SecurityEventType(str, Enum):
    """Taxonomy of security-critical runtime events."""
    UNAUTHORIZED_TOOL_CALL = "UNAUTHORIZED_TOOL_CALL"
    PROMPT_INJECTION_DETECTED = "PROMPT_INJECTION_DETECTED"
    JAILBREAK_ATTEMPT = "JAILBREAK_ATTEMPT"
    PRIVILEGED_TOOL_CALL = "PRIVILEGED_TOOL_CALL"
    SECRET_EXPOSURE = "SECRET_EXPOSURE"
    DATA_EXFILTRATION_ATTEMPT = "DATA_EXFILTRATION_ATTEMPT"
    POLICY_BYPASS = "POLICY_BYPASS"
    ABNORMAL_AGENT_BEHAVIOR = "ABNORMAL_AGENT_BEHAVIOR"
    RAG_POISONING_ATTEMPT = "RAG_POISONING_ATTEMPT"
    MEMORY_POISONING_ATTEMPT = "MEMORY_POISONING_ATTEMPT"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    RUNTIME_ANOMALY = "RUNTIME_ANOMALY"
    GENERIC_SECURITY_EVENT = "GENERIC_SECURITY_EVENT"


# Valid status transitions
VALID_INCIDENT_TRANSITIONS: Dict[IncidentStatus, Set[IncidentStatus]] = {
    IncidentStatus.DETECTED: {IncidentStatus.TRIAGED, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED, IncidentStatus.RESOLVED, IncidentStatus.CLOSED},
    IncidentStatus.TRIAGED: {IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED, IncidentStatus.RESOLVED, IncidentStatus.CLOSED},
    IncidentStatus.INVESTIGATING: {IncidentStatus.CONTAINED, IncidentStatus.RESOLVED, IncidentStatus.CLOSED},
    IncidentStatus.CONTAINED: {IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED, IncidentStatus.CLOSED},
    IncidentStatus.RESOLVED: {IncidentStatus.CLOSED, IncidentStatus.REOPENED},
    IncidentStatus.CLOSED: {IncidentStatus.REOPENED},
    IncidentStatus.REOPENED: {IncidentStatus.TRIAGED, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED, IncidentStatus.RESOLVED, IncidentStatus.CLOSED},
}


# -----------------------------------------------------------------------------
# Event & Evidence Models
# -----------------------------------------------------------------------------

def compute_evidence_hash(data: Any) -> str:
    """Computes a deterministic SHA-256 hash of an evidence record."""
    try:
        serialized = json.dumps(data, sort_keys=True, default=str)
    except Exception:
        serialized = str(data)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class SecurityEvent(BaseModel):
    """Structured security-critical event emitted by runtime sensors, detectors, or tools."""
    id: str = Field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:12]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str
    source: str = "llmfirewall.runtime"
    asset_id: Optional[str] = None
    agent_id: Optional[str] = None
    tool_id: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    metadata: Dict[str, Any] = Field(default_factory=dict)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)

    model_config = ConfigDict(extra="ignore")

    @model_validator(mode="before")
    @classmethod
    def sanitize_secrets_in_event(cls, data: Any) -> Any:
        """Sanitizes metadata and evidence to avoid raw secret leakage."""
        if not isinstance(data, dict):
            return data
        
        # Sanitize metadata
        if "metadata" in data and isinstance(data["metadata"], dict):
            data["metadata"] = sanitize_compliance_metadata(data["metadata"])
            
        # Sanitize evidence
        if "evidence" in data and isinstance(data["evidence"], list):
            cleaned_ev = []
            for ev in data["evidence"]:
                if isinstance(ev, dict):
                    cleaned_ev.append(sanitize_compliance_metadata(ev))
                else:
                    cleaned_ev.append(ev)
            data["evidence"] = cleaned_ev
            
        return data


class EvidenceItem(BaseModel):
    """Preserved evidence artifact linked to an incident."""
    id: str = Field(default_factory=lambda: f"ev_{uuid.uuid4().hex[:8]}")
    event_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    asset_id: Optional[str] = None
    source: str = "runtime_inspection"
    evidence_hash: str
    collection_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    details: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="ignore")


class IncidentActionRecord(BaseModel):
    """Audit log entry of an action executed on an incident."""
    id: str = Field(default_factory=lambda: f"act_{uuid.uuid4().hex[:8]}")
    action: IncidentAction
    actor: str = "security_analyst"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notes: str = ""
    details: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="ignore")


class TimelineEntry(BaseModel):
    """Single chronological step in an incident's investigation timeline."""
    timestamp: datetime
    stage: str
    title: str
    description: str
    event_id: Optional[str] = None
    asset_id: Optional[str] = None
    evidence_hash: Optional[str] = None
    observed: bool = True  # True = empirical observation, False = inference / hypothesis

    model_config = ConfigDict(extra="ignore")


# -----------------------------------------------------------------------------
# Security Incident Model
# -----------------------------------------------------------------------------

class SecurityIncident(BaseModel):
    """Structured security incident representing correlated suspicious or malicious events."""
    id: str = Field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:6].upper()}")
    title: str
    description: str
    status: IncidentStatus = IncidentStatus.DETECTED
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    assets: List[str] = Field(default_factory=list)
    events: List[str] = Field(default_factory=list)  # list of event IDs
    attack_paths: List[str] = Field(default_factory=list)  # Correlated Phase 33 attack path IDs
    findings: List[str] = Field(default_factory=list)      # Correlated finding IDs
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    actions: List[IncidentActionRecord] = Field(default_factory=list)
    owner: Optional[str] = None

    model_config = ConfigDict(extra="ignore")

    @model_validator(mode="before")
    @classmethod
    def sanitize_incident_data(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        if "evidence" in data and isinstance(data["evidence"], list):
            cleaned = []
            for item in data["evidence"]:
                if isinstance(item, dict):
                    cleaned.append(sanitize_compliance_metadata(item))
                else:
                    cleaned.append(item)
            data["evidence"] = cleaned
        return data

    def can_transition_to(self, new_status: IncidentStatus) -> bool:
        """Checks if transitioning to new_status is valid under the lifecycle state machine."""
        allowed = VALID_INCIDENT_TRANSITIONS.get(self.status, set())
        return new_status in allowed

    def record_action(
        self,
        action: IncidentAction,
        actor: str = "security_analyst",
        notes: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> IncidentActionRecord:
        """Records an action in the incident audit trail."""
        record = IncidentActionRecord(
            action=action,
            actor=actor,
            notes=notes,
            details=details or {},
        )
        self.actions.append(record)
        return record
