"""Domain models, enums, requests, and decisions for Phase 39: AI Security Runtime Protection & Policy Enforcement."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import time
from typing import Any, Callable, Dict, List, Optional, Set, Union
import uuid
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from llmfirewall.compliance.models import sanitize_compliance_metadata


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------

class PolicyDecision(str, Enum):
    """Real-time policy decision values."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REDACT = "REDACT"
    REVIEW = "REVIEW"
    RATE_LIMIT = "RATE_LIMIT"


class PolicyMode(str, Enum):
    """Runtime operational policy enforcement mode."""
    DISABLED = "DISABLED"  # Completely bypass policy evaluation
    SHADOW = "SHADOW"      # Evaluate policies, record decisions, but do NOT block traffic
    ENFORCE = "ENFORCE"    # Strictly enforce policy decisions (ALLOW, BLOCK, REDACT, REVIEW)


class FailBehavior(str, Enum):
    """Explicit system failure behavior when runtime inspection encounters an unexpected exception."""
    FAIL_OPEN = "FAIL_OPEN"      # Allow request through on unhandled internal error (prioritizes availability)
    FAIL_CLOSED = "FAIL_CLOSED"  # Block request on unhandled internal error (prioritizes confidentiality/security)
    FAIL_REVIEW = "FAIL_REVIEW"  # Route request to security review on unhandled internal error


# -----------------------------------------------------------------------------
# Runtime Request & Decision Models
# -----------------------------------------------------------------------------

class RuntimeRequest(BaseModel):
    """Normalized payload representing an incoming runtime interaction."""
    request_id: str = Field(default_factory=lambda: f"req_{uuid.uuid4().hex[:12]}")
    session_id: Optional[str] = None
    agent_id: Optional[str] = None
    user_context: Dict[str, Any] = Field(default_factory=dict)
    input: Optional[str] = None
    tool: Optional[Dict[str, Any]] = None  # e.g. {"name": "...", "arguments": {...}}
    output: Optional[str] = None
    rag_context: Optional[List[Dict[str, Any]]] = None
    memory_item: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(extra="ignore")

    @model_validator(mode="before")
    @classmethod
    def sanitize_secrets_in_request(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "metadata" in data and isinstance(data["metadata"], dict):
                data["metadata"] = sanitize_compliance_metadata(data["metadata"])
            if "user_context" in data and isinstance(data["user_context"], dict):
                data["user_context"] = sanitize_compliance_metadata(data["user_context"])
        return data


class RuntimeDecision(BaseModel):
    """Comprehensive policy evaluation decision emitted by the runtime protection engine."""
    decision: PolicyDecision
    effective_decision: PolicyDecision  # Decision after applying PolicyMode (e.g. ALLOW if in SHADOW)
    reason: str
    matched_policies: List[str] = Field(default_factory=list)
    risk_factors: List[str] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    latency_ms: float = 0.0
    redacted_content: Optional[str] = None
    mode: PolicyMode = PolicyMode.ENFORCE
    request_id: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(extra="ignore")

    @property
    def is_blocked(self) -> bool:
        """Returns True if the effective decision blocks execution."""
        return self.effective_decision == PolicyDecision.BLOCK

    @property
    def is_allowed(self) -> bool:
        """Returns True if the effective decision allows execution."""
        return self.effective_decision == PolicyDecision.ALLOW

    @property
    def is_redacted(self) -> bool:
        """Returns True if the effective decision applied redaction."""
        return self.effective_decision == PolicyDecision.REDACT


class ProtectionAuditEntry(BaseModel):
    """Audit record generated for every runtime protection decision without leaking raw payloads."""
    request_id: str
    decision: str
    effective_decision: str
    mode: str
    policy: str
    reason: str
    asset: Optional[str] = None
    agent: Optional[str] = None
    tool: Optional[str] = None
    latency_ms: float
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(extra="ignore")
