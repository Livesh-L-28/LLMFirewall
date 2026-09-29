"""Data models and value types for agent and tool-call security."""

from datetime import datetime, timezone
from enum import Enum
import json
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from llmfirewall.core.models import Action, Finding, RiskScore, Severity, ThreatType


class ToolPermission(str, Enum):
    """Standardized granular permission taxonomy for agent tools.
    
    Adheres to the principle of least privilege:
    - READ: Read-only access to benign resources or calculations.
    - WRITE: Mutating resources or writing state.
    - NETWORK: External HTTP or socket access.
    - FILESYSTEM: Local disk read/write access.
    - DATABASE: Relational or document database queries.
    - EXECUTE: Shell, subprocess, or code evaluation execution.
    - EXTERNAL_API: Calling 3rd-party SaaS or webhook endpoints.
    - CUSTOM: Custom enterprise permission tag.
    """
    READ = "read"
    WRITE = "write"
    NETWORK = "network"
    FILESYSTEM = "filesystem"
    DATABASE = "database"
    EXECUTE = "execute"
    EXTERNAL_API = "external_api"
    CUSTOM = "custom"


class ToolCall(BaseModel):
    """Immutable representation of an AI agent's requested tool invocation."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique tool call invocation ID")
    tool_name: str = Field(..., min_length=1, max_length=128, description="Identifier of target tool")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Structured arguments passed to the tool")
    request_id: Optional[str] = Field(default=None, description="Correlating client or session request ID")
    user_id: Optional[str] = Field(default=None, description="Calling user or tenant identifier")
    session_id: Optional[str] = Field(default=None, description="Conversation session identifier")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Contextual execution metadata")

    @field_validator("tool_name")
    @classmethod
    def normalize_tool_name(cls, v: str) -> str:
        clean = v.strip().lower()
        if not clean:
            raise ValueError("tool_name cannot be empty or whitespace")
        return clean

    def serialize_arguments(self) -> str:
        """Deterministic string serialization of arguments for text-based detector inspection."""
        try:
            return json.dumps(self.arguments, sort_keys=True, ensure_ascii=False)
        except Exception:
            return str(self.arguments)


class ToolResult(BaseModel):
    """Immutable representation of the raw output produced by an executed tool."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique tool result ID")
    tool_name: str = Field(..., min_length=1, max_length=128, description="Name of tool that produced result")
    output: str = Field(..., description="Raw text, JSON, or stringified payload produced by the tool")
    tool_call_id: Optional[str] = Field(default=None, description="Correlating ToolCall ID")
    request_id: Optional[str] = Field(default=None, description="Correlating client request ID")
    success: bool = Field(default=True, description="Whether tool execution completed without error")
    error: Optional[str] = Field(default=None, description="Error message if tool execution failed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata associated with tool output")

    @field_validator("tool_name")
    @classmethod
    def normalize_tool_name(cls, v: str) -> str:
        clean = v.strip().lower()
        if not clean:
            raise ValueError("tool_name cannot be empty or whitespace")
        return clean


class ToolSecurityDecision(BaseModel):
    """Deterministic security outcome evaluating a tool call or tool result."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Decision outcome ID")
    tool_name: str = Field(..., description="Target tool evaluated")
    action: Action = Field(..., description="Enforced action: ALLOW, WARN, BLOCK, or REDACT")
    reason: str = Field(..., description="Human-readable justification for the decision")
    triggered_rules: List[str] = Field(default_factory=list, description="IDs of policy rules triggered")
    findings: List[Finding] = Field(default_factory=list, description="Findings detected in tool arguments/result")
    risk_score: Optional[RiskScore] = Field(default=None, description="Quantified risk assessment")
    sanitized_arguments: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Redacted/modified tool arguments if redaction was applied",
    )
    sanitized_output: Optional[str] = Field(
        default=None,
        description="Redacted/sanitized tool result output if applicable",
    )
    require_approval: bool = Field(
        default=False,
        description="Whether this tool invocation requires explicit human-in-the-loop approval",
    )
    policy_id: Optional[str] = Field(default=None, description="Evaluated policy ID")
    policy_version: Optional[str] = Field(default=None, description="Evaluated policy version")
    explanations: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Structured rule-by-rule matching explanations",
    )
    execution_time_ms: float = Field(default=0.0, ge=0.0, description="Evaluation latency in milliseconds")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC evaluation timestamp",
    )
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Evaluation metadata")

    @property
    def is_allowed(self) -> bool:
        """True if the action permits execution (ALLOW, WARN, REDACT)."""
        return self.action in (Action.ALLOW, Action.WARN, Action.REDACT)

    @property
    def is_blocked(self) -> bool:
        """True if action is BLOCK."""
        return self.action == Action.BLOCK

    def safe_dict(self) -> Dict[str, Any]:
        """Serialize for export, omitting raw matched secrets or PII."""
        data = self.model_dump(mode="json")
        for finding in data.get("findings", []):
            if finding.get("matched_text"):
                finding["matched_text"] = "[REDACTED_FROM_AUDIT]"
        return data
