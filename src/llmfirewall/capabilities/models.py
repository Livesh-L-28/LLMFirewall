"""Data models and enums for Phase 29: Agent Capability Security & Action Control."""

from datetime import datetime, timezone
from enum import Enum
import fnmatch
import time
from typing import Any, Dict, List, Optional, Set
import uuid
from pydantic import BaseModel, ConfigDict, Field, field_validator

from llmfirewall.core.models import Action, Finding, Severity, ThreatType


class ActionClassification(str, Enum):
    """Standardized action classification types."""
    READ = "READ"
    WRITE = "WRITE"
    DELETE = "DELETE"
    EXECUTE = "EXECUTE"
    COMMUNICATE = "COMMUNICATE"
    DEPLOY = "DEPLOY"
    ADMIN = "ADMIN"


class SideEffectType(str, Enum):
    """Side effect impact classifications."""
    NONE = "NONE"
    READ_ONLY = "READ_ONLY"
    LOCAL_WRITE = "LOCAL_WRITE"
    EXTERNAL_WRITE = "EXTERNAL_WRITE"
    DESTRUCTIVE = "DESTRUCTIVE"


class CapabilityRiskClass(str, Enum):
    """Inherent risk classification for capabilities."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActionDecisionStatus(str, Enum):
    """Outcome of capability authorization and action evaluation."""
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    RATE_LIMIT = "RATE_LIMIT"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"


class Capability(BaseModel):
    """Normalized security capability representation."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(..., min_length=1, max_length=128, description="Capability identifier (e.g. 'filesystem.read', 'shell.execute').")
    action: ActionClassification = Field(default=ActionClassification.READ, description="Action classification.")
    resource_pattern: str = Field(default="*", description="Glob pattern or resource descriptor (e.g. 'documents/*', 'api.github.com/*').")
    risk_class: CapabilityRiskClass = Field(default=CapabilityRiskClass.LOW, description="Inherent risk classification.")
    side_effects: SideEffectType = Field(default=SideEffectType.READ_ONLY, description="Expected side-effect level.")
    destructive: bool = Field(default=False, description="Whether capability involves destructive mutations (delete, overwrite).")
    requires_approval: bool = Field(default=False, description="Whether action requires explicit approval gate.")
    description: str = Field(default="", description="Descriptive purpose of capability.")

    @field_validator("name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        clean = v.strip().lower()
        if not clean:
            raise ValueError("Capability name cannot be empty.")
        return clean

    def matches_resource(self, target_resource: Optional[str]) -> bool:
        """Check if target resource matches the allowed glob resource_pattern."""
        if not target_resource or self.resource_pattern == "*":
            return True
        return fnmatch.fnmatch(target_resource, self.resource_pattern)


class CapabilityGrant(BaseModel):
    """An explicit capability grant assigned to an agent or role."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    grant_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    capability_name: str = Field(..., description="Target capability name.")
    resource_scope: List[str] = Field(default_factory=lambda: ["*"], description="Allowed resources (e.g. ['./documents/*']).")
    max_uses: Optional[int] = Field(default=None, ge=1, description="Optional ceiling on number of uses.")
    expires_at: Optional[float] = Field(default=None, description="Epoch timestamp when grant expires.")
    created_at: float = Field(default_factory=time.time)

    def is_expired(self) -> bool:
        if self.expires_at is not None and time.time() > self.expires_at:
            return True
        return False

    def allows_resource(self, resource: Optional[str]) -> bool:
        if not resource or "*" in self.resource_scope:
            return True
        for pattern in self.resource_scope:
            if fnmatch.fnmatch(resource, pattern):
                return True
        return False


class DelegationGrant(BaseModel):
    """Delegated authorization token passed from a parent agent to a child agent."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    delegation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    parent_agent_id: str = Field(..., description="Originating delegating agent ID.")
    child_agent_id: str = Field(..., description="Target delegated child agent ID.")
    capabilities: List[CapabilityGrant] = Field(default_factory=list, description="Delegated capability grants.")
    depth: int = Field(default=1, ge=1, description="Delegation depth relative to root agent.")
    created_at: float = Field(default_factory=time.time)
    expires_at: Optional[float] = Field(default=None)

    def is_expired(self) -> bool:
        if self.expires_at is not None and time.time() > self.expires_at:
            return True
        return False


class ActionBudget(BaseModel):
    """Action and resource limits assigned to an agent session."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    max_actions: int = Field(default=50, ge=1, description="Maximum total tool/action executions.")
    max_runtime_seconds: float = Field(default=300.0, ge=1.0, description="Max session duration.")
    per_capability_limits: Dict[str, int] = Field(default_factory=dict, description="Limits per capability name.")
    max_tokens: Optional[int] = Field(default=None, ge=1, description="Token ceiling.")
    max_cost: Optional[float] = Field(default=None, ge=0.0, description="Monetary cost ceiling.")


class ActionRequest(BaseModel):
    """Normalized action request emitted when an agent attempts a tool or operation."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    parent_action_id: Optional[str] = Field(default=None, description="Parent action ID if part of recursive/chained call.")
    agent_id: str = Field(default="default_agent", description="Requesting agent identifier.")
    parent_agent_id: Optional[str] = Field(default=None, description="Parent agent ID if delegated.")
    session_id: str = Field(default="default_session", description="Correlating agent session ID.")
    capability_name: str = Field(..., description="Required capability (e.g. 'filesystem.read').")
    tool_name: str = Field(default="unknown_tool", description="Name of tool requested.")
    resource: Optional[str] = Field(default=None, description="Target resource (file path, URI, table name).")
    arguments_metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe metadata about arguments (no raw secrets).")
    timestamp: float = Field(default_factory=time.time)


class ApprovalRequest(BaseModel):
    """Request for explicit human or administrative approval of a high-risk action."""
    model_config = ConfigDict(frozen=False, extra="forbid")

    approval_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_id: str = Field(..., description="Action ID requiring approval.")
    agent_id: str = Field(..., description="Requesting agent ID.")
    capability_name: str = Field(..., description="Capability requested.")
    resource: Optional[str] = Field(default=None, description="Target resource.")
    reason: str = Field(default="Action requires explicit administrative approval.")
    approved: bool = Field(default=False)
    approved_by: Optional[str] = Field(default=None)
    created_at: float = Field(default_factory=time.time)
    expires_at: float = Field(default_factory=lambda: time.time() + 300.0, description="Default 5-minute expiration.")

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def is_valid_for(self, action: ActionRequest) -> bool:
        """Enforce strict binding to prevent approval replay across differing actions/resources."""
        if self.is_expired():
            return False
        if not self.approved:
            return False
        if self.action_id != action.action_id:
            return False
        if self.capability_name != action.capability_name:
            return False
        if self.resource != action.resource:
            return False
        return True


class ActionDecision(BaseModel):
    """Security authorization decision for an ActionRequest."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    decision: ActionDecisionStatus = Field(..., description="ALLOW, DENY, REQUIRE_APPROVAL, RATE_LIMIT, BUDGET_EXCEEDED.")
    action_id: str = Field(..., description="Correlating action request ID.")
    agent_id: str = Field(..., description="Agent ID.")
    capability_name: str = Field(..., description="Requested capability.")
    resource: Optional[str] = Field(default=None, description="Resource evaluated.")
    reason: str = Field(default="Authorized by capability security policy.")
    approval_request: Optional[ApprovalRequest] = Field(default=None, description="Associated approval request if approval required.")
    findings: List[Finding] = Field(default_factory=list, description="Associated policy findings.")
    policy_rule: Optional[str] = Field(default=None, description="Name of policy rule applied.")

    @property
    def is_allowed(self) -> bool:
        return self.decision == ActionDecisionStatus.ALLOW


class ActionChain(BaseModel):
    """Tracks nested action lineage and execution depth across agent tool calls."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    root_action_id: str = Field(..., description="Root action ID initiating the chain.")
    parent_action_id: Optional[str] = Field(default=None, description="Immediate parent action ID.")
    depth: int = Field(default=1, ge=1, description="Nesting depth.")
    history: List[str] = Field(default_factory=list, description="Sequence of capability/tool invocations in chain.")
