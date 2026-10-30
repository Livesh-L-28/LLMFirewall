"""Domain models, boundaries, execution state, and scoped permissions for cross-step workflows.

Phase 3: Cross-Step Agent Security.
Enforces:
- Strict, immutable tenant identity (zero cross-tenant data or context sharing).
- Immutable agent role binding (rejection of mid-workflow identity tampering).
- Bounded, serializable cross-step context envelopes.
- Monotonic threat taint propagation across reasoning cycles.
- Zero raw credential retention (cryptographic SHA-256 summaries).
"""

from __future__ import annotations

from enum import Enum
import fnmatch
import hashlib
import time
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.exceptions import LLMFirewallError
from llmfirewall.core.models import Action, Severity


# =============================================================================
# 1. Exceptions
# =============================================================================

class WorkflowSecurityError(LLMFirewallError):
    """Base exception for cross-step workflow security violations."""

    def __init__(self, message: str, workflow_id: Optional[str] = None, tenant_id: Optional[str] = None) -> None:
        super().__init__(message)
        self.workflow_id = workflow_id
        self.tenant_id = tenant_id


class CrossTenantViolationError(WorkflowSecurityError):
    """Raised when an operation attempts to cross tenant isolation boundaries."""
    pass


class IdentityTamperingError(WorkflowSecurityError):
    """Raised when an agent attempts to hijack, escalate, or switch identity mid-workflow."""
    pass


class WorkflowExpiredError(WorkflowSecurityError):
    """Raised when an operation is attempted on an expired or timed-out workflow."""
    pass


class WorkflowCancelledError(WorkflowSecurityError):
    """Raised when an operation is attempted on an explicitly cancelled workflow."""
    pass


class WorkflowLimitExceededError(WorkflowSecurityError):
    """Raised when a workflow exceeds its configured step or tool execution quota."""
    pass


class ToolAuthorizationError(WorkflowSecurityError):
    """Raised when a tool execution is denied by scoped permissions or taint policy."""

    def __init__(
        self,
        message: str,
        tool_name: str,
        workflow_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> None:
        super().__init__(message, workflow_id=workflow_id, tenant_id=tenant_id)
        self.tool_name = tool_name
        self.reason = reason or message


# =============================================================================
# 2. Enumerations
# =============================================================================

class WorkflowStatus(str, Enum):
    """Operational lifecycle state of an active workflow."""
    INITIALIZING = "initializing"
    ACTIVE = "active"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    BLOCKED = "blocked"
    COMPLETED = "completed"


class WorkflowThreatState(str, Enum):
    """Cumulative threat taint level of a workflow."""
    CLEAN = "clean"          # Zero threat observations
    ELEVATED = "elevated"    # Low/medium warning or suspicious argument
    TAINTED = "tainted"      # Prompt injection, RAG poisoning, or flagged tool result
    CRITICAL = "critical"    # Critical attack attempt or active policy block


class StepBoundary(str, Enum):
    """Execution trust boundaries within a multi-step workflow."""
    PROMPT_INPUT = "prompt_input"
    MODEL_OUTPUT = "model_output"
    RAG_RETRIEVAL = "rag_retrieval"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"


# =============================================================================
# 3. Scoped Permissions & Threat Observations
# =============================================================================

class ScopedPermission(BaseModel):
    """Granular permission scope governing tool operations in a workflow."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_name: str = Field(..., description="Target tool name")
    allowed_actions: List[str] = Field(default_factory=lambda: ["*"], description="Permitted operations (e.g. ['read', 'query'])")
    denied_actions: List[str] = Field(default_factory=list, description="Explicitly forbidden operations (e.g. ['delete', 'drop'])")
    allowed_resources: List[str] = Field(default_factory=lambda: ["*"], description="Glob patterns for permitted resources/paths/tables")
    denied_resources: List[str] = Field(default_factory=list, description="Glob patterns for prohibited resources (e.g. ['/etc/*', '*.pem'])")
    max_invocations: Optional[int] = Field(default=None, ge=1, description="Max permitted executions in workflow")
    requires_clean_workflow: bool = Field(default=False, description="If True, denied whenever workflow threat_state != CLEAN")

    def allows_action(self, action: Optional[str]) -> bool:
        """Verify action is allowed and not explicitly denied."""
        if not action:
            return True
        act_lower = action.strip().lower()
        # Check blacklist first
        for den in self.denied_actions:
            if fnmatch.fnmatch(act_lower, den.lower()):
                return False
        # Check whitelist
        if "*" in self.allowed_actions:
            return True
        for allow in self.allowed_actions:
            if fnmatch.fnmatch(act_lower, allow.lower()):
                return True
        return False

    def allows_resource(self, resource: Optional[str]) -> bool:
        """Verify resource matches allowlist and avoids all denied patterns."""
        if not resource:
            return "*" in self.allowed_resources
        res_str = str(resource)
        # Check blacklist first
        for den in self.denied_resources:
            if fnmatch.fnmatch(res_str, den):
                return False
        # Check whitelist
        if "*" in self.allowed_resources:
            return True
        for allow in self.allowed_resources:
            if fnmatch.fnmatch(res_str, allow):
                return True
        return False


class ThreatObservation(BaseModel):
    """Immutable audit record of a security threat observed during a workflow step."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    threat_id: str = Field(default_factory=lambda: f"obs-{uuid.uuid4().hex[:8]}")
    threat_type: str = Field(..., description="Threat category or detector name")
    severity: Severity = Field(default=Severity.MEDIUM)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    step_number: int = Field(default=1, ge=1)
    boundary: StepBoundary = Field(default=StepBoundary.PROMPT_INPUT)
    source: str = Field(default="firewall", description="Originating detector or subsystem")
    description: str = Field(default="", description="Summary of observation (no raw secrets)")
    timestamp: float = Field(default_factory=time.time)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class WorkflowStepRecord(BaseModel):
    """Bounded, privacy-safe record of an executed workflow step."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    step_number: int = Field(..., ge=1)
    boundary: StepBoundary
    content_hash: str = Field(..., description="SHA-256 digest of input or output text")
    tool_name: Optional[str] = Field(default=None)
    tool_arguments_summary: Optional[Dict[str, Any]] = Field(default=None, description="Sanitized key names and types; raw secrets scrubbed")
    decision: Action = Field(default=Action.ALLOW)
    reason: str = Field(default="")
    findings_count: int = Field(default=0)
    threat_types: List[str] = Field(default_factory=list)
    timestamp: float = Field(default_factory=time.time)


# =============================================================================
# 4. Workflow Security Context
# =============================================================================

class WorkflowSecurityContext(BaseModel):
    """Stateful, thread-safe cross-step security envelope for an agent workflow."""
    model_config = ConfigDict(extra="forbid")

    workflow_id: str = Field(default_factory=lambda: f"wf-{uuid.uuid4().hex[:12]}")
    tenant_id: str = Field(..., min_length=1, max_length=128, description="Authoritative immutable tenant identifier")
    agent_id: str = Field(default="default_agent", min_length=1, max_length=128, description="Authoritative agent role/persona")
    session_id: Optional[str] = Field(default=None)
    status: WorkflowStatus = Field(default=WorkflowStatus.ACTIVE)
    threat_state: WorkflowThreatState = Field(default=WorkflowThreatState.CLEAN)

    step_count: int = Field(default=0, ge=0)
    max_steps: int = Field(default=50, ge=1)
    tool_call_count: int = Field(default=0, ge=0)
    max_tool_calls: int = Field(default=30, ge=1)

    created_at: float = Field(default_factory=time.time)
    last_active_at: float = Field(default_factory=time.time)
    ttl_seconds: float = Field(default=3600.0, ge=0.01, description="Absolute workflow expiration timeout")
    idle_timeout_seconds: float = Field(default=300.0, ge=0.01, description="Idle timeout since last step")

    cumulative_risk_score: float = Field(default=0.0, ge=0.0)
    threat_observations: List[ThreatObservation] = Field(default_factory=list)
    steps: List[WorkflowStepRecord] = Field(default_factory=list)

    scoped_permissions: Dict[str, ScopedPermission] = Field(default_factory=dict)
    allowed_tools: Optional[List[str]] = Field(default=None, description="Global whitelist of tools permitted in this workflow")
    denied_tools: List[str] = Field(default_factory=list, description="Global blacklist of forbidden tools")

    cancellation_reason: Optional[str] = Field(default=None)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # -------------------------------------------------------------------------
    # Lifecycle and State Predicates
    # -------------------------------------------------------------------------

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        """Check whether the workflow has exceeded its absolute TTL or idle timeout."""
        now = current_time or time.time()
        if now - self.created_at > self.ttl_seconds:
            return True
        if now - self.last_active_at > self.idle_timeout_seconds:
            return True
        return False

    @property
    def is_active(self) -> bool:
        """True if the workflow is in ACTIVE state and not expired."""
        if self.status != WorkflowStatus.ACTIVE:
            return False
        return not self.is_expired()

    @property
    def is_tainted(self) -> bool:
        """True if any threat has elevated or tainted the workflow security posture."""
        return self.threat_state in (WorkflowThreatState.TAINTED, WorkflowThreatState.CRITICAL)

    # -------------------------------------------------------------------------
    # Identity & Tenancy Invariant Enforcement
    # -------------------------------------------------------------------------

    def assert_tenant(self, target_tenant_id: Optional[str]) -> None:
        """Enforces that an invoked step strictly belongs to the authoritative workflow tenant."""
        if target_tenant_id is not None and target_tenant_id != self.tenant_id:
            raise CrossTenantViolationError(
                f"Cross-tenant access violation: step requested tenant '{target_tenant_id}', "
                f"but workflow is immutably bound to tenant '{self.tenant_id}'.",
                workflow_id=self.workflow_id,
                tenant_id=self.tenant_id,
            )

    def assert_agent(self, target_agent_id: Optional[str]) -> None:
        """Enforces that an invoked step matches the authorized agent role without tampering."""
        if target_agent_id is not None and target_agent_id != self.agent_id:
            raise IdentityTamperingError(
                f"Agent identity tampering detected: step specified agent '{target_agent_id}', "
                f"but workflow is bound to authorized agent '{self.agent_id}'.",
                workflow_id=self.workflow_id,
                tenant_id=self.tenant_id,
            )

    # -------------------------------------------------------------------------
    # State Mutation Methods
    # -------------------------------------------------------------------------

    def touch(self) -> None:
        """Update last active timestamp to current time."""
        self.last_active_at = time.time()

    def add_threat_observation(self, obs: ThreatObservation) -> None:
        """Record an observed threat and monotonically escalate workflow taint."""
        self.touch()
        if len(self.threat_observations) >= 50:
            self.threat_observations.pop(0)  # Bounded FIFO window
        self.threat_observations.append(obs)

        # Monotonic escalation
        if obs.severity == Severity.CRITICAL:
            self.threat_state = WorkflowThreatState.CRITICAL
            self.cumulative_risk_score = min(1.0, self.cumulative_risk_score + 0.5)
        elif obs.severity == Severity.HIGH:
            if self.threat_state != WorkflowThreatState.CRITICAL:
                self.threat_state = WorkflowThreatState.TAINTED
            self.cumulative_risk_score = min(1.0, self.cumulative_risk_score + 0.3)
        elif obs.severity in (Severity.MEDIUM, Severity.LOW):
            if self.threat_state == WorkflowThreatState.CLEAN:
                self.threat_state = WorkflowThreatState.ELEVATED
            self.cumulative_risk_score = min(1.0, self.cumulative_risk_score + 0.15)

    def add_step_record(self, rec: WorkflowStepRecord) -> None:
        """Append bounded step record to the audit trail."""
        self.touch()
        self.step_count = rec.step_number
        if len(self.steps) >= 100:
            self.steps.pop(0)  # Bounded FIFO window
        self.steps.append(rec)

    def safe_dict(self) -> Dict[str, Any]:
        """Telemetry and audit safe serialization with zero raw text or secrets."""
        return {
            "workflow_id": self.workflow_id,
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "status": self.status.value,
            "threat_state": self.threat_state.value,
            "step_count": self.step_count,
            "max_steps": self.max_steps,
            "tool_call_count": self.tool_call_count,
            "max_tool_calls": self.max_tool_calls,
            "cumulative_risk_score": round(self.cumulative_risk_score, 4),
            "threat_observations_count": len(self.threat_observations),
            "created_at": self.created_at,
            "last_active_at": self.last_active_at,
            "is_active": self.is_active,
            "is_tainted": self.is_tainted,
        }
