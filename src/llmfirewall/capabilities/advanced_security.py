"""Phase 61 — Advanced Agent Security: Resource Scopes, Delegation Chains, and Approval Gates.

Extends capability authorization with structured resource scopes (whitelist/blacklist),
attenuated multi-hop delegation chain validation, step-up approval gates,
and sliding time-window action budgets.
"""

from enum import Enum
import fnmatch
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid

from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.capabilities.approval import ApprovalProvider
from llmfirewall.capabilities.models import (
    ActionClassification,
    ActionDecisionStatus,
    ActionRequest,
    ApprovalRequest,
    Capability,
    CapabilityGrant,
    CapabilityRiskClass,
    DelegationGrant,
    SideEffectType,
)


class ScopeType(str, Enum):
    """Categorization of managed resource scopes."""
    GENERIC = "GENERIC"
    FILE_PATH = "FILE_PATH"
    URL_ENDPOINT = "URL_ENDPOINT"
    TENANT_NAMESPACE = "TENANT_NAMESPACE"
    DATABASE_SCHEMA = "DATABASE_SCHEMA"


class ResourceScope(BaseModel):
    """Fine-grained resource scope with allowlist patterns and explicit exclusions."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    scope_id: str = Field(default_factory=lambda: f"scope-{uuid.uuid4().hex[:8]}", description="Unique scope ID")
    scope_type: ScopeType = Field(default=ScopeType.GENERIC, description="Type of target resource")
    allowed_patterns: List[str] = Field(default_factory=lambda: ["*"], description="Glob patterns permitted")
    disallowed_patterns: List[str] = Field(default_factory=list, description="Explicit blacklist patterns")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Auxiliary scope metadata")

    def matches(self, resource: Optional[str]) -> bool:
        """Check if resource satisfies allowlist and does not match any exclusion."""
        if not resource:
            return "*" in self.allowed_patterns

        # 1. Check blacklist first (fail-closed exclusion)
        for dis_pat in self.disallowed_patterns:
            if fnmatch.fnmatch(resource, dis_pat):
                return False

        # 2. Check allowlist
        if "*" in self.allowed_patterns:
            return True
        for allow_pat in self.allowed_patterns:
            if fnmatch.fnmatch(resource, allow_pat):
                return True
        return False


class DelegationChainValidator:
    """Validates multi-hop agent delegation chains, ensuring monotonic privilege attenuation.
    
    Security Invariants:
    - Max delegation depth is strictly bounded.
    - An agent cannot delegate permissions or scopes it does not itself possess.
    - Grants cannot be extended or broadened down the delegation tree.
    """

    def __init__(self, max_depth: int = 3) -> None:
        self.max_depth = max_depth

    def validate_chain(
        self,
        chain: List[DelegationGrant],
        target_capability: str,
        target_resource: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Validate entire delegation lineage from root to leaf agent."""
        if not chain:
            return False, "Delegation chain cannot be empty."

        if len(chain) > self.max_depth:
            return False, f"Delegation chain depth ({len(chain)}) exceeds max allowed {self.max_depth}."

        # Check chain link continuity (each link's child must be next link's parent)
        for i in range(len(chain) - 1):
            parent = chain[i]
            child = chain[i + 1]
            if parent.child_agent_id != child.parent_agent_id:
                return False, f"Delegation discontinuity between link {i} ({parent.child_agent_id}) and link {i+1} ({child.parent_agent_id})."
            if parent.is_expired():
                return False, f"Delegation link {i} from '{parent.parent_agent_id}' has expired."

        # Check leaf link
        leaf = chain[-1]
        if leaf.is_expired():
            return False, f"Leaf delegation grant from '{leaf.parent_agent_id}' has expired."

        # Ensure target capability is authorized across every hop in the chain
        for i, grant in enumerate(chain):
            has_cap = False
            for cg in grant.capabilities:
                if cg.capability_name == target_capability and (not target_resource or cg.allows_resource(target_resource)):
                    has_cap = True
                    break
            if not has_cap:
                return False, f"Hop {i} ({grant.parent_agent_id} -> {grant.child_agent_id}) does not permit capability '{target_capability}'."

        return True, "Delegation chain valid and attenuated."


class StepUpApprovalProvider(ApprovalProvider):
    """Approval provider requiring dynamic step-up authorization for high-impact actions.
    
    Supports auto-approval for read-only actions and explicit callbacks for write/destructive actions.
    """

    def __init__(
        self,
        auto_approve_low_risk: bool = True,
        auto_approved_capabilities: Optional[Set[str]] = None,
        approval_callback: Optional[Callable[[ApprovalRequest], bool]] = None,
    ) -> None:
        self.auto_approve_low_risk = auto_approve_low_risk
        self.auto_approved_capabilities: Set[str] = set(auto_approved_capabilities or {"filesystem.read", "tool.read", "query.read"})
        self._callback = approval_callback

    def request_approval(self, request: ApprovalRequest) -> bool:
        """Evaluate approval criteria or execute external step-up callback."""
        if self.auto_approve_low_risk:
            if request.capability_name in self.auto_approved_capabilities:
                return True
            if any(request.capability_name.endswith(suffix) for suffix in (".read", "_read", ".view", "_view", ".get")):
                return True

        if self._callback is not None:
            return bool(self._callback(request))

        # Default fail-closed policy for unhandled high-risk approvals
        return False


class TimeWindowBudget(BaseModel):
    """Rolling time-window budget limiting action invocation rates per window."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    max_actions: int = Field(default=50, ge=1, description="Max actions allowed per time window")
    window_seconds: float = Field(default=60.0, ge=1.0, description="Duration of sliding window in seconds")


class SlidingWindowRateLimiter:
    """In-memory sliding window limiter for agent capabilities and tool calls."""

    def __init__(self, budget: TimeWindowBudget) -> None:
        self.budget = budget
        self._action_timestamps: List[float] = []

    def allow_action(self, now: Optional[float] = None) -> bool:
        """Check if action is permitted under sliding window ceiling; records timestamp if allowed."""
        current_time = now or time.time()
        cutoff = current_time - self.budget.window_seconds

        # Prune expired entries
        self._action_timestamps = [t for t in self._action_timestamps if t > cutoff]

        if len(self._action_timestamps) >= self.budget.max_actions:
            return False

        self._action_timestamps.append(current_time)
        return True

    @property
    def current_count(self) -> int:
        cutoff = time.time() - self.budget.window_seconds
        return len([t for t in self._action_timestamps if t > cutoff])
