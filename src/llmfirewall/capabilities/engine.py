"""Capability resolution, delegation lineage validation, and capability security engine."""

from typing import Any, Dict, List, Optional, Set, Tuple
import threading
import time

from llmfirewall.capabilities.approval import ApprovalProvider, DenyAllApprovalProvider
from llmfirewall.capabilities.budget import BudgetManager
from llmfirewall.capabilities.models import (
    ActionBudget,
    ActionChain,
    ActionClassification,
    ActionDecision,
    ActionDecisionStatus,
    ActionRequest,
    ApprovalRequest,
    Capability,
    CapabilityGrant,
    CapabilityRiskClass,
    DelegationGrant,
    SideEffectType,
)
from llmfirewall.core.models import Finding, Severity, ThreatType
from llmfirewall.tools.path_security import validate_path_safety

# Default standard built-in capability definitions
DEFAULT_CAPABILITIES: Dict[str, Capability] = {
    "filesystem.read": Capability(
        name="filesystem.read",
        action=ActionClassification.READ,
        risk_class=CapabilityRiskClass.LOW,
        side_effects=SideEffectType.READ_ONLY,
        description="Read files from local filesystem.",
    ),
    "filesystem.write": Capability(
        name="filesystem.write",
        action=ActionClassification.WRITE,
        risk_class=CapabilityRiskClass.HIGH,
        side_effects=SideEffectType.LOCAL_WRITE,
        description="Create or mutate files on local filesystem.",
    ),
    "filesystem.delete": Capability(
        name="filesystem.delete",
        action=ActionClassification.DELETE,
        risk_class=CapabilityRiskClass.CRITICAL,
        side_effects=SideEffectType.DESTRUCTIVE,
        destructive=True,
        requires_approval=True,
        description="Delete files or directories from filesystem.",
    ),
    "database.read": Capability(
        name="database.read",
        action=ActionClassification.READ,
        risk_class=CapabilityRiskClass.LOW,
        side_effects=SideEffectType.READ_ONLY,
        description="Query data from databases.",
    ),
    "database.write": Capability(
        name="database.write",
        action=ActionClassification.WRITE,
        risk_class=CapabilityRiskClass.MEDIUM,
        side_effects=SideEffectType.EXTERNAL_WRITE,
        description="Insert or update database records.",
    ),
    "database.delete": Capability(
        name="database.delete",
        action=ActionClassification.DELETE,
        risk_class=CapabilityRiskClass.CRITICAL,
        side_effects=SideEffectType.DESTRUCTIVE,
        destructive=True,
        requires_approval=True,
        description="Delete database records or drop tables.",
    ),
    "network.request": Capability(
        name="network.request",
        action=ActionClassification.COMMUNICATE,
        risk_class=CapabilityRiskClass.MEDIUM,
        side_effects=SideEffectType.EXTERNAL_WRITE,
        description="Outbound HTTP or socket communication.",
    ),
    "email.send": Capability(
        name="email.send",
        action=ActionClassification.COMMUNICATE,
        risk_class=CapabilityRiskClass.HIGH,
        side_effects=SideEffectType.EXTERNAL_WRITE,
        requires_approval=True,
        description="Send outbound emails.",
    ),
    "shell.execute": Capability(
        name="shell.execute",
        action=ActionClassification.EXECUTE,
        risk_class=CapabilityRiskClass.CRITICAL,
        side_effects=SideEffectType.DESTRUCTIVE,
        destructive=True,
        requires_approval=True,
        description="Execute commands in shell or subprocess.",
    ),
}

# Tool-to-Capabilities standard mapping
DEFAULT_TOOL_CAPABILITY_MAP: Dict[str, List[str]] = {
    "read_file": ["filesystem.read"],
    "cat": ["filesystem.read"],
    "view_file": ["filesystem.read"],
    "write_file": ["filesystem.write"],
    "create_file": ["filesystem.write"],
    "delete_file": ["filesystem.delete"],
    "rm": ["filesystem.delete"],
    "search_web": ["network.request"],
    "fetch_url": ["network.request"],
    "http_get": ["network.request"],
    "http_post": ["network.request"],
    "sql_query": ["database.read"],
    "db_query": ["database.read"],
    "db_delete": ["database.delete"],
    "send_email": ["email.send"],
    "shell_exec": ["shell.execute"],
    "bash": ["shell.execute"],
    "terminal": ["shell.execute"],
}


class CapabilityEngine:
    """Security authorization engine for agent capabilities, resource scoping, and action control."""

    def __init__(
        self,
        capabilities: Optional[Dict[str, Capability]] = None,
        tool_map: Optional[Dict[str, List[str]]] = None,
        approval_provider: Optional[ApprovalProvider] = None,
        max_delegation_depth: int = 3,
        max_action_depth: int = 20,
        max_repeated_actions: Optional[int] = None,
    ) -> None:
        self.capabilities: Dict[str, Capability] = dict(DEFAULT_CAPABILITIES)
        if capabilities:
            self.capabilities.update(capabilities)

        self.tool_map: Dict[str, List[str]] = dict(DEFAULT_TOOL_CAPABILITY_MAP)
        if tool_map:
            self.tool_map.update(tool_map)

        self.approval_provider: ApprovalProvider = approval_provider or DenyAllApprovalProvider()
        self.max_delegation_depth = max_delegation_depth
        self.max_action_depth = max_action_depth
        self.max_repeated_actions = max_repeated_actions

        # Agent registrations: agent_id -> Set[CapabilityGrant]
        self._grants: Dict[str, List[CapabilityGrant]] = {}
        # Explicit denylist: agent_id -> Set[capability_name]
        self._denies: Dict[str, Set[str]] = {}
        # Roles: role_name -> List[CapabilityGrant]
        self._roles: Dict[str, List[CapabilityGrant]] = {}
        # Agent to role mapping: agent_id -> role_name
        self._agent_roles: Dict[str, str] = {}
        # Revocations: Set of revoked session IDs or agent IDs
        self._revoked_sessions: Set[str] = set()
        self._revoked_agents: Set[str] = set()
        # Action chain tracking: session_id -> ActionChain
        self._action_chains: Dict[str, ActionChain] = {}
        # Repeated actions history: session_id -> List[Tuple[capability, resource]]
        self._action_history: Dict[str, List[Tuple[str, Optional[str]]]] = {}
        # Emergency block
        self._emergency_block_writes: bool = False
        self._lock = threading.Lock()

    def register_capability(self, capability: Capability) -> None:
        with self._lock:
            self.capabilities[capability.name] = capability

    def map_tool(self, tool_name: str, required_capabilities: List[str]) -> None:
        with self._lock:
            self.tool_map[tool_name.lower().strip()] = required_capabilities

    def grant_capability(
        self,
        agent_id: str,
        capability_name: str,
        resource_scope: Optional[List[str]] = None,
        max_uses: Optional[int] = None,
        expires_at: Optional[float] = None,
    ) -> CapabilityGrant:
        """Explicitly assign a capability grant to an agent."""
        cap_clean = capability_name.strip().lower()
        grant = CapabilityGrant(
            capability_name=cap_clean,
            resource_scope=resource_scope or ["*"],
            max_uses=max_uses,
            expires_at=expires_at,
        )
        with self._lock:
            if agent_id not in self._grants:
                self._grants[agent_id] = []
            self._grants[agent_id].append(grant)
        return grant

    def deny_capability(self, agent_id: str, capability_name: str) -> None:
        """Explicitly deny a capability to an agent (takes precedence over allow)."""
        cap_clean = capability_name.strip().lower()
        with self._lock:
            if agent_id not in self._denies:
                self._denies[agent_id] = set()
            self._denies[agent_id].add(cap_clean)

    def define_role(self, role_name: str, capabilities: List[CapabilityGrant]) -> None:
        with self._lock:
            self._roles[role_name.lower()] = capabilities

    def assign_role(self, agent_id: str, role_name: str) -> None:
        with self._lock:
            self._agent_roles[agent_id] = role_name.lower()

    def revoke_session(self, session_id: str) -> None:
        """Agent kill-switch for an active session."""
        with self._lock:
            self._revoked_sessions.add(session_id)

    def revoke_agent(self, agent_id: str) -> None:
        """Revoke all capabilities and access for an agent."""
        with self._lock:
            self._revoked_agents.add(agent_id)

    def set_emergency_block_external_writes(self, enabled: bool) -> None:
        with self._lock:
            self._emergency_block_writes = enabled

    def delegate(
        self,
        parent_agent_id: str,
        child_agent_id: str,
        capabilities_to_delegate: List[CapabilityGrant],
        depth: int = 1,
    ) -> DelegationGrant:
        """Delegate capabilities from parent agent to child agent. Enforces child <= parent."""
        if depth > self.max_delegation_depth:
            raise ValueError(f"Delegation depth {depth} exceeds max allowed depth {self.max_delegation_depth}.")

        parent_caps = {g.capability_name for g in self._get_active_grants(parent_agent_id)}
        for cg in capabilities_to_delegate:
            if cg.capability_name not in parent_caps:
                raise PermissionError(
                    f"Privilege escalation prevented: parent agent '{parent_agent_id}' does not possess "
                    f"capability '{cg.capability_name}' to delegate to '{child_agent_id}'."
                )

        grant = DelegationGrant(
            parent_agent_id=parent_agent_id,
            child_agent_id=child_agent_id,
            capabilities=capabilities_to_delegate,
            depth=depth,
        )
        with self._lock:
            if child_agent_id not in self._grants:
                self._grants[child_agent_id] = []
            self._grants[child_agent_id].extend(capabilities_to_delegate)

        return grant

    def _get_active_grants(self, agent_id: str) -> List[CapabilityGrant]:
        grants = list(self._grants.get(agent_id, []))
        role = self._agent_roles.get(agent_id)
        if role and role in self._roles:
            grants.extend(self._roles[role])
        return [g for g in grants if not g.is_expired()]

    def authorize_action(
        self,
        request: ActionRequest,
        budget_manager: Optional[BudgetManager] = None,
    ) -> ActionDecision:
        """Evaluate an ActionRequest through the full authorization chain.
        
        Pipeline:
        1. Revocation & Kill-switch check
        2. Emergency policies
        3. Action chain depth & loop limits
        4. Explicit Deny check
        5. Capability grant & Least-privilege resolution
        6. Resource scoping & Path safety
        7. Action budget reservation
        8. Human/Policy Approval gate
        """
        # 1. Revocation & Kill-Switch
        if request.session_id in self._revoked_sessions:
            return ActionDecision(
                decision=ActionDecisionStatus.DENY,
                action_id=request.action_id,
                agent_id=request.agent_id,
                capability_name=request.capability_name,
                resource=request.resource,
                reason=f"Action denied: Agent session '{request.session_id}' has been revoked (kill-switch active).",
                findings=[Finding(
                    detector_name="capability_engine",
                    threat_type=ThreatType.POLICY_VIOLATION,
                    description=f"Session '{request.session_id}' is revoked.",
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    metadata={"violation": "SESSION_REVOKED"},
                )],
            )

        if request.agent_id in self._revoked_agents:
            return ActionDecision(
                decision=ActionDecisionStatus.DENY,
                action_id=request.action_id,
                agent_id=request.agent_id,
                capability_name=request.capability_name,
                resource=request.resource,
                reason=f"Action denied: Agent '{request.agent_id}' has been revoked.",
                findings=[Finding(
                    detector_name="capability_engine",
                    threat_type=ThreatType.POLICY_VIOLATION,
                    description=f"Agent '{request.agent_id}' is revoked.",
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    metadata={"violation": "AGENT_REVOKED"},
                )],
            )

        cap_def = self.capabilities.get(request.capability_name)
        if not cap_def:
            # Fallback capability definition
            cap_def = Capability(
                name=request.capability_name,
                action=ActionClassification.EXECUTE,
                risk_class=CapabilityRiskClass.HIGH,
            )

        # 2. Emergency Block
        if self._emergency_block_writes and cap_def.side_effects in (SideEffectType.LOCAL_WRITE, SideEffectType.EXTERNAL_WRITE, SideEffectType.DESTRUCTIVE):
            return ActionDecision(
                decision=ActionDecisionStatus.DENY,
                action_id=request.action_id,
                agent_id=request.agent_id,
                capability_name=request.capability_name,
                resource=request.resource,
                reason="Action denied: Emergency block on all write and destructive actions is active.",
                findings=[Finding(
                    detector_name="capability_engine",
                    threat_type=ThreatType.POLICY_VIOLATION,
                    description="Emergency write block active.",
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    metadata={"violation": "EMERGENCY_BLOCK_ACTIVE"},
                )],
            )

        # 3. Action Chain Depth & Loop Protection
        with self._lock:
            # Action depth measures recursive nested actions (when parent_action_id is provided)
            if request.parent_action_id:
                chain = self._action_chains.get(request.session_id)
                current_depth = (chain.depth + 1) if chain else 2
                self._action_chains[request.session_id] = ActionChain(
                    root_action_id=chain.root_action_id if chain else request.parent_action_id,
                    parent_action_id=request.parent_action_id,
                    depth=current_depth,
                    history=(chain.history if chain else []) + [request.capability_name],
                )
                if current_depth > self.max_action_depth:
                    return ActionDecision(
                        decision=ActionDecisionStatus.DENY,
                        action_id=request.action_id,
                        agent_id=request.agent_id,
                        capability_name=request.capability_name,
                        resource=request.resource,
                        reason=f"Action denied: Action chain depth {current_depth} exceeded limit {self.max_action_depth}.",
                        findings=[Finding(
                            detector_name="capability_engine",
                            threat_type=ThreatType.POLICY_VIOLATION,
                            description="Max action depth exceeded.",
                            severity=Severity.HIGH,
                            confidence=1.0,
                            metadata={"violation": "MAX_ACTION_DEPTH_EXCEEDED"},
                        )],
                    )
            else:
                # Top-level action: depth 1
                self._action_chains[request.session_id] = ActionChain(
                    root_action_id=request.action_id,
                    parent_action_id=None,
                    depth=1,
                    history=[request.capability_name],
                )

            # Loop detection (e.g. repeated identical actions exceeding configured threshold)
            if self.max_repeated_actions is not None:
                hist = self._action_history.setdefault(request.session_id, [])
                hist.append((request.capability_name, request.resource))
                if len(hist) >= self.max_repeated_actions:
                    last_n = hist[-self.max_repeated_actions:]
                    if all(item == last_n[0] for item in last_n):
                        return ActionDecision(
                            decision=ActionDecisionStatus.DENY,
                            action_id=request.action_id,
                            agent_id=request.agent_id,
                            capability_name=request.capability_name,
                            resource=request.resource,
                            reason="Action denied: Excessive identical action repetition loop detected.",
                            findings=[Finding(
                                detector_name="capability_engine",
                                threat_type=ThreatType.POLICY_VIOLATION,
                                description="Identical action repetition loop.",
                                severity=Severity.HIGH,
                                confidence=1.0,
                                metadata={"violation": "AGENT_LOOP_DETECTED"},
                            )],
                        )

        # 4. Explicit Deny Check (Takes precedence)
        denied_caps = self._denies.get(request.agent_id, set())
        if request.capability_name in denied_caps:
            return ActionDecision(
                decision=ActionDecisionStatus.DENY,
                action_id=request.action_id,
                agent_id=request.agent_id,
                capability_name=request.capability_name,
                resource=request.resource,
                reason=f"Action denied: Capability '{request.capability_name}' is explicitly denied to agent '{request.agent_id}'.",
                findings=[Finding(
                    detector_name="capability_engine",
                    threat_type=ThreatType.POLICY_VIOLATION,
                    description="Explicit deny rule triggered.",
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    metadata={"violation": "CAPABILITY_EXPLICITLY_DENIED"},
                )],
            )

        # 5. Least-Privilege Grant Resolution
        active_grants = self._get_active_grants(request.agent_id)
        matching_grants = [g for g in active_grants if g.capability_name == request.capability_name]

        if not matching_grants:
            return ActionDecision(
                decision=ActionDecisionStatus.DENY,
                action_id=request.action_id,
                agent_id=request.agent_id,
                capability_name=request.capability_name,
                resource=request.resource,
                reason=f"Action denied: Agent '{request.agent_id}' has not been granted capability '{request.capability_name}'.",
                findings=[Finding(
                    detector_name="capability_engine",
                    threat_type=ThreatType.POLICY_VIOLATION,
                    description=f"Missing capability '{request.capability_name}'.",
                    severity=Severity.HIGH,
                    confidence=1.0,
                    metadata={"violation": "CAPABILITY_UNAUTHORIZED"},
                )],
            )

        # 6. Resource Scoping & Path Traversal Safety
        if request.resource and request.capability_name.startswith("filesystem."):
            path_finding = validate_path_safety(request.resource)
            if path_finding:
                return ActionDecision(
                    decision=ActionDecisionStatus.DENY,
                    action_id=request.action_id,
                    agent_id=request.agent_id,
                    capability_name=request.capability_name,
                    resource=request.resource,
                    reason=f"Resource security violation: {path_finding.description}",
                    findings=[path_finding],
                )

        resource_permitted = any(g.allows_resource(request.resource) for g in matching_grants)
        if not resource_permitted:
            return ActionDecision(
                decision=ActionDecisionStatus.DENY,
                action_id=request.action_id,
                agent_id=request.agent_id,
                capability_name=request.capability_name,
                resource=request.resource,
                reason=f"Action denied: Resource '{request.resource}' is out of scope for capability '{request.capability_name}'.",
                findings=[Finding(
                    detector_name="capability_engine",
                    threat_type=ThreatType.POLICY_VIOLATION,
                    description=f"Resource '{request.resource}' out of authorized scope.",
                    severity=Severity.HIGH,
                    confidence=1.0,
                    metadata={"violation": "RESOURCE_SCOPE_EXCEEDED"},
                )],
            )

        # 7. Action Budget Reservation
        if budget_manager:
            allowed, reason = budget_manager.check_and_reserve(request.capability_name)
            if not allowed:
                return ActionDecision(
                    decision=ActionDecisionStatus.BUDGET_EXCEEDED,
                    action_id=request.action_id,
                    agent_id=request.agent_id,
                    capability_name=request.capability_name,
                    resource=request.resource,
                    reason=reason or "Action budget exhausted.",
                    findings=[Finding(
                        detector_name="capability_engine",
                        threat_type=ThreatType.POLICY_VIOLATION,
                        description=reason or "Budget exceeded.",
                        severity=Severity.HIGH,
                        confidence=1.0,
                        metadata={"violation": "BUDGET_EXCEEDED"},
                    )],
                )

        # 8. Human / Policy Approval Gate
        if cap_def.requires_approval:
            appr_req = ApprovalRequest(
                action_id=request.action_id,
                agent_id=request.agent_id,
                capability_name=request.capability_name,
                resource=request.resource,
            )
            approved = self.approval_provider.request_approval(appr_req)
            if not approved:
                if budget_manager:
                    budget_manager.release_reservation(request.capability_name)
                return ActionDecision(
                    decision=ActionDecisionStatus.REQUIRE_APPROVAL,
                    action_id=request.action_id,
                    agent_id=request.agent_id,
                    capability_name=request.capability_name,
                    resource=request.resource,
                    reason=f"Action '{request.capability_name}' requires approval which was not granted.",
                    approval_request=appr_req,
                    findings=[Finding(
                        detector_name="capability_engine",
                        threat_type=ThreatType.POLICY_VIOLATION,
                        description="Approval required but not granted.",
                        severity=Severity.HIGH,
                        confidence=1.0,
                        metadata={"violation": "APPROVAL_REQUIRED"},
                    )],
                )

        return ActionDecision(
            decision=ActionDecisionStatus.ALLOW,
            action_id=request.action_id,
            agent_id=request.agent_id,
            capability_name=request.capability_name,
            resource=request.resource,
            reason="Action successfully authorized.",
        )
