"""Comprehensive test suite for Phase 29: Agent Capability Security & Action Control."""

import time
import pytest
from concurrent.futures import ThreadPoolExecutor

from llmfirewall import (
    Action,
    ActionBudget,
    ActionClassification,
    ActionDecisionStatus,
    ActionRequest,
    ApprovalRequest,
    BudgetManager,
    CallbackApprovalProvider,
    Capability,
    CapabilityEngine,
    CapabilityGrant,
    CapabilityRiskClass,
    DelegationGrant,
    DenyAllApprovalProvider,
    Firewall,
    MemoryApprovalProvider,
    SideEffectType,
)


def test_capability_least_privilege_and_explicit_deny():
    """Test that capabilities are not granted implicitly, and explicit deny overrides grants."""
    engine = CapabilityEngine()

    # Agent A has no grants
    req_unauth = ActionRequest(
        agent_id="agent_a",
        capability_name="filesystem.read",
        resource="./docs/plan.md",
    )
    dec_unauth = engine.authorize_action(req_unauth)
    assert dec_unauth.decision == ActionDecisionStatus.DENY
    assert "not been granted capability" in dec_unauth.reason

    # Grant filesystem.read to agent_a
    engine.grant_capability("agent_a", "filesystem.read", resource_scope=["./docs/*"])
    dec_auth = engine.authorize_action(req_unauth)
    assert dec_auth.decision == ActionDecisionStatus.ALLOW

    # Verify agent_a did NOT implicitly get filesystem.write
    req_write = ActionRequest(
        agent_id="agent_a",
        capability_name="filesystem.write",
        resource="./docs/plan.md",
    )
    dec_write = engine.authorize_action(req_write)
    assert dec_write.decision == ActionDecisionStatus.DENY

    # Explicit deny on agent_a for filesystem.read
    engine.deny_capability("agent_a", "filesystem.read")
    dec_denied = engine.authorize_action(req_unauth)
    assert dec_denied.decision == ActionDecisionStatus.DENY
    assert "explicitly denied" in dec_denied.reason


def test_resource_scoping_and_path_security():
    """Test glob-based resource scoping and directory traversal protection."""
    engine = CapabilityEngine()
    engine.grant_capability("agent_scoped", "filesystem.read", resource_scope=["./documents/*"])

    # 1. Allowed scoped resource
    req_ok = ActionRequest(agent_id="agent_scoped", capability_name="filesystem.read", resource="./documents/faq.txt")
    assert engine.authorize_action(req_ok).decision == ActionDecisionStatus.ALLOW

    # 2. Out of scope resource
    req_out = ActionRequest(agent_id="agent_scoped", capability_name="filesystem.read", resource="./secrets/key.pem")
    dec_out = engine.authorize_action(req_out)
    assert dec_out.decision == ActionDecisionStatus.DENY
    assert "out of scope" in dec_out.reason

    # 3. Path traversal attack attempting to escape scope
    req_traversal = ActionRequest(
        agent_id="agent_scoped",
        capability_name="filesystem.read",
        resource="./documents/../../etc/passwd",
    )
    dec_trav = engine.authorize_action(req_traversal)
    assert dec_trav.decision == ActionDecisionStatus.DENY
    assert any("traversal" in f.description.lower() for f in dec_trav.findings)


def test_delegation_and_privilege_escalation_protection():
    """Test parent -> child agent delegation ensuring child <= parent permissions."""
    engine = CapabilityEngine(max_delegation_depth=2)

    # Parent has filesystem.read and network.request
    engine.grant_capability("parent_agent", "filesystem.read")
    engine.grant_capability("parent_agent", "network.request")

    # 1. Valid delegation subset
    del_grant = engine.delegate(
        parent_agent_id="parent_agent",
        child_agent_id="child_agent",
        capabilities_to_delegate=[CapabilityGrant(capability_name="filesystem.read")],
        depth=1,
    )
    assert del_grant.child_agent_id == "child_agent"

    req_child = ActionRequest(agent_id="child_agent", capability_name="filesystem.read")
    assert engine.authorize_action(req_child).decision == ActionDecisionStatus.ALLOW

    # 2. Privilege escalation attempt: Parent tries to delegate shell.execute (which parent lacks)
    with pytest.raises(PermissionError) as exc_info:
        engine.delegate(
            parent_agent_id="parent_agent",
            child_agent_id="rogue_child",
            capabilities_to_delegate=[CapabilityGrant(capability_name="shell.execute")],
            depth=1,
        )
    assert "Privilege escalation prevented" in str(exc_info.value)

    # 3. Max delegation depth exceeded
    with pytest.raises(ValueError) as exc_depth:
        engine.delegate(
            parent_agent_id="parent_agent",
            child_agent_id="deep_child",
            capabilities_to_delegate=[CapabilityGrant(capability_name="filesystem.read")],
            depth=3,  # max is 2
        )
    assert "exceeds max allowed depth" in str(exc_depth.value)


def test_action_budget_and_reservation():
    """Test total action budget, per-capability limits, and runtime timeouts."""
    budget = ActionBudget(
        max_actions=3,
        per_capability_limits={"network.request": 2},
        max_runtime_seconds=50.0,
    )
    mgr = BudgetManager(budget=budget)
    engine = CapabilityEngine()
    engine.grant_capability("agent_b", "network.request")
    engine.grant_capability("agent_b", "filesystem.read")

    # Call 1: network.request (allowed)
    r1 = engine.authorize_action(ActionRequest(agent_id="agent_b", capability_name="network.request"), budget_manager=mgr)
    assert r1.decision == ActionDecisionStatus.ALLOW

    # Call 2: network.request (allowed, 2nd)
    r2 = engine.authorize_action(ActionRequest(agent_id="agent_b", capability_name="network.request"), budget_manager=mgr)
    assert r2.decision == ActionDecisionStatus.ALLOW

    # Call 3: network.request exceeds per-capability budget (max 2)
    r3 = engine.authorize_action(ActionRequest(agent_id="agent_b", capability_name="network.request"), budget_manager=mgr)
    assert r3.decision == ActionDecisionStatus.BUDGET_EXCEEDED

    # Call 4: filesystem.read (allowed, total action 3)
    r4 = engine.authorize_action(ActionRequest(agent_id="agent_b", capability_name="filesystem.read"), budget_manager=mgr)
    assert r4.decision == ActionDecisionStatus.ALLOW

    # Call 5: total action limit exceeded (max 3 reached)
    r5 = engine.authorize_action(ActionRequest(agent_id="agent_b", capability_name="filesystem.read"), budget_manager=mgr)
    assert r5.decision == ActionDecisionStatus.BUDGET_EXCEEDED


def test_approval_gates_and_replay_prevention():
    """Test approval requirement, approval provider authorization, and replay prevention."""
    approval_provider = MemoryApprovalProvider()
    engine = CapabilityEngine(approval_provider=approval_provider)
    engine.grant_capability("ops_agent", "database.delete")

    action_id = "act-delete-101"
    req_delete = ActionRequest(
        action_id=action_id,
        agent_id="ops_agent",
        capability_name="database.delete",
        resource="users_table",
    )

    # 1. Unapproved: Requires approval -> Denied
    dec_unapproved = engine.authorize_action(req_delete)
    assert dec_unapproved.decision == ActionDecisionStatus.REQUIRE_APPROVAL

    # 2. Pre-approve specifically for action_id and resource
    approval_provider.pre_approve(
        action_id=action_id,
        agent_id="ops_agent",
        capability_name="database.delete",
        resource="users_table",
        approved_by="admin_alice",
    )

    dec_approved = engine.authorize_action(req_delete)
    assert dec_approved.decision == ActionDecisionStatus.ALLOW

    # 3. Approval Replay Attempt: Trying to reuse same approval for different resource
    req_replay = ActionRequest(
        action_id=action_id,
        agent_id="ops_agent",
        capability_name="database.delete",
        resource="audit_logs",  # Different resource!
    )
    dec_replay = engine.authorize_action(req_replay)
    assert dec_replay.decision == ActionDecisionStatus.REQUIRE_APPROVAL


def test_agent_kill_switch_and_revocation():
    """Test session revocation and agent kill switch."""
    engine = CapabilityEngine()
    engine.grant_capability("monitored_agent", "filesystem.read")

    session_id = "session_xyz_789"
    req1 = ActionRequest(agent_id="monitored_agent", session_id=session_id, capability_name="filesystem.read")
    assert engine.authorize_action(req1).decision == ActionDecisionStatus.ALLOW

    # Trigger session kill switch
    engine.revoke_session(session_id)

    dec_killed = engine.authorize_action(req1)
    assert dec_killed.decision == ActionDecisionStatus.DENY
    assert "kill-switch active" in dec_killed.reason


def test_action_depth_and_loop_detection():
    """Test action chain nesting depth limit and excessive identical loop detection."""
    engine = CapabilityEngine(max_action_depth=10, max_repeated_actions=5)
    engine.grant_capability("loop_agent", "filesystem.read")

    # Identical repeated action loop
    session_id = "loop_sess"
    for i in range(4):
        req = ActionRequest(agent_id="loop_agent", session_id=session_id, capability_name="filesystem.read", resource="file.txt")
        dec = engine.authorize_action(req)
        assert dec.decision == ActionDecisionStatus.ALLOW

    # 5th identical action triggers loop protection
    req_loop = ActionRequest(agent_id="loop_agent", session_id=session_id, capability_name="filesystem.read", resource="file.txt")
    dec_loop = engine.authorize_action(req_loop)
    assert dec_loop.decision == ActionDecisionStatus.DENY
    assert any(f.metadata.get("violation") == "AGENT_LOOP_DETECTED" for f in dec_loop.findings)


def test_concurrency_thread_safety():
    """Verify thread-safe concurrent capability checks and budget consumption."""
    budget = ActionBudget(max_actions=100)
    mgr = BudgetManager(budget=budget)
    engine = CapabilityEngine()
    engine.grant_capability("concurrent_agent", "filesystem.read")

    def execute_action(idx: int):
        req = ActionRequest(
            action_id=f"act-{idx}",
            agent_id="concurrent_agent",
            session_id="thread_session",
            capability_name="filesystem.read",
        )
        return engine.authorize_action(req, budget_manager=mgr)

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(execute_action, range(120)))

    allowed_count = sum(1 for r in results if r.decision == ActionDecisionStatus.ALLOW)
    exceeded_count = sum(1 for r in results if r.decision == ActionDecisionStatus.BUDGET_EXCEEDED)

    # Exactly 100 allowed, exactly 20 budget exceeded
    assert allowed_count == 100
    assert exceeded_count == 20
    assert mgr.total_actions == 100


def test_firewall_integration_authorize_action():
    """Test Firewall.authorize_action() and Firewall.revoke_session() top-level methods."""
    fw = Firewall()
    fw.capability_engine.grant_capability("fw_agent", "filesystem.read", resource_scope=["./reports/*"])

    # Allowed
    dec_ok = fw.authorize_action("filesystem.read", agent_id="fw_agent", resource="./reports/q3.csv")
    assert dec_ok.is_allowed

    # Denied out of scope
    dec_bad = fw.authorize_action("filesystem.read", agent_id="fw_agent", resource="./private/keys.json")
    assert not dec_bad.is_allowed

    # Revoke session
    sess_id = "test_sess_001"
    fw.revoke_session(sess_id)
    dec_rev = fw.authorize_action("filesystem.read", agent_id="fw_agent", session_id=sess_id)
    assert not dec_rev.is_allowed
