"""Working demonstration of Agent Capability Security, Action Budgets, and Delegation."""

from llmfirewall import (
    ActionBudget,
    ActionDecisionStatus,
    BudgetManager,
    CapabilityGrant,
    Firewall,
    MemoryApprovalProvider,
)
try:
    from tools import TOOLS
except ImportError:
    from examples.agent_security.tools import TOOLS


def main():
    print("===================================================================")
    print("LLMFirewall Phase 29 — Agent Capability Security Demo")
    print("===================================================================")

    fw = Firewall()
    cap_engine = fw.capability_engine

    # Attach interactive memory approval provider
    approval_provider = MemoryApprovalProvider()
    cap_engine.approval_provider = approval_provider

    # 1. Setup Research Agent with Least-Privilege Grants
    print("\n[1] Registering Agent Capabilities:")
    agent_id = "research_agent"
    cap_engine.grant_capability(agent_id, "filesystem.read", resource_scope=["./docs/*"])
    cap_engine.grant_capability(agent_id, "network.request", resource_scope=["https://api.arxiv.org/*"])
    cap_engine.deny_capability(agent_id, "shell.execute")
    print(f"    Agent '{agent_id}' configured with filesystem.read (./docs/*) and network.request.")

    # 2. Execute Allowed Action
    print("\n[2] Executing In-Scope Action:")
    dec1 = fw.authorize_action("filesystem.read", agent_id=agent_id, resource="./docs/intro.md")
    print(f"    Action 'filesystem.read' on './docs/intro.md' -> {dec1.decision.value} ({dec1.reason})")

    # 3. Denied Out-of-Scope Resource
    print("\n[3] Attempting Out-of-Scope Action:")
    dec2 = fw.authorize_action("filesystem.read", agent_id=agent_id, resource="./secrets/credentials.json")
    print(f"    Action 'filesystem.read' on './secrets/credentials.json' -> {dec2.decision.value} ({dec2.reason})")

    # 4. Action Budget Enforcement
    print("\n[4] Action Budget Enforcement:")
    budget = ActionBudget(max_actions=2)
    budget_mgr = BudgetManager(budget=budget)

    b1 = fw.authorize_action("filesystem.read", agent_id=agent_id, resource="./docs/part1.md", budget_manager=budget_mgr)
    b2 = fw.authorize_action("filesystem.read", agent_id=agent_id, resource="./docs/part2.md", budget_manager=budget_mgr)
    b3 = fw.authorize_action("filesystem.read", agent_id=agent_id, resource="./docs/part3.md", budget_manager=budget_mgr)

    print(f"    Action 1: {b1.decision.value}")
    print(f"    Action 2: {b2.decision.value}")
    print(f"    Action 3: {b3.decision.value} ({b3.reason})")

    # 5. Delegation and Privilege Escalation Prevention
    print("\n[5] Multi-Agent Delegation Controls:")
    child_id = "writer_agent"
    # Research agent delegates filesystem.read to writer agent (permitted)
    cap_engine.delegate(
        parent_agent_id=agent_id,
        child_agent_id=child_id,
        capabilities_to_delegate=[CapabilityGrant(capability_name="filesystem.read")],
    )
    print(f"    Delegated 'filesystem.read' from '{agent_id}' to '{child_id}'.")
    dec_child = fw.authorize_action("filesystem.read", agent_id=child_id, resource="./docs/intro.md")
    print(f"    Writer agent action: {dec_child.decision.value}")

    # Privilege escalation attempt
    try:
        cap_engine.delegate(
            parent_agent_id=agent_id,
            child_agent_id=child_id,
            capabilities_to_delegate=[CapabilityGrant(capability_name="shell.execute")],
        )
    except PermissionError as e:
        print(f"    Privilege escalation blocked as expected: {e}")

    # 6. Approval Gate Workflow
    print("\n[6] Human/Administrative Approval Gate:")
    cap_engine.grant_capability(agent_id, "database.delete")
    action_key = "act-cleanup-99"

    # Attempt without approval
    dec_unappr = fw.authorize_action(
        "database.delete",
        agent_id=agent_id,
        resource="temp_table",
    )
    print(f"    Unapproved delete -> {dec_unappr.decision.value} ({dec_unappr.reason})")

    # Grant pre-approval
    approval_provider.pre_approve(
        action_id=action_key,
        agent_id=agent_id,
        capability_name="database.delete",
        resource="temp_table",
        approved_by="security_officer_carol",
    )
    from llmfirewall.capabilities.models import ActionRequest
    req_appr = ActionRequest(
        action_id=action_key,
        agent_id=agent_id,
        capability_name="database.delete",
        resource="temp_table",
    )
    dec_appr = cap_engine.authorize_action(req_appr)
    print(f"    Approved delete   -> {dec_appr.decision.value} ({dec_appr.reason})")

    print("\n===================================================================")
    print("Agent Capability Security Demo Complete.")
    print("===================================================================")


if __name__ == "__main__":
    main()
