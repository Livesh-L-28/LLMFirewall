"""Example: AI Security Compliance & Control Mapping (Phase 36).

Demonstrates the complete evidence-driven compliance workflow:
1. AI Asset Inventory & Posture setup (Customer Support AI).
2. Initial compliance assessment against AI Security Baseline v1.0.0.
3. Identifying open compliance gaps (e.g. Missing Tool Authorization Evidence).
4. Evidence Chain Traceability:
   Asset -> Security Control -> Posture -> Evidence -> Compliance Control -> Assessment -> Gap.
5. Ingesting empirical security tests & policies to satisfy requirements.
6. Re-assessing compliance to verify transition to EVIDENCED status.
7. Managing formal business exceptions and waivers with automatic expiration.
8. Exporting compliance baseline snapshot and SARIF vulnerability report.
"""

import json
import time

from llmfirewall import (
    Asset,
    AssetInventory,
    AssetType,
    AttackGraph,
    KnowledgeGraph,
    Node,
    NodeType,
    Relationship,
    RelationshipType,
)
from llmfirewall.compliance import (
    ComplianceEngine,
    ComplianceEvidence,
    ControlState,
    EvidenceType,
    EvidenceValidity,
    format_compliance_human,
    format_control_detail_human,
)
from llmfirewall.spm import PostureEngine


def run_compliance_demo() -> None:
    print("=" * 80)
    print("  LLMFirewall Phase 36: AI Security Compliance & Control Mapping Demo")
    print("=" * 80)

    # 1. Setup Underlying Knowledge Graph, Attack Graph, Inventory, and AI-SPM Posture
    kg = KnowledgeGraph()
    ag = AttackGraph(kg=kg)
    inv = AssetInventory(kg=kg, attack_graph=ag)
    spm = PostureEngine(inventory=inv, kg=kg, attack_graph=ag)

    print("\n[Step 1] Registering Customer Support AI Assets...")
    agent = Asset(id="agent:customer-support", type=AssetType.AGENT, name="Customer Support Agent", environment="production")
    tool = Asset(id="tool:db-query", type=AssetType.TOOL, name="Database Query Tool", environment="production")
    model = Asset(id="model:gpt-4o", type=AssetType.MODEL, name="GPT-4o Foundation Model", environment="production")

    inv.register(agent)
    inv.register(tool)
    inv.register(model)

    kg.add_node(Node(id=agent.id, type=NodeType.AGENT.value))
    kg.add_node(Node(id=tool.id, type=NodeType.TOOL.value))
    kg.add_node(Node(id=model.id, type=NodeType.MODEL.value))
    kg.add_relationship(Relationship(source=agent.id, type=RelationshipType.CAN_CALL.value, target=tool.id))
    kg.add_relationship(Relationship(source=agent.id, type=RelationshipType.CALLS.value, target=model.id))

    # Initialize Compliance Engine
    compliance = ComplianceEngine(inventory=inv, kg=kg, attack_graph=ag, spm=spm)
    print(f"Loaded Control Catalog: {len(compliance.catalog.list_frameworks())} framework(s), 15 security domains.")

    # 2. Initial Assessment
    print("\n[Step 2] Executing Initial Compliance Assessment for 'agent:customer-support'...")
    assessments_initial = compliance.assess_asset("agent:customer-support")
    ac_assessment = next(a for a in assessments_initial if a.control_id == "ai-baseline:AC-01")

    print("\nControl 'ai-baseline:AC-01' (Tool Authorization):")
    print(f"  Status: {ac_assessment.status.value}")
    print(f"  Missing Evidence: {ac_assessment.missing_evidence}")
    print(f"  Gaps Identified: {len(ac_assessment.gaps)}")
    if ac_assessment.gaps:
        print(f"  Remediation Guidance: {ac_assessment.gaps[0].remediation_guidance}")

    # 3. Defensive Engineering: Configure Policy and Execute Security Tests
    print("\n[Step 3] Adding Defensive Controls & Registering Empirical Test Evidence...")
    now = time.time()

    # Evidence A: Configured Policy
    compliance.add_evidence(ComplianceEvidence(
        type=EvidenceType.POLICY,
        source="llmfirewall.governance",
        asset_id="agent:customer-support",
        control_id="ai-baseline:AC-01",
        collected_at=now,
        last_verified=now,
        content_reference="authorization_policy:enforce_tool_rbac",
        status=EvidenceValidity.VALID,
    ))

    # Evidence B: Automated Security Test Run (Unauthorized Tool Invocation Blocked)
    compliance.add_evidence(ComplianceEvidence(
        type=EvidenceType.SECURITY_TEST,
        source="llmfirewall.security_testing",
        asset_id="agent:customer-support",
        control_id="ai-baseline:AC-01",
        collected_at=now,
        last_verified=now,
        content_reference="authorization_test:T-TA-01:BLOCKED",
        status=EvidenceValidity.VALID,
    ))

    # Evidence C: Production Configuration Verification
    compliance.add_evidence(ComplianceEvidence(
        type=EvidenceType.CONFIGURATION,
        source="runtime_config_engine",
        asset_id="agent:customer-support",
        control_id="ai-baseline:AC-01",
        collected_at=now,
        last_verified=now,
        content_reference="production_configuration:verified_active",
        status=EvidenceValidity.VALID,
    ))

    # 4. Re-Assessment and Verification of EVIDENCED Status
    print("\n[Step 4] Re-Assessing Compliance Post-Remediation...")
    ac_assessment_post = compliance.assess_control("ai-baseline:AC-01", "agent:customer-support")

    print("Control 'ai-baseline:AC-01' Post-Remediation:")
    print(f"  Status: {ac_assessment_post.status.value}")
    print(f"  Missing Evidence: {ac_assessment_post.missing_evidence}")
    print(f"  Open Gaps: {len(ac_assessment_post.gaps)}")

    # 5. Complete Evidence Chain Traceability (Section 63)
    print("\n[Step 5] Section 63 Complete Evidence Chain Traceability:")
    chain = ac_assessment_post.evidence_chain
    print(f"  Framework Control:    {chain.get('framework_control')}")
    print(f"  Asset:                {chain.get('asset')}")
    print(f"  Defensive Controls:   {chain.get('security_controls')}")
    print(f"  Security Posture:     {chain.get('posture')}")
    print(f"  Tests / Policies:     {chain.get('test_policy_finding')}")
    print(f"  Evidence Artifacts:   {chain.get('evidence')}")

    # 6. Managing Formal Exceptions & Waivers
    print("\n[Step 6] Granting Formal Business Exception for Unresolved Gap...")
    exc = compliance.add_exception(
        control_id="ai-baseline:RS-01",
        asset_id="agent:customer-support",
        reason="RAG vector store isolation scheduled for Q4 infrastructure upgrade.",
        approved_by="Jane Doe, VP of Security Architecture",
        duration_seconds=30 * 86400,
    )
    print(f"  Exception ID:   {exc.exception_id}")
    print(f"  Approved By:    {exc.approved_by}")
    print(f"  Is Active:      {exc.is_active}")

    # 7. Summary Report
    print("\n[Step 7] Generating Comprehensive Compliance Assessment Report:")
    all_assessments = [compliance.assess_control(c.id, "agent:customer-support") for c in compliance.catalog.get_framework("ai-security-baseline").controls.values()]
    report = format_compliance_human(
        all_assessments,
        framework_name="AI Security Baseline",
        framework_version="1.0.0",
        exceptions=compliance.list_exceptions(),
    )
    print(report)

    # 8. SARIF Vulnerability Export
    print("\n[Step 8] Exporting Actionable Compliance Gaps as SARIF 2.1.0...")
    sarif = compliance.export_sarif()
    print(f"  SARIF Version:  {sarif['version']}")
    print(f"  Runs / Rules:   {len(sarif['runs'][0]['tool']['driver']['rules'])}")
    print(f"  Actionable Gaps Recorded: {len(sarif['runs'][0]['results'])}")

    print("\n" + "=" * 80)
    print("  Phase 36 Compliance Demo Completed Successfully!")
    print("=" * 80)


if __name__ == "__main__":
    run_compliance_demo()
