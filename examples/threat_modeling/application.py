"""Example: Attack Graph & AI Threat Modeling Architecture (Phase 33).

Demonstrates:
  User Ingress (Chat API)
        ↓
  Prompt Injection (T-PI-01)
        ↓
  Customer Support Agent
        ↓
  Tool Abuse / Missing Auth (T-TA-04)
        ↓
  CRM Database Tool
        ↓
  Data Exfiltration (T-DE-06)

Features:
  1. Attack Graph bounded path discovery
  2. Automated AI Threat Model generation
  3. Continuous testing corroboration (CANDIDATE -> TESTED)
  4. Governance security gap extraction
  5. Cryptographic snapshots & drift diffing
"""

import json
from llmfirewall.attack_graph import (
    AttackGraph,
    format_attack_paths_human,
    format_threat_model_human,
)
from llmfirewall.graph import (
    KnowledgeGraph,
    NodeType,
    RelationshipType,
)


def build_customer_support_graph() -> KnowledgeGraph:
    """Build an enterprise customer support system graph."""
    kg = KnowledgeGraph()

    # 1. Ingress & Application
    kg.add_node("app:customer_portal", NodeType.APPLICATION.value, properties={
        "tier": "public_ingress",
        "entry_point": True,
    })

    # 2. Support Agent
    kg.add_node("agent:support_copilot", NodeType.AGENT.value, properties={
        "role": "customer_support",
        "reasoning": "react",
    })
    kg.add_relationship("app:customer_portal", RelationshipType.USES.value, "agent:support_copilot")

    # 3. Model
    kg.add_node("model:gpt-4o", NodeType.MODEL.value, properties={"provider": "openai"})
    kg.add_relationship("agent:support_copilot", RelationshipType.USES.value, "model:gpt-4o")

    # 4. RAG Knowledge Base
    kg.add_node("rag:help_docs", NodeType.RAG_SOURCE.value, properties={"sha256": None})
    kg.add_relationship("rag:help_docs", RelationshipType.USES.value, "agent:support_copilot")

    # 5. Tools
    # Tool 1: Benign FAQ tool with passing authorization
    kg.add_node("tool:faq_reader", NodeType.TOOL.value, properties={"category": "search"})
    kg.add_relationship("agent:support_copilot", RelationshipType.CAN_CALL.value, "tool:faq_reader")
    kg.add_node("control:rbac_auth", NodeType.SECURITY_CONTROL.value, properties={"mode": "rbac", "authorization": True})
    kg.add_relationship("control:rbac_auth", RelationshipType.PROTECTS.value, "tool:faq_reader")

    # Tool 2: Unprotected CRM & Database tool (Security Gap)
    kg.add_node("tool:crm_database", NodeType.TOOL.value, properties={"category": "database"})
    kg.add_relationship("agent:support_copilot", RelationshipType.CAN_CALL.value, "tool:crm_database")

    return kg


def main() -> None:
    print("=" * 80)
    print(" LLMFIREWALL — PHASE 33: ATTACK GRAPH & AI THREAT MODELING")
    print("=" * 80)

    # 1. Build Architecture Knowledge Graph
    kg = build_customer_support_graph()
    ag = AttackGraph(kg=kg)

    # 2. Discover Multi-Step Attack Paths
    print("\n[+] Discovering Candidate Attack Paths...")
    paths = ag.find_paths(source="app:customer_portal", max_depth=4)
    print(format_attack_paths_human(paths, asset_id="app:customer_portal"))

    # 3. Generate Complete AI Threat Model
    print("\n[+] Generating AI Threat Model for 'agent:support_copilot'...")
    tm = ag.generate_threat_model(asset_id="agent:support_copilot")
    print(format_threat_model_human(tm))

    # 4. Test Corroboration (Phase 30 Integration)
    print("\n[+] Corroborating Attack Path with Automated Red-Team Tests...")
    test_results = [
        {"technique": "T-PI-01", "target": "agent:support_copilot", "passed": True, "test_id": "TEST-PI-001"},
        {"technique": "T-TA-04", "target": "tool:crm_database", "passed": True, "test_id": "TEST-TA-002"},
    ]
    tested_paths = ag.ingest_test_results(test_results)
    if tested_paths:
        print(f"    Successfully validated {len(tested_paths)} multi-step attack path(s) into TESTED status:")
        for tp in tested_paths:
            print(f"    - {tp.path_id}: Status={tp.status.value}, Confidence={tp.confidence.value}")

    # 5. Extract Governance Security Gaps (Phase 31 Integration)
    print("\n[+] Extracting Unmitigated Security Gaps into Governance Findings...")
    gaps = ag.extract_security_gaps(paths)
    for g in gaps:
        print(f"    - [{g.severity.value.upper()}] {g.category} (Resource: {g.resource})")
        print(f"      {g.description[:110]}...")

    # 6. Snapshots & Drift Diff
    print("\n[+] Capturing Security Baseline Snapshot & Simulating Architecture Drift...")
    snap_v1 = ag.snapshot(graph_version="1.0")

    # Drift: Engineer connects an administrative shell tool
    kg.add_node("tool:admin_shell", NodeType.TOOL.value, properties={"category": "system"})
    kg.add_relationship("agent:support_copilot", RelationshipType.CAN_CALL.value, "tool:admin_shell")

    snap_v2 = ag.snapshot(graph_version="1.1")
    diff = AttackGraph.diff(snap_v1, snap_v2)

    print(f"    Snapshot Digest (v1.0): {snap_v1.snapshot_hash[:16]}...")
    print(f"    Snapshot Digest (v1.1): {snap_v2.snapshot_hash[:16]}...")
    print(f"    Architectural Drift Detected: New Attack Paths = {len(diff.paths_added)}")
    for p_id in diff.paths_added:
        print(f"      * NEW_ATTACK_PATH: {p_id}")

    print("\n" + "=" * 80)
    print(" DEMO COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()
