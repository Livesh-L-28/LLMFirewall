"""Example: AI Security Posture Management (AI-SPM) (Phase 35).

Demonstrates the full defensive security lifecycle:
1. Asset discovery & topology setup (Customer Support AI with Agent, Tools, Memory, RAG).
2. Initial posture evaluation revealing unmitigated attack paths and security gaps.
3. Baseline snapshot capture (SHA-256 fingerprinting).
4. Engineering remediation (adding Tool Authorization and Input Validation controls).
5. Ingesting empirical security test results confirming control validation.
6. Posture re-evaluation and comparative diff showing posture improvement and gap resolution.
"""

import json
import time

from llmfirewall import (
    Asset,
    AssetInventory,
    AssetSource,
    AssetType,
    AttackGraph,
    KnowledgeGraph,
    Node,
    NodeType,
    Relationship,
    RelationshipType,
)
from llmfirewall.spm import (
    ControlEffectiveness,
    ControlPresence,
    PostureEngine,
    PostureState,
    format_posture_diff_human,
    format_posture_human,
    format_posture_json,
    format_posture_summary_human,
)


def run_spm_lifecycle_demo() -> None:
    print("=" * 80)
    print("  LLMFirewall Phase 35: AI Security Posture Management (AI-SPM) Demo")
    print("=" * 80)

    # 1. Setup Knowledge Graph, Attack Graph, and Asset Inventory
    kg = KnowledgeGraph()
    kg.register_node_type("memory_store")
    ag = AttackGraph(kg=kg)
    inv = AssetInventory(kg=kg, attack_graph=ag)
    engine = PostureEngine(inventory=inv, kg=kg, attack_graph=ag)

    print("\n[Step 1] Discovering & Registering AI Assets...")

    # Assets
    app = Asset(id="application:support_portal", type=AssetType.APPLICATION, name="Support Portal", environment="production")
    agent = Asset(id="agent:support_agent", type=AssetType.AGENT, name="Customer Support Agent", environment="production", metadata={"department": "support"})
    model = Asset(id="model:gpt-4o", type=AssetType.MODEL, name="GPT-4o", environment="production", version="2024-08-06")
    db_tool = Asset(id="tool:customer_db", type=AssetType.TOOL, name="Customer Database Tool", environment="production", metadata={"category": "database", "sensitivity": "high"})
    search_tool = Asset(id="tool:web_search", type=AssetType.TOOL, name="Web Search Tool", environment="production")
    memory = Asset(id="memory_store:customer_memory", type="memory_store", name="Session Memory Store", environment="production")
    rag = Asset(id="rag_source:support_kb", type=AssetType.RAG_SOURCE, name="Knowledge Base RAG", environment="production")

    for a in (app, agent, model, db_tool, search_tool, memory, rag):
        inv.register(a)
        kg.add_node(Node(id=a.id, type=a.type, properties={"name": a.name}))

    # Topology relationships
    kg.add_relationship(Relationship(source=app.id, type=RelationshipType.USES.value, target=agent.id))
    kg.add_relationship(Relationship(source=agent.id, type=RelationshipType.USES.value, target=model.id))
    kg.add_relationship(Relationship(source=agent.id, type=RelationshipType.CAN_CALL.value, target=db_tool.id))
    kg.add_relationship(Relationship(source=agent.id, type=RelationshipType.CAN_CALL.value, target=search_tool.id))
    kg.add_relationship(Relationship(source=agent.id, type=RelationshipType.CAN_ACCESS.value, target=memory.id))
    kg.add_relationship(Relationship(source=agent.id, type=RelationshipType.CAN_ACCESS.value, target=rag.id))

    print(f"  ✓ Registered {len(inv.list_assets())} AI assets in inventory and graph.")

    # 2. Initial Posture Evaluation
    print("\n[Step 2] Evaluating Initial Security Posture...")
    p_initial = engine.evaluate(agent.id)
    print(format_posture_human(p_initial))

    # Capture Baseline Snapshot
    print("\n[Step 3] Capturing Baseline Snapshot (SHA-256)...")
    snap_baseline = engine.snapshot(posture_version="1.0-baseline")
    print(f"  ✓ Snapshot Hash: {snap_baseline.snapshot_hash}")
    print(f"  ✓ Identified {len(p_initial.security_gaps)} security gap(s).")

    # 3. Remediation Engineering
    print("\n[Step 4] Applying Remediation & Defensive Security Controls...")
    # Add Tool Authorization control protecting customer_db
    auth_ctrl = Asset(
        id="control:tool_authorizer",
        type=AssetType.SECURITY_CONTROL,
        name="RBAC Tool Authorizer",
        environment="production",
        source=AssetSource.CONFIGURATION,
    )
    val_ctrl = Asset(
        id="control:database_firewall",
        type=AssetType.SECURITY_CONTROL,
        name="Database Query Validator",
        environment="production",
        source=AssetSource.CONFIGURATION,
    )
    inv.register(auth_ctrl)
    inv.register(val_ctrl)
    kg.add_node(Node(id=auth_ctrl.id, type=NodeType.SECURITY_CONTROL.value, properties={"name": auth_ctrl.name}))
    kg.add_node(Node(id=val_ctrl.id, type=NodeType.SECURITY_CONTROL.value, properties={"name": val_ctrl.name}))

    kg.add_relationship(Relationship(source=auth_ctrl.id, type=RelationshipType.PROTECTS.value, target=agent.id))
    kg.add_relationship(Relationship(source=val_ctrl.id, type=RelationshipType.PROTECTS.value, target=db_tool.id))

    # Ingest passing security tests
    engine.ingest_test_results(agent.id, [
        {"target": auth_ctrl.id, "name": "Tool Authorization Enforcement", "passed": True, "timestamp": time.time()},
        {"target": val_ctrl.id, "name": "SQL Injection & Query Defense", "passed": True, "timestamp": time.time()},
    ])
    print("  ✓ Registered Tool Authorizer and Database Validator controls.")
    print("  ✓ Ingested verified passing security test results.")

    # 4. Re-evaluate Posture
    print("\n[Step 5] Re-evaluating Security Posture Post-Remediation...")
    p_remediated = engine.evaluate(agent.id)
    print(format_posture_human(p_remediated))

    snap_remediated = engine.snapshot(posture_version="2.0-remediated")

    # 5. Posture Diff
    print("\n[Step 6] Comparing Posture Against Baseline (Diff)...")
    diff = PostureEngine.diff(snap_baseline, snap_remediated)
    print(format_posture_diff_human(diff))

    print("=" * 80)
    print("  AI-SPM Lifecycle Demo Completed Successfully!")
    print("=" * 80)


if __name__ == "__main__":
    run_spm_lifecycle_demo()
