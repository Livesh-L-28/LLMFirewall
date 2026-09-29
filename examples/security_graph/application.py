"""Example: AI Security Knowledge Graph Architecture (Phase 32).

Demonstrates:
  Application
      ↓
    Agent
   ┌──┴─────┐
   ↓        ↓
 Model    Tool
            ↓
         Database

  + Policy
  + SecurityControl
  + Finding
  + SecurityTest
"""

import json
from pathlib import Path
from llmfirewall.graph import (
    KnowledgeGraph,
    NodeType,
    RelationshipType,
    ControlStatus,
    format_impact_human,
    format_blast_radius_human,
    format_coverage_human,
    format_path_human,
)


def build_enterprise_ai_graph() -> KnowledgeGraph:
    """Construct an illustrative AI security knowledge graph."""
    kg = KnowledgeGraph()

    # 1. Assets: Application, Agent, Model, Tools
    kg.add_node("app:customer_portal", node_type=NodeType.APPLICATION.value, properties={
        "environment": "production",
        "tier": "mission_critical",
    })
    kg.add_node("agent:support_copilot", node_type=NodeType.AGENT.value, properties={
        "role": "customer_support",
        "framework": "langchain",
        "version": "2.4.0",
    })
    kg.add_node("model:gpt-4o", node_type=NodeType.MODEL.value, properties={
        "provider": "openai",
        "model_id": "gpt-4o-2024-08-06",
        "context_window": 128000,
    })
    kg.add_node("tool:web_search", node_type=NodeType.TOOL.value, properties={
        "permission": "read_only",
        "network_access": True,
    })
    kg.add_node("tool:customer_db", node_type=NodeType.TOOL.value, properties={
        "permission": "read_write",
        "category": "database",
    })

    # 2. Controls & Governance: Policies, Security Controls
    kg.add_node("policy:enterprise_ai_guardrails", node_type=NodeType.POLICY.value, properties={
        "version": "3.1.0",
        "compliance": ["NIST_AI_RMF", "EU_AI_ACT"],
    })
    kg.add_node("control:prompt_shield", node_type=NodeType.SECURITY_CONTROL.value, properties={
        "name": "Prompt Injection Shield",
        "enforcement": "block",
    })
    kg.add_node("control:sql_sanitizer", node_type=NodeType.SECURITY_CONTROL.value, properties={
        "name": "SQL Injection & Tool Parameter Sanitizer",
        "enforcement": "validate_and_sanitize",
    })

    # 3. Findings, Threats & Tests
    kg.add_node("threat:indirect_injection", node_type=NodeType.THREAT.value, properties={
        "cwe": "CWE-1426",
        "severity": "high",
    })
    kg.add_node("test:pi_regression_suite", node_type=NodeType.SECURITY_TEST.value, properties={
        "suite_name": "prompt_injection_v2",
        "status": "passing",
        "pass_rate": 1.0,
    })
    kg.add_node("finding:db_auth_missing", node_type=NodeType.FINDING.value, properties={
        "severity": "medium",
        "rule_id": "SEC-TOOL-02",
        "title": "Tool lacks granular column-level authorization",
    })

    # 4. Directed Relationships
    # Topology: Application -> Agent -> (Model, Tools -> Database)
    kg.add_relationship("app:customer_portal", RelationshipType.USES.value, "agent:support_copilot")
    kg.add_relationship("agent:support_copilot", RelationshipType.USES.value, "model:gpt-4o")
    kg.add_relationship("agent:support_copilot", RelationshipType.CAN_CALL.value, "tool:web_search")
    kg.add_relationship("agent:support_copilot", RelationshipType.CAN_CALL.value, "tool:customer_db")

    # Policy Governance
    kg.add_relationship("app:customer_portal", RelationshipType.GOVERNED_BY.value, "policy:enterprise_ai_guardrails")
    kg.add_relationship("agent:support_copilot", RelationshipType.GOVERNED_BY.value, "policy:enterprise_ai_guardrails")

    # Security Controls
    kg.add_relationship("control:prompt_shield", RelationshipType.PROTECTS.value, "agent:support_copilot")
    kg.add_relationship("control:sql_sanitizer", RelationshipType.PROTECTS.value, "tool:customer_db")
    kg.add_relationship("control:prompt_shield", RelationshipType.MITIGATES.value, "threat:indirect_injection")

    # Security Testing & Findings
    kg.add_relationship("test:pi_regression_suite", RelationshipType.TESTS.value, "control:prompt_shield")
    kg.add_relationship("finding:db_auth_missing", RelationshipType.AFFECTS.value, "tool:customer_db")
    kg.add_relationship("finding:db_auth_missing", RelationshipType.MITIGATED_BY.value, "control:sql_sanitizer")

    return kg


def main():
    print("=" * 70)
    print(" LLMFirewall Phase 32 — AI Security Knowledge Graph Example")
    print("=" * 70)

    # 1. Build and validate graph
    kg = build_enterprise_ai_graph()
    errors = kg.validate()
    print("\n[1] Graph Construction & Validation:")
    print(f"    Nodes: {kg.store.node_count()} | Relationships: {kg.store.relationship_count()}")
    print(f"    Integrity Status: {'VALID (0 errors)' if not errors else f'ERRORS: {errors}'}")

    # 2. Directed Path Discovery
    print("\n[2] Bounded Path Discovery (app:customer_portal -> tool:customer_db):")
    path = kg.find_path("app:customer_portal", "tool:customer_db", max_depth=4)
    if path:
        print(f"    {format_path_human(path)}")

    # 3. Security Impact Query
    print("\n[3] Security Impact Analysis for agent:support_copilot:")
    impact = kg.security_impact("agent:support_copilot", max_depth=2)
    print(format_impact_human(impact))

    # 4. Outward Blast Radius Analysis (What happens if model:gpt-4o changes?)
    print("\n[4] Blast Radius Analysis for model:gpt-4o:")
    blast = kg.blast_radius("model:gpt-4o", max_depth=3)
    print(format_blast_radius_human(blast))

    # 5. Evidence-Based Control Coverage (No fake coverage)
    print("\n[5] Control Coverage Assessment for agent:support_copilot:")
    coverage = kg.control_coverage("agent:support_copilot")
    print(format_coverage_human(coverage))

    # 6. Cryptographic Snapshot
    snap = kg.snapshot()
    print("\n[6] Tamper-Evident Graph Snapshot:")
    print(f"    Schema Version: {snap.schema_version}")
    print(f"    Canonical SHA-256 Digest: {snap.graph_hash}")

    # Export graph to disk
    out_file = Path("examples/security_graph/sample_graph.json")
    kg.export_to_file(str(out_file))
    print(f"    Exported to: {out_file} ({out_file.stat().st_size} bytes)")

    print("\n" + "=" * 70)
    print(" AI Security Knowledge Graph Demonstration Completed.")
    print("=" * 70)


if __name__ == "__main__":
    main()
