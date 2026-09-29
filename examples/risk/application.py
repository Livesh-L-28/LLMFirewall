"""Runnable example demonstrating AI Security Risk Prioritization (Phase 37)."""

import json
from llmfirewall import Firewall, RiskLevel, RiskFactorType
from llmfirewall.inventory import Asset, AssetType
from llmfirewall.graph import Node, NodeType, Relationship, RelationshipType

def main() -> None:
    print("=" * 80)
    print("      LLMFirewall Phase 37: AI Security Risk & Prioritization Engine      ")
    print("=" * 80)

    # 1. Initialize Firewall orchestrator
    fw = Firewall()

    # 2. Register assets with concrete exposure and criticality
    fw.inventory.register(Asset.create(
        asset_id="agent:support_copilot",
        asset_type=AssetType.AGENT.value,
        name="Customer Support Copilot",
        metadata={"criticality": 0.8, "exposure": "external", "data_classification": "sensitive"},
    ))
    fw.inventory.register(Asset.create(
        asset_id="tool:db_sql_tool",
        asset_type=AssetType.TOOL.value,
        name="Database SQL Query Tool",
        metadata={"criticality": 0.9, "exposure": "internal", "data_classification": "restricted"},
    ))
    fw.inventory.register(Asset.create(
        asset_id="db:production_customers",
        asset_type=AssetType.DATABASE.value,
        name="Production Customer Database",
        metadata={"criticality": 0.95, "exposure": "isolated", "data_classification": "restricted"},
    ))

    # 3. Model relations in knowledge graph
    fw.knowledge_graph.add_node(Node(id="agent:support_copilot", type=NodeType.AGENT.value))
    fw.knowledge_graph.add_node(Node(id="tool:db_sql_tool", type=NodeType.TOOL.value))
    fw.knowledge_graph.add_node(Node(id="db:production_customers", type=NodeType.CUSTOM.value))
    fw.knowledge_graph.add_relationship(Relationship(source="agent:support_copilot", target="tool:db_sql_tool", type=RelationshipType.CALLS.value))
    fw.knowledge_graph.add_relationship(Relationship(source="tool:db_sql_tool", target="db:production_customers", type=RelationshipType.CAN_ACCESS.value))

    # 4. Assess risk for customer support agent
    assessments = fw.risk.prioritize(asset_id="agent:support_copilot")
    print(f"\nPrioritized Assessments: {len(assessments)}")

    for r in assessments:
        print(f"\n[RISK ASSESSMENT: {r.id}]")
        print(f"Target Asset:         {r.asset_id}")
        print(f"Risk Level:           {r.level.value}")
        print(f"Inherited From:       {r.inherited_from or 'None'}")
        print(f"Uncertainty:          {r.uncertainty.value}")
        print(f"Prioritization Reason: {r.rationale}")
        print("\nIndependently Evaluated Factors:")
        for factor in r.factors:
            print(f"  - [{factor.factor_type.value}] {factor.name} (score: {factor.score:.2f}, weight: {factor.weight}): {factor.rationale}")

    # 5. Snapshot & Diff
    snap1 = fw.risk.snapshot(environment="production")
    print(f"\nBaseline Risk Snapshot Created: {snap1.snapshot_hash[:16]}... (Total: {snap1.summary.get('total_risks')})")

if __name__ == "__main__":
    main()
