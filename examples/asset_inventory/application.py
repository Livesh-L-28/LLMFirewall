"""Example: Customer Support AI Asset Inventory & Continuous Discovery (Phase 34).

Demonstrates:
1. Multi-source automated discovery (Config, Dependencies, Code, Runtime).
2. Asset normalization, canonical identities, and deterministic SHA-256 fingerprints.
3. Multi-source deduplication and provenance merging.
4. Drift and conflict tracking (e.g. configured vs runtime observed versions).
5. Automatic Phase 32 Knowledge Graph synchronization.
6. Phase 33 Security Exposure & Attack Surface analysis.
7. Baseline snapshots and architectural diffing.
"""

import json
import time
from pathlib import Path

from llmfirewall import (
    Asset,
    AssetConflict,
    AssetInventory,
    AssetProvenance,
    AssetSource,
    AssetStatus,
    AssetType,
    AttackGraph,
    CodeDiscoveryProvider,
    ConfigDiscoveryProvider,
    DependencyDiscoveryProvider,
    EnvironmentDiscoveryProvider,
    Firewall,
    FirewallConfig,
    KnowledgeGraph,
    RuntimeDiscoveryProvider,
    format_asset_show_human,
    format_discovery_result_human,
    format_inventory_diff_human,
    format_inventory_list_human,
)


def run_customer_support_inventory_demo() -> None:
    print("=" * 80)
    print("  LLMFirewall Phase 34: Customer Support AI Asset Inventory & Discovery")
    print("=" * 80)

    # 1. Initialize KnowledgeGraph & AttackGraph
    kg = KnowledgeGraph()
    ag = AttackGraph(kg=kg)
    inv = AssetInventory(kg=kg, attack_graph=ag)

    print("\n[Step 1] Initializing Customer Support AI Assets...")
    # Application Orchestrator
    inv.register(Asset(
        id="application:customer_support_app",
        type=AssetType.APPLICATION.value,
        name="Customer Support Portal",
        version="2.4.0",
        environment="production",
        source=AssetSource.CONFIGURATION,
        tags=["core", "perimeter", "customer_facing"],
    ))

    # Support Agent
    inv.register(Asset(
        id="agent:support_agent",
        type=AssetType.AGENT.value,
        name="Support Conversational Agent",
        version="1.0.0",
        environment="production",
        source=AssetSource.CONFIGURATION,
        metadata={
            "model": "gpt-4o",
            "tools": ["database_tool", "crm_lookup"],
            "rag_source": "rag_source:kb_articles",
        },
        tags=["agent", "autonomous", "tier1"],
        provenance=[
            AssetProvenance(
                source=AssetSource.CONFIGURATION,
                provider_name="config_discovery",
                reference="agents.yaml:line_15",
            )
        ],
    ))

    # Model & Provider
    inv.register(Asset(
        id="model:gpt-4o",
        type=AssetType.MODEL.value,
        name="GPT-4o Omnimodal",
        version="2024-08-06",
        environment="production",
        source=AssetSource.CONFIGURATION,
        metadata={"provider": "openai", "max_context": 128000},
    ))
    inv.register(Asset(
        id="provider:openai",
        type=AssetType.MODEL_PROVIDER.value,
        name="OpenAI Platform",
        source=AssetSource.ENVIRONMENT,
        metadata={"configured": True, "region": "us-east-1"},
    ))

    # Callable Tools
    inv.register(Asset(
        id="tool:database_tool",
        type=AssetType.TOOL.value,
        name="Customer Orders Database",
        environment="production",
        source=AssetSource.CONFIGURATION,
        metadata={"category": "database", "endpoint": "internal://db.support.local"},
        tags=["database", "sensitive"],
    ))
    inv.register(Asset(
        id="tool:crm_lookup",
        type=AssetType.TOOL.value,
        name="Zendesk CRM Lookup",
        environment="production",
        source=AssetSource.CONFIGURATION,
        metadata={"category": "api", "auth_mode": "oauth2"},
        tags=["crm", "external_api"],
    ))

    # RAG Pipeline & Vector Store
    inv.register(Asset(
        id="rag_source:kb_articles",
        type=AssetType.RAG_SOURCE.value,
        name="KnowledgeBase RAG Pipeline",
        source=AssetSource.CONFIGURATION,
        metadata={"vector_store": "vector_store:pinecone_docs"},
    ))
    inv.register(Asset(
        id="vector_store:pinecone_docs",
        type=AssetType.VECTOR_STORE.value,
        name="Pinecone Support Index",
        source=AssetSource.CONFIGURATION,
        metadata={"dimension": 1536, "metric": "cosine"},
    ))

    # Security Controls
    inv.register(Asset(
        id="security_control:prompt_firewall",
        type=AssetType.SECURITY_CONTROL.value,
        name="LLMFirewall Prompt Guardrail",
        source=AssetSource.CONFIGURATION,
        metadata={"mode": "blocking", "categories": ["injection", "pii"]},
    ))

    print(f"Registered {len(inv)} architectural AI assets.")

    # 2. Multi-Source Discovery & Deduplication
    print("\n[Step 2] Observing Dynamic Runtime Telemetry & Merging Provenance...")
    runtime_prov = RuntimeDiscoveryProvider()
    # Telemetry event: Agent invoked model and tools, but observed newer version 1.1.0
    runtime_prov.observe_event({
        "event_type": "agent_execution",
        "agent": "support_agent",
        "model": "gpt-4o",
        "tools": ["database_tool"],
        "timestamp": time.time(),
    })
    # Another event observes runtime version update
    inv.register(Asset(
        id="agent:support_agent",
        type=AssetType.AGENT.value,
        name="Support Conversational Agent",
        version="1.1.0",  # Version discrepancy with config (1.0.0 vs 1.1.0)
        source=AssetSource.RUNTIME,
        metadata={"observed_runtime_latency_ms": 142.5},
        provenance=[
            AssetProvenance(
                source=AssetSource.RUNTIME,
                provider_name="runtime_discovery",
                reference="metrics:session_8819",
            )
        ],
    ))

    support_agent = inv.get("agent:support_agent")
    print(f"Asset: {support_agent.id}")
    print(f"  Provenance Sources: {[p.source.value for p in support_agent.provenance]}")
    print(f"  Discrepancy / Conflicts Detected: {len(support_agent.conflicts)}")
    if support_agent.conflicts:
        c = support_agent.conflicts[0]
        print(f"    - Field '{c.field}': Configured={c.configured_value} vs Observed={c.observed_value}")

    # 3. Synchronize to Knowledge Graph & Link Relationships
    print("\n[Step 3] Synchronizing Inventory to Phase 32 Security Knowledge Graph...")
    inv.sync_to_graph()
    # Add defensive protection edge: Prompt Firewall PROTECTS Agent
    kg.add_relationship("security_control:prompt_firewall", "PROTECTS", "agent:support_agent")

    print(f"Knowledge Graph populated: {kg.store.node_count()} nodes, {kg.store.relationship_count()} edges.")

    # 4. Phase 33 Security Exposure Analysis
    print("\n[Step 4] Querying Security Exposure & Attack Surface for 'agent:support_agent'...")
    exposure = inv.attack_surface("agent:support_agent")
    print(format_asset_show_human(support_agent, exposure))

    # 5. Snapshots & Baseline Drift
    print("\n[Step 5] Capturing Baseline Snapshot & Detecting Architectural Drift...")
    baseline_snap = inv.snapshot(inventory_version="1.0-baseline")
    print(f"Baseline Snapshot: hash={baseline_snap.snapshot_hash[:16]}... ({baseline_snap.assets_count} assets)")

    # Simulate architectural change: Decommissioning database tool, adding new refund tool
    inv.remove("tool:database_tool", reason="Migrated to secure API")
    inv.register(Asset(
        id="tool:refund_api",
        type=AssetType.TOOL.value,
        name="Stripe Refund API Tool",
        environment="production",
        source=AssetSource.CONFIGURATION,
        metadata={"category": "finance", "capabilities": ["payment:refund"]},
    ))
    current_snap = inv.snapshot(inventory_version="1.1-release")

    diff = AssetInventory.diff(baseline_snap, current_snap)
    print("\n" + format_inventory_diff_human(diff))

    # 6. Export Baseline
    out_path = Path("examples/asset_inventory/inventory_export.json")
    inv.export_to_file(str(out_path), format_type="json")
    print(f"\n[Step 6] Exported validated inventory snapshot to: {out_path}")
    print("\nDemo completed successfully.")


if __name__ == "__main__":
    run_customer_support_inventory_demo()
