"""Comprehensive Unit, Integration, Security, and Regression tests for Phase 34 — AI Asset Inventory & Discovery."""

import json
import os
import tempfile
import time
from pathlib import Path
import pytest

from llmfirewall import (
    Firewall,
    FirewallConfig,
    AuditConfig,
    KnowledgeGraph,
    AttackGraph,
    Asset,
    AssetConflict,
    AssetExposure,
    AssetInventory,
    AssetProvenance,
    AssetSource,
    AssetStatus,
    AssetType,
    CodeDiscoveryProvider,
    ConfigDiscoveryProvider,
    DependencyDiscoveryProvider,
    DiscoveryConfidence,
    DiscoveryEngine,
    DiscoveryProvider,
    DiscoveryResult,
    DiscoveryStatus,
    EnvironmentDiscoveryProvider,
    ImportDiscoveryProvider,
    InventoryDiff,
    InventoryMetrics,
    InventorySnapshot,
    ManualDiscoveryProvider,
    RuntimeDiscoveryProvider,
    format_asset_show_human,
    format_discovery_result_human,
    format_discovery_result_json,
    format_inventory_diff_human,
    format_inventory_json,
    format_inventory_list_human,
    normalize_asset_id,
    sanitize_metadata_secrets,
)
from llmfirewall.cli.commands import (
    handle_inventory_diff,
    handle_inventory_discover,
    handle_inventory_export,
    handle_inventory_list,
    handle_inventory_show,
)
from llmfirewall.cli.errors import EXIT_ALLOWED, EXIT_USAGE_ERROR


# -----------------------------------------------------------------------------
# 1. Models & Validation Tests
# -----------------------------------------------------------------------------

def test_asset_enums_and_types() -> None:
    """Verify standard asset enums and extensible types."""
    assert AssetType.APPLICATION.value == "application"
    assert AssetType.AGENT.value == "agent"
    assert AssetType.MODEL.value == "model"
    assert AssetType.MODEL_PROVIDER.value == "model_provider"
    assert AssetType.TOOL.value == "tool"
    assert AssetType.RAG_SOURCE.value == "rag_source"
    assert AssetType.VECTOR_STORE.value == "vector_store"
    assert AssetType.DEPENDENCY.value == "dependency"
    assert AssetType.PACKAGE.value == "package"
    assert AssetType.POLICY.value == "policy"
    assert AssetType.SECURITY_CONTROL.value == "security_control"

    assert AssetStatus.ACTIVE.value == "ACTIVE"
    assert AssetStatus.STALE.value == "STALE"
    assert AssetStatus.REMOVED.value == "REMOVED"
    assert AssetStatus.UNKNOWN.value == "UNKNOWN"

    assert AssetSource.CONFIGURATION.value == "CONFIGURATION"
    assert AssetSource.RUNTIME.value == "RUNTIME"
    assert AssetSource.DEPENDENCY_MANIFEST.value == "DEPENDENCY_MANIFEST"


def test_asset_creation_and_deterministic_fingerprint() -> None:
    """Test asset creation, validation, and deterministic fingerprint generation."""
    asset1 = Asset(
        id="agent:support",
        type=AssetType.AGENT.value,
        name="Support Agent",
        version="1.0.0",
        environment="production",
        source=AssetSource.CONFIGURATION,
        metadata={"model": "gpt-4o", "tools": ["search", "db"]},
    )

    asset2 = Asset(
        id="agent:support",
        type=AssetType.AGENT.value,
        name="Support Agent",
        version="1.0.0",
        environment="production",
        source=AssetSource.CONFIGURATION,
        metadata={"tools": ["search", "db"], "model": "gpt-4o"},
    )

    # Identical content in different key orders must produce identical fingerprints
    assert asset1.fingerprint == asset2.fingerprint
    assert len(asset1.fingerprint) == 64  # SHA-256 hex digest

    # Different version produces different fingerprint
    asset3 = Asset(
        id="agent:support",
        type=AssetType.AGENT.value,
        name="Support Agent",
        version="1.0.1",
        environment="production",
        source=AssetSource.CONFIGURATION,
    )
    assert asset1.fingerprint != asset3.fingerprint


def test_secret_scrubbing_in_asset_metadata() -> None:
    """Verify that credentials and sensitive secrets are automatically sanitized."""
    metadata = {
        "api_key": "sk-proj-1234567890abcdef1234567890abcdef",
        "nested": {
            "token": "ghp_abcdefghijklmnopqrstuvwxyz123456",
            "safe_val": "hello world",
            "password": "supersecretpassword",
        },
        "safe_list": [1, 2, "normal_string"],
    }

    sanitized = sanitize_metadata_secrets(metadata)
    assert sanitized["api_key"] == "[REDACTED_CREDENTIAL]"
    assert sanitized["nested"]["token"] == "[REDACTED_CREDENTIAL]"
    assert sanitized["nested"]["password"] == "[REDACTED_CREDENTIAL]"
    assert sanitized["nested"]["safe_val"] == "hello world"
    assert sanitized["safe_list"] == [1, 2, "normal_string"]

    # Creation of Asset must sanitize metadata automatically
    asset = Asset(
        id="model:gpt-4o",
        type="model",
        name="GPT-4o",
        metadata=metadata,
    )
    assert asset.metadata["api_key"] == "[REDACTED_CREDENTIAL]"
    assert asset.metadata["nested"]["token"] == "[REDACTED_CREDENTIAL]"


def test_oversized_metadata_rejection() -> None:
    """Verify that assets with metadata exceeding 64KB are rejected to prevent DoS."""
    huge_data = {"key": "x" * 70_000}
    with pytest.raises(ValueError, match="Asset metadata exceeds maximum size limit"):
        Asset(
            id="agent:huge",
            type="agent",
            name="Huge Agent",
            metadata=huge_data,
        )


# -----------------------------------------------------------------------------
# 2. Discovery Providers Tests
# -----------------------------------------------------------------------------

def test_config_discovery_provider() -> None:
    """Verify discovery from FirewallConfig, PolicyEngine, and Detectors."""
    cfg = FirewallConfig(audit=AuditConfig(enabled=False))
    fw = Firewall(config=cfg)

    provider = ConfigDiscoveryProvider(firewall=fw)
    assets = provider.discover()

    assert len(assets) >= 4
    asset_ids = {a.id for a in assets}
    assert "application:firewall" in asset_ids
    assert "policy:default_ai_security_policy" in asset_ids
    assert any("prompt_injection" in a_id for a_id in asset_ids)
    assert any("pii" in a_id for a_id in asset_ids)

    app = next(a for a in assets if a.id == "application:firewall")
    assert app.type == AssetType.APPLICATION.value
    assert app.source == AssetSource.CONFIGURATION
    assert len(app.provenance) == 1
    assert app.provenance[0].reference == "llmfirewall.config"


def test_environment_discovery_provider() -> None:
    """Verify environment discovery detects provider presence without storing raw keys."""
    os.environ["OPENAI_API_KEY"] = "sk-fake-secret-key-12345"
    os.environ["ANTHROPIC_API_KEY"] = "ant-fake-secret-key-67890"

    try:
        provider = EnvironmentDiscoveryProvider()
        assets = provider.discover()

        assert len(assets) == 2
        provider_ids = {a.id for a in assets}
        assert "provider:openai" in provider_ids
        assert "provider:anthropic" in provider_ids

        for a in assets:
            assert a.type == AssetType.MODEL_PROVIDER.value
            assert a.source == AssetSource.ENVIRONMENT
            # CRITICAL SECURITY CHECK: Raw key must NEVER appear anywhere in asset
            assert "sk-fake-secret-key-12345" not in json.dumps(a.to_dict())
            assert "ant-fake-secret-key-67890" not in json.dumps(a.to_dict())
            assert a.metadata.get("configured") is True
    finally:
        os.environ.pop("OPENAI_API_KEY", None)
        os.environ.pop("ANTHROPIC_API_KEY", None)


def test_dependency_discovery_provider() -> None:
    """Verify dependency discovery scans installed Python packages safely offline."""
    provider = DependencyDiscoveryProvider(max_packages=20)
    assets = provider.discover()

    assert len(assets) > 0
    for a in assets:
        assert a.type == AssetType.PACKAGE.value
        assert a.source == AssetSource.DEPENDENCY_MANIFEST
        assert a.version is not None
        assert a.provenance[0].provider_name == "dependency_discovery"


def test_code_discovery_provider() -> None:
    """Verify static code AST scanning discovers AI SDK calls without executing code."""
    sample_code = """
import openai
from anthropic import Anthropic
from transformers import AutoModelForCausalLM
from fastapi import FastAPI

client = openai.OpenAI(model="gpt-4o")
claude = Anthropic(model="claude-3-opus")
hf_model = AutoModelForCausalLM.from_pretrained("meta-llama/Llama-3-8B")
app = FastAPI()
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        py_file = Path(tmpdir) / "app.py"
        py_file.write_text(sample_code, encoding="utf-8")

        # Also write a file with syntax error to ensure resilience
        bad_file = Path(tmpdir) / "invalid.py"
        bad_file.write_text("def broken syntax : (", encoding="utf-8")

        provider = CodeDiscoveryProvider(root_dir=tmpdir)
        assets = provider.discover()

        asset_ids = {a.id for a in assets}
        assert "model:gpt-4o" in asset_ids
        assert "model:claude-3-opus" in asset_ids
        assert "api:fastapi_app" in asset_ids

        for a in assets:
            assert a.source == AssetSource.CODE
            assert a.confidence == DiscoveryConfidence.MEDIUM


def test_import_discovery_provider() -> None:
    """Verify importing assets from JSON/YAML with strict schema validation."""
    valid_doc = {
        "schema_version": "1.0.0",
        "assets": [
            {
                "id": "agent:customer_support",
                "type": "agent",
                "name": "Customer Support Agent",
                "version": "2.1.0",
                "environment": "production",
                "metadata": {"model": "gpt-4o"},
            },
            {
                "id": "model:gpt-4o",
                "type": "model",
                "name": "GPT-4o",
                "environment": "production",
            },
        ],
    }

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump(valid_doc, tf)
        tmp_path = tf.name

    try:
        provider = ImportDiscoveryProvider(file_path=tmp_path)
        assets = provider.discover()
        assert len(assets) == 2
        assert assets[0].id == "agent:customer_support"
        assert assets[0].source == AssetSource.USER_REGISTERED
    finally:
        os.unlink(tmp_path)


def test_import_discovery_rejection_of_oversized_file() -> None:
    """Verify import rejects files larger than 10MB to prevent memory exhaustion."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        # Write large file
        tf.write('{"assets": []}' + " " * (10 * 1024 * 1024 + 10))
        tmp_path = tf.name

    try:
        provider = ImportDiscoveryProvider(file_path=tmp_path)
        with pytest.raises(ValueError, match="exceeds maximum size limit"):
            provider.discover()
    finally:
        os.unlink(tmp_path)


def test_runtime_discovery_provider() -> None:
    """Verify runtime discovery observes emitted telemetry events and discovers assets."""
    provider = RuntimeDiscoveryProvider()
    provider.observe_event({
        "event_type": "agent_invocation",
        "agent": "support_agent",
        "model": "gpt-4o",
        "tools": ["database_tool", "web_search"],
    })
    provider.observe_event({
        "event_type": "tool_execution",
        "tool": "calculator",
        "endpoint": "http://internal:8000/calc",
    })

    assets = provider.discover()
    assert len(assets) >= 4
    asset_ids = {a.id for a in assets}
    assert "agent:support_agent" in asset_ids
    assert "model:gpt-4o" in asset_ids
    assert "tool:database_tool" in asset_ids
    assert "tool:calculator" in asset_ids

    for a in assets:
        assert a.source == AssetSource.RUNTIME


# -----------------------------------------------------------------------------
# 3. Deduplication, Normalization & Conflict Resolution Tests
# -----------------------------------------------------------------------------

def test_asset_id_normalization() -> None:
    """Verify consistent canonical ID normalization."""
    assert normalize_asset_id("agent", "Support Agent") == "agent:support_agent"
    assert normalize_asset_id("tool", "Database-Query Tool!") == "tool:database-query_tool"
    assert normalize_asset_id("model", "gpt-4o") == "model:gpt-4o"
    assert normalize_asset_id("model", "model:gpt-4o") == "model:gpt-4o"


def test_asset_deduplication_and_provenance_merging() -> None:
    """Verify that multiple discoveries of the same asset merge cleanly preserving provenance."""
    inv = AssetInventory()

    # Source 1: Config
    a1 = Asset(
        id="agent:support",
        type="agent",
        name="Support Agent",
        version="1.0.0",
        source=AssetSource.CONFIGURATION,
        provenance=[
            AssetProvenance(
                source=AssetSource.CONFIGURATION,
                provider_name="config_discovery",
                reference="config.yaml",
            )
        ],
        metadata={"timeout": 30},
        tags=["core"],
    )

    # Source 2: Runtime
    a2 = Asset(
        id="agent:support",
        type="agent",
        name="Support Agent",
        version="1.0.0",
        source=AssetSource.RUNTIME,
        provenance=[
            AssetProvenance(
                source=AssetSource.RUNTIME,
                provider_name="runtime_discovery",
                reference="events.log",
            )
        ],
        metadata={"invocations": 150},
        tags=["active"],
    )

    inv.register(a1)
    inv.register(a2)

    # Deduplicated to 1 asset
    assert len(inv) == 1
    asset = inv.get("agent:support")
    assert asset is not None
    assert asset.name == "Support Agent"
    assert asset.version == "1.0.0"

    # Both provenance records preserved
    assert len(asset.provenance) == 2
    prov_sources = {p.source for p in asset.provenance}
    assert AssetSource.CONFIGURATION in prov_sources
    assert AssetSource.RUNTIME in prov_sources

    # Metadata and tags merged
    assert asset.metadata["timeout"] == 30
    assert asset.metadata["invocations"] == 150
    assert set(asset.tags) == {"core", "active"}


def test_conflict_detection_on_version_mismatch() -> None:
    """Verify that version discrepancies between sources record conflicts for drift detection."""
    inv = AssetInventory()

    a1 = Asset(
        id="model:llama",
        type="model",
        name="Llama",
        version="3.1",
        source=AssetSource.CONFIGURATION,
        metadata={"context": 8192},
    )

    a2 = Asset(
        id="model:llama",
        type="model",
        name="Llama",
        version="3.2",
        source=AssetSource.RUNTIME,
        metadata={"context": 16384},
    )

    inv.register(a1)
    inv.register(a2)

    asset = inv.get("model:llama")
    assert asset is not None
    assert len(asset.conflicts) == 1
    conflict = asset.conflicts[0]
    assert conflict.field == "version"
    assert conflict.configured_value == "3.1"
    assert conflict.observed_value == "3.2"


def test_stale_asset_lifecycle() -> None:
    """Verify active assets transition to STALE when not observed within threshold."""
    inv = AssetInventory()

    a = Asset(
        id="tool:deprecated_calc",
        type="tool",
        name="Calculator",
        last_seen=time.time() - 500,  # 500 seconds ago
    )
    inv.register(a)

    stale_count = inv.mark_stale_assets(stale_threshold_seconds=300)
    assert len(stale_count) == 1
    assert inv.get("tool:deprecated_calc").status == AssetStatus.STALE

    # Re-observing revitalizes the asset to ACTIVE
    a_fresh = Asset(
        id="tool:deprecated_calc",
        type="tool",
        name="Calculator",
        last_seen=time.time(),
    )
    inv.register(a_fresh)
    assert inv.get("tool:deprecated_calc").status == AssetStatus.ACTIVE


def test_asset_removal() -> None:
    """Verify soft asset removal sets status to REMOVED."""
    inv = AssetInventory()
    a = Asset(id="agent:decommissioned", type="agent", name="Old Agent")
    inv.register(a)

    res = inv.remove("agent:decommissioned")
    assert res is True
    assert inv.get("agent:decommissioned").status == AssetStatus.REMOVED


# -----------------------------------------------------------------------------
# 4. Fault Isolation & Discovery Engine Tests
# -----------------------------------------------------------------------------

class FaultyProvider(DiscoveryProvider):
    """Mock discovery provider that raises an exception to test fault isolation."""

    @property
    def name(self) -> str:
        return "faulty_provider"

    def discover(self) -> list[Asset]:
        raise RuntimeError("Provider connection dropped or crashed!")


class SuccessfulProvider(DiscoveryProvider):
    """Mock discovery provider that succeeds."""

    @property
    def name(self) -> str:
        return "successful_provider"

    def discover(self) -> list[Asset]:
        return [
            Asset(id="tool:math", type="tool", name="Math Tool", source=AssetSource.PLUGIN)
        ]


def test_discovery_failure_isolation() -> None:
    """CRITICAL: If one provider fails, the discovery engine must complete with PARTIAL status."""
    engine = DiscoveryEngine()
    engine.register_provider(SuccessfulProvider())
    engine.register_provider(FaultyProvider())

    res = engine.run_all()

    assert res.status == DiscoveryStatus.PARTIAL
    assert res.assets_discovered == 1
    assert len(res.warnings) == 1
    assert "Provider 'faulty_provider' failed" in res.warnings[0]
    assert res.provider_statuses["successful_provider"] == "success"
    assert res.provider_statuses["faulty_provider"] == "failed"


# -----------------------------------------------------------------------------
# 5. Knowledge Graph & Attack Graph Integration Tests
# -----------------------------------------------------------------------------

def test_sync_to_knowledge_graph() -> None:
    """Verify that discovered inventory assets populate Phase 32 KnowledgeGraph nodes and edges."""
    kg = KnowledgeGraph()
    inv = AssetInventory(kg=kg)

    # Register agent, model, and tool
    inv.register(Asset(
        id="agent:assistant",
        type=AssetType.AGENT.value,
        name="Assistant Agent",
        metadata={"model": "gpt-4o", "tools": ["database_tool"]},
    ))
    inv.register(Asset(
        id="model:gpt-4o",
        type=AssetType.MODEL.value,
        name="GPT-4o",
        metadata={"provider": "openai"},
    ))
    inv.register(Asset(
        id="provider:openai",
        type=AssetType.MODEL_PROVIDER.value,
        name="OpenAI Provider",
    ))
    inv.register(Asset(
        id="tool:database_tool",
        type=AssetType.TOOL.value,
        name="Database Tool",
    ))

    # Synchronize to graph
    inv.sync_to_graph()

    # Verify nodes created
    assert kg.get_node("agent:assistant") is not None
    assert kg.get_node("model:gpt-4o") is not None
    assert kg.get_node("tool:database_tool") is not None
    assert kg.get_node("provider:openai") is not None

    # Verify inferred relationships
    agent_rels = kg.find_relationships(source="agent:assistant")
    targets = {r.target for r in agent_rels}
    assert "model:gpt-4o" in targets
    assert "tool:database_tool" in targets

    model_rels = kg.find_relationships(source="model:gpt-4o")
    m_targets = {r.target for r in model_rels}
    assert "provider:openai" in m_targets


def test_asset_attack_surface_integration() -> None:
    """Verify that inventory.attack_surface queries Phase 32 & 33 graph exposure."""
    kg = KnowledgeGraph()
    ag = AttackGraph(kg=kg)
    inv = AssetInventory(kg=kg, attack_graph=ag)

    # Add agent, tool, and control
    inv.register(Asset(id="agent:search_agent", type="agent", name="Search Agent", metadata={"tools": ["web_search"]}))
    inv.register(Asset(id="tool:web_search", type="tool", name="Web Search Tool"))
    inv.register(Asset(id="security_control:prompt_firewall", type="security_control", name="Prompt Firewall"))
    inv.sync_to_graph()

    # Link security control protecting agent
    kg.add_relationship("security_control:prompt_firewall", "PROTECTS", "agent:search_agent")

    exposure = inv.attack_surface("agent:search_agent")
    assert isinstance(exposure, AssetExposure)
    assert exposure.asset_id == "agent:search_agent"
    assert "tool:web_search" in exposure.accessible_tools
    assert "security_control:prompt_firewall" in exposure.protecting_controls


# -----------------------------------------------------------------------------
# 6. Snapshot & Diffing Tests
# -----------------------------------------------------------------------------

def test_inventory_snapshot_and_diff() -> None:
    """Verify inventory snapshot creation and architectural drift detection."""
    inv = AssetInventory()

    inv.register(Asset(id="agent:bot", type="agent", name="Bot v1", version="1.0.0"))
    inv.register(Asset(id="tool:calculator", type="tool", name="Calculator"))

    snap1 = inv.snapshot()
    assert snap1.assets_count == 2
    assert len(snap1.graph_hash) == 64

    # Make changes: remove tool:calculator, update agent:bot, add model:gpt-4o
    inv.remove("tool:calculator")
    inv.register(Asset(id="agent:bot", type="agent", name="Bot v2", version="2.0.0"))
    inv.register(Asset(id="model:gpt-4o", type="model", name="GPT-4o"))

    snap2 = inv.snapshot()
    assert snap2.assets_count == 3

    # Diff
    diff = AssetInventory.diff(snap1, snap2)
    assert isinstance(diff, InventoryDiff)
    assert "model:gpt-4o" in diff.added_assets
    assert "tool:calculator" in diff.removed_assets
    assert "agent:bot" in diff.changed_assets


# -----------------------------------------------------------------------------
# 7. CLI Handlers Tests
# -----------------------------------------------------------------------------

def test_cli_inventory_handlers() -> None:
    """Verify all Phase 34 CLI handlers execute cleanly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        export_json = Path(tmpdir) / "inventory.json"
        before_json = Path(tmpdir) / "before.json"
        after_json = Path(tmpdir) / "after.json"

        # 1. Discover
        ret_disc = handle_inventory_discover(format_type="json")
        assert ret_disc == EXIT_ALLOWED

        # 2. List
        ret_list = handle_inventory_list(format_type="human")
        assert ret_list == EXIT_ALLOWED

        # 3. Export
        ret_exp = handle_inventory_export(output_file=str(export_json), format_type="json")
        assert ret_exp == EXIT_ALLOWED
        assert export_json.exists()

        # 4. Show
        ret_show = handle_inventory_show(
            asset_id="application:firewall",
            inventory_file=str(export_json),
            format_type="json",
        )
        assert ret_show == EXIT_ALLOWED

        # 5. Diff
        before_snap = InventorySnapshot(
            schema_version="1.0.0",
            inventory_version="1.0.0",
            created_at=time.time(),
            assets_count=1,
            assets=[{"id": "agent:bot", "type": "agent", "name": "Bot"}],
            sources=["CONFIGURATION"],
            graph_hash="0" * 64,
        )
        before_json.write_text(before_snap.model_dump_json(), encoding="utf-8")

        after_snap = InventorySnapshot(
            schema_version="1.0.0",
            inventory_version="1.0.0",
            created_at=time.time(),
            assets_count=2,
            assets=[
                {"id": "agent:bot", "type": "agent", "name": "Bot"},
                {"id": "tool:db", "type": "tool", "name": "Database"},
            ],
            sources=["CONFIGURATION"],
            graph_hash="1" * 64,
        )
        after_json.write_text(after_snap.model_dump_json(), encoding="utf-8")

        ret_diff = handle_inventory_diff(
            before_file=str(before_json),
            after_file=str(after_json),
            format_type="human",
        )
        assert ret_diff == EXIT_ALLOWED
