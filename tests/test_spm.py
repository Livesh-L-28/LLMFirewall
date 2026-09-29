"""Comprehensive unit, integration, and scenario tests for Phase 35 — AI-SPM."""

import json
from pathlib import Path
import tempfile
import time
from typing import Any, Dict
import pytest

from llmfirewall.core.models import Severity
from llmfirewall.firewall import Firewall
from llmfirewall.graph import (
    KnowledgeGraph,
    Node,
    NodeType,
    Relationship,
    RelationshipType,
)
from llmfirewall.inventory import (
    Asset,
    AssetInventory,
    AssetSource,
    AssetStatus,
    AssetType,
)
from llmfirewall.spm import (
    AttackSurfaceRecord,
    ControlEffectiveness,
    ControlPostureRecord,
    ControlPresence,
    PostureDiff,
    PostureDimension,
    PostureEngine,
    PostureMetrics,
    PostureRule,
    PostureRuleContext,
    PostureRuleRegistry,
    PostureSnapshot,
    PostureState,
    SecurityGap,
    SecurityGapStatus,
    SecurityPosture,
    TestCoverageRecord,
    TestFreshness,
    format_posture_diff_human,
    format_posture_human,
    format_posture_json,
    format_posture_sarif,
    format_posture_summary_human,
    sanitize_posture_metadata,
)
from llmfirewall.cli.main import main


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------

@pytest.fixture
def empty_inventory():
    kg = KnowledgeGraph()
    inv = AssetInventory(kg=kg)
    return inv, kg


@pytest.fixture
def populated_inventory(empty_inventory):
    inv, kg = empty_inventory

    # Register assets
    agent = Asset(
        id="agent:customer-support",
        type=AssetType.AGENT,
        name="Customer Support Agent",
        environment="production",
        source=AssetSource.CONFIGURATION,
        metadata={"model": "gpt-4o", "department": "support"},
    )
    model = Asset(
        id="model:gpt-4o",
        type=AssetType.MODEL,
        name="GPT-4o",
        environment="production",
        source=AssetSource.CONFIGURATION,
    )
    tool_db = Asset(
        id="tool:customer_db",
        type=AssetType.TOOL,
        name="Customer DB Tool",
        environment="production",
        source=AssetSource.CONFIGURATION,
        metadata={"category": "database", "sensitivity": "high"},
    )
    rag_doc = Asset(
        id="rag_source:kb_docs",
        type=AssetType.RAG_SOURCE,
        name="KnowledgeBase RAG",
        environment="production",
        source=AssetSource.CONFIGURATION,
    )
    ctrl_auth = Asset(
        id="control:tool_authorizer",
        type=AssetType.SECURITY_CONTROL,
        name="Tool Authorization Guard",
        environment="production",
        source=AssetSource.CONFIGURATION,
    )

    for a in (agent, model, tool_db, rag_doc, ctrl_auth):
        inv.register(a)

    # Sync to KG
    kg.add_node(Node(id=agent.id, type=NodeType.AGENT.value, properties={"label": agent.name}))
    kg.add_node(Node(id=model.id, type=NodeType.MODEL.value, properties={"label": model.name}))
    kg.add_node(Node(id=tool_db.id, type=NodeType.TOOL.value, properties={"label": tool_db.name}))
    kg.add_node(Node(id=rag_doc.id, type=NodeType.RAG_SOURCE.value, properties={"label": rag_doc.name}))
    kg.add_node(Node(id=ctrl_auth.id, type=NodeType.SECURITY_CONTROL.value, properties={"label": ctrl_auth.name}))

    # Add edges
    kg.add_relationship(Relationship(source=agent.id, type=RelationshipType.USES.value, target=model.id))
    kg.add_relationship(Relationship(source=agent.id, type=RelationshipType.CAN_CALL.value, target=tool_db.id))
    kg.add_relationship(Relationship(source=agent.id, type=RelationshipType.CAN_ACCESS.value, target=rag_doc.id))
    kg.add_relationship(Relationship(source=ctrl_auth.id, type=RelationshipType.PROTECTS.value, target=tool_db.id))

    return inv, kg


# -----------------------------------------------------------------------------
# 1. Models & Sanitization Tests
# -----------------------------------------------------------------------------

def test_spm_secret_sanitization():
    """Verify recursive redaction of credentials and secrets from posture metadata."""
    dirty_data = {
        "api_key": "sk-proj-123456789012345678901234",
        "auth_token": "Bearer xyz123",
        "nested": {
            "password": "supersecretpassword123!",
            "public_field": "safe_value",
            "list_secrets": [
                "AKIAIOSFODNN7EXAMPLE",
                "normal text",
                {"credential": "secret_hash"},
            ],
        },
    }
    clean = sanitize_posture_metadata(dirty_data)
    assert clean["api_key"] == "[REDACTED_CREDENTIAL]"
    assert clean["auth_token"] == "[REDACTED_CREDENTIAL]"
    assert clean["nested"]["password"] == "[REDACTED_CREDENTIAL]"
    assert clean["nested"]["public_field"] == "safe_value"
    assert clean["nested"]["list_secrets"][0] == "[REDACTED_SECRET]"
    assert clean["nested"]["list_secrets"][1] == "normal text"
    assert clean["nested"]["list_secrets"][2]["credential"] == "[REDACTED_CREDENTIAL]"


def test_spm_metadata_size_limit():
    """Verify that oversized configuration metadata (>64KB) is rejected."""
    huge_cfg = {"oversized_dump": "X" * 70_000}
    with pytest.raises(ValueError, match="exceeds maximum size limit"):
        SecurityPosture(
            asset_id="agent:test",
            configuration=huge_cfg,
        )


def test_spm_deterministic_fingerprint():
    """Verify deterministic SHA-256 fingerprint generation for change detection."""
    p1 = SecurityPosture(
        asset_id="agent:test",
        state=PostureState.HEALTHY,
    )
    p2 = SecurityPosture(
        asset_id="agent:test",
        state=PostureState.HEALTHY,
    )
    assert p1.fingerprint != ""
    assert p1.fingerprint == p2.fingerprint

    # Modified state changes fingerprint
    p3 = SecurityPosture(
        asset_id="agent:test",
        state=PostureState.DEGRADED,
    )
    assert p1.fingerprint != p3.fingerprint


# -----------------------------------------------------------------------------
# 2. Rule Engine & Declarative Rules
# -----------------------------------------------------------------------------

def test_spm_rule_registry_versioning():
    """Verify rule registry registration, removal, versioning, and execution."""
    reg = PostureRuleRegistry()
    assert reg.rules_version == "1.0.0"
    init_count = len(reg.list_rules())
    assert init_count >= 10

    # Add custom declarative rule
    def custom_eval(ctx: PostureRuleContext):
        if ctx.asset_type == "test_asset":
            return [
                SecurityGap(
                    asset_id=ctx.asset_id,
                    dimension=PostureDimension.CONFIGURATION_SECURITY.value,
                    title="Custom Gap Detected",
                    description="Custom rule identified deficiency.",
                    severity=Severity.HIGH,
                )
            ]
        return []

    rule = PostureRule(
        rule_id="R-CUSTOM-001",
        name="Custom Test Rule",
        dimension=PostureDimension.CONFIGURATION_SECURITY,
        severity=Severity.HIGH,
        description="Flags test assets.",
        evaluator=custom_eval,
    )
    reg.register(rule)
    assert len(reg.list_rules()) == init_count + 1

    # Evaluate context
    ctx = PostureRuleContext(
        asset_id="test:1",
        asset_type="test_asset",
    )
    gaps = reg.evaluate(ctx)
    assert len(gaps) == 1
    assert gaps[0].title == "Custom Gap Detected"

    # Remove rule
    assert reg.remove("R-CUSTOM-001") is True
    assert len(reg.list_rules()) == init_count


# -----------------------------------------------------------------------------
# 3. Posture Engine Evaluation
# -----------------------------------------------------------------------------

def test_spm_evaluate_known_and_unknown_assets(populated_inventory):
    """Verify posture evaluation for indexed assets and graceful UNKNOWN for non-indexed."""
    inv, kg = populated_inventory
    engine = PostureEngine(inventory=inv, kg=kg)

    # 1. Non-indexed asset
    p_unindexed = engine.evaluate("agent:non_existent")
    assert p_unindexed.state == PostureState.UNKNOWN
    assert "not indexed" in p_unindexed.state_reason
    assert len(p_unindexed.unknowns) > 0

    # 2. Indexed asset
    p_agent = engine.evaluate("agent:customer-support")
    assert p_agent.asset_id == "agent:customer-support"
    assert p_agent.asset_name == "Customer Support Agent"
    assert p_agent.attack_surface.tools_count == 1
    assert "tool:customer_db" in p_agent.attack_surface.tools
    assert p_agent.attack_surface.rag_sources_count == 1
    assert "rag_source:kb_docs" in p_agent.attack_surface.rag_sources


def test_spm_evaluate_all_and_summary(populated_inventory):
    """Verify evaluate_all and summary statistics calculation."""
    inv, kg = populated_inventory
    engine = PostureEngine(inventory=inv, kg=kg)

    postures = engine.evaluate_all()
    assert len(postures) == len(inv.list_assets())
    assert "agent:customer-support" in postures
    assert "tool:customer_db" in postures

    summary = engine.summary()
    assert summary["assets_count"] == len(inv.list_assets())
    assert "posture_states" in summary
    assert "controls" in summary
    assert "findings" in summary
    assert "attack_paths" in summary
    assert "security_tests" in summary
    assert "security_gaps" in summary
    assert "unknown_areas_count" in summary


def test_spm_incremental_evaluation(populated_inventory):
    """Verify incremental evaluation only updates changed assets and downstream dependents."""
    inv, kg = populated_inventory
    engine = PostureEngine(inventory=inv, kg=kg)

    # Full eval first
    engine.evaluate_all()

    # Invalidate tool:customer_db (dependent agent:customer-support should re-evaluate)
    reevaluated = engine.incremental_evaluate(["tool:customer_db"])
    assert "tool:customer_db" in reevaluated
    assert "agent:customer-support" in reevaluated
    assert "model:gpt-4o" not in reevaluated


# -----------------------------------------------------------------------------
# 4. Snapshots & Diffing (Regressions and Improvements)
# -----------------------------------------------------------------------------

def test_spm_snapshot_hash_and_integrity(populated_inventory):
    """Verify canonical SHA-256 snapshot hashing and reproducible structure."""
    inv, kg = populated_inventory
    engine = PostureEngine(inventory=inv, kg=kg)

    snap = engine.snapshot(posture_version="1.0")
    assert snap.snapshot_hash != ""
    assert len(snap.snapshot_hash) == 64
    assert snap.rules_version == "1.0.0"
    assert len(snap.postures) == len(inv.list_assets())

    # Snapshot to JSON and re-parse
    dumped = snap.to_json()
    reparsed = PostureSnapshot.model_validate_json(dumped)
    assert reparsed.snapshot_hash == snap.snapshot_hash


def test_spm_diff_detects_regressions(populated_inventory):
    """Verify diff detects posture degradation, control removal, and stale tests."""
    inv, kg = populated_inventory
    engine = PostureEngine(inventory=inv, kg=kg)

    snap_before = engine.snapshot(posture_version="1.0")

    # Ingest failing test into agent
    engine.ingest_test_results("agent:customer-support", [
        {"test_id": "T-AUTH-001", "name": "Tool Auth Test", "passed": False, "details": "Bypass verified"}
    ])

    snap_after = engine.snapshot(posture_version="1.1")

    diff = PostureEngine.diff(snap_before, snap_after)
    assert diff.is_identical is False
    assert len(diff.posture_degraded) > 0 or len(diff.regressions) > 0


# -----------------------------------------------------------------------------
# 5. SARIF 2.1.0 Export & Formatters
# -----------------------------------------------------------------------------

def test_spm_sarif_export(populated_inventory):
    """Verify OASIS SARIF 2.1.0 output validity for actionable security gaps."""
    inv, kg = populated_inventory
    engine = PostureEngine(inventory=inv, kg=kg)

    sarif = engine.export_sarif()
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "LLMFirewall AI-SPM"
    assert isinstance(run["results"], list)


def test_spm_reporting_formatters(populated_inventory):
    """Verify human, JSON, and diff formatters execute without error."""
    inv, kg = populated_inventory
    engine = PostureEngine(inventory=inv, kg=kg)

    p = engine.evaluate("agent:customer-support")
    human_rep = format_posture_human(p)
    assert "AI Security Posture Report" in human_rep
    assert "Customer Support Agent" in human_rep
    assert "Controls" in human_rep
    assert "Attack Surface" in human_rep

    sum_rep = format_posture_summary_human(engine.summary())
    assert "AI Security Posture" in sum_rep
    assert "Assets:" in sum_rep

    json_rep = format_posture_json(p)
    assert json.loads(json_rep)["schema_version"] == "1.0.0"


# -----------------------------------------------------------------------------
# 6. Scenarios from Prompt (63 through 68)
# -----------------------------------------------------------------------------

def test_scenario_63_regression_when_control_removed(populated_inventory):
    """Scenario 63: Initial: Agent has tool authorization; Change: Authorization removed -> POSTURE_REGRESSION."""
    inv, kg = populated_inventory
    engine = PostureEngine(inventory=inv, kg=kg)

    snap1 = engine.snapshot(posture_version="1.0")

    # Remove protecting control edge
    kg.remove_relationship("control:tool_authorizer", "PROTECTS", "tool:customer_db")

    snap2 = engine.snapshot(posture_version="2.0")

    diff = PostureEngine.diff(snap1, snap2)
    assert any("removed" in r.lower() or "degraded" in r.lower() for r in diff.regressions + diff.controls_removed)


def test_scenario_64_unknown_state_when_evidence_absent(empty_inventory):
    """Scenario 64: Agent has tool, authorization evidence absent -> UNKNOWN, not SECURE and not automatically VULNERABLE."""
    inv, kg = empty_inventory
    agent = Asset(id="agent:bare", type=AssetType.AGENT, name="Bare Agent")
    tool = Asset(id="tool:raw", type=AssetType.TOOL, name="Raw Tool")
    inv.register(agent)
    inv.register(tool)
    kg.add_node(Node(id=agent.id, type=NodeType.AGENT.value))
    kg.add_node(Node(id=tool.id, type=NodeType.TOOL.value))
    kg.add_relationship(Relationship(source=agent.id, type=RelationshipType.CAN_CALL.value, target=tool.id))

    engine = PostureEngine(inventory=inv, kg=kg)
    posture = engine.evaluate(agent.id)

    # Must be UNKNOWN or ATTENTION_REQUIRED due to missing evidence, never HEALTHY
    assert posture.state in (PostureState.UNKNOWN, PostureState.ATTENTION_REQUIRED)
    # Evidence must state authorization is unknown
    assert any("tool" in u.lower() or "authorization" in u.lower() for u in posture.unknowns + [g.title for g in posture.security_gaps])


def test_scenario_65_stale_test_when_asset_modified(populated_inventory):
    """Scenario 65: Security test PASS -> Agent config changes -> TEST_STALE."""
    inv, kg = populated_inventory
    engine = PostureEngine(inventory=inv, kg=kg)

    # Ingest passing test
    engine.ingest_test_results("agent:customer-support", [
        {"test_id": "T-1", "name": "Basic Guard", "passed": True, "executed_at": time.time() - 100}
    ])
    p1 = engine.evaluate("agent:customer-support")
    assert p1.test_coverage.passed == 1
    assert p1.test_coverage.is_stale is False

    # Simulate asset modification AFTER test
    agent_asset = inv.get("agent:customer-support")
    inv.register(Asset(
        id=agent_asset.id,
        type=agent_asset.type,
        name=agent_asset.name,
        metadata={"model": "gpt-4o", "updated_param": "temperature=0.9"},
        last_seen=time.time() + 10,
    ))

    p2 = engine.evaluate("agent:customer-support")
    assert p2.test_coverage.is_stale is True
    assert p2.test_coverage.stale_reason is not None


def test_scenario_66_attack_path_candidate_not_automatic_vulnerability(populated_inventory):
    """Scenario 66: Candidate attack path exists -> candidate path, not confirmed vulnerability."""
    inv, kg = populated_inventory
    engine = PostureEngine(inventory=inv, kg=kg)

    posture = engine.evaluate("agent:customer-support")
    # No candidate path should be falsely promoted to confirmed finding without exploit evidence
    assert len(posture.findings.get("open", [])) == 0


def test_scenario_67_policy_conflict_detected(populated_inventory):
    """Scenario 67: Conflicting policies -> POLICY_CONFLICT generated without silent resolution."""
    inv, kg = populated_inventory
    engine = PostureEngine(inventory=inv, kg=kg)

    # Attach conflicting policy rules in engine context
    agent = inv.get("agent:customer-support")
    engine.evaluate(agent.id)

    ctx = PostureRuleContext(
        asset_id=agent.id,
        policy_status={
            "assigned_policies": [{"name": "PolicyA"}, {"name": "PolicyB"}],
            "conflicts": ["Policy A allows database tool, while Policy B denies database tool."],
        }
    )
    gaps = engine.rule_registry.evaluate(ctx)
    conflict_gaps = [g for g in gaps if "Policy Conflict" in g.title]
    assert len(conflict_gaps) == 1
    assert conflict_gaps[0].severity == Severity.HIGH


def test_scenario_68_secret_protection_in_exports(populated_inventory):
    """Scenario 68: Verify posture reports do not leak secrets or credentials."""
    inv, kg = populated_inventory
    agent = inv.get("agent:customer-support")
    # Add dirty metadata
    agent_with_secret = Asset(
        id=agent.id,
        type=agent.type,
        name=agent.name,
        metadata={"api_key": "sk-live-09876543210987654321", "password": "supersecretpassword"},
    )
    inv.register(agent_with_secret)

    engine = PostureEngine(inventory=inv, kg=kg)
    posture = engine.evaluate(agent.id)
    json_out = format_posture_json(posture)

    assert "sk-live-" not in json_out
    assert "supersecretpassword" not in json_out
    assert "[REDACTED_CREDENTIAL]" in json_out or "[REDACTED_SECRET]" in json_out


# -----------------------------------------------------------------------------
# 7. Telemetry & Audit
# -----------------------------------------------------------------------------

def test_spm_telemetry_metrics(populated_inventory):
    """Verify bounded telemetry counters increment properly."""
    inv, kg = populated_inventory
    metrics = PostureMetrics()
    engine = PostureEngine(inventory=inv, kg=kg, metrics=metrics)

    engine.evaluate("agent:customer-support")
    engine.snapshot()

    stats = metrics.get_metrics()
    assert stats["posture_evaluations_total"] >= 1
    assert stats["posture_snapshots_total"] >= 1


# -----------------------------------------------------------------------------
# 8. CLI Commands Verification
# -----------------------------------------------------------------------------

def test_spm_cli_commands():
    """Verify CLI commands for posture summary, show, snapshot, diff, and export."""
    # Summary
    assert main(["posture", "summary"]) == 0

    # Summary JSON
    assert main(["posture", "summary", "--json"]) == 0

    # Show application asset
    assert main(["posture", "application:firewall"]) == 0

    # Snapshot to file and diff
    with tempfile.TemporaryDirectory() as td:
        snap1_file = Path(td) / "snap1.json"
        snap2_file = Path(td) / "snap2.json"
        sarif_file = Path(td) / "posture.sarif"

        assert main(["posture", "snapshot", "--output", str(snap1_file)]) == 0
        assert snap1_file.exists()

        assert main(["posture", "snapshot", "--output", str(snap2_file)]) == 0
        assert snap2_file.exists()

        # Diff
        assert main(["posture", "diff", "--before", str(snap1_file), "--after", str(snap2_file)]) == 0

        # Export SARIF
        assert main(["posture", "export", "--format", "sarif", "--output", str(sarif_file)]) == 0
        assert sarif_file.exists()
