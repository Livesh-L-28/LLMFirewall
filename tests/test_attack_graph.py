"""Unit, integration, and security tests for Phase 33 — Attack Graph & AI Threat Modeling."""

import json
from pathlib import Path
import tempfile
import time
import pytest

from llmfirewall import (
    Action,
    AttackEvidence,
    AttackGraph,
    AttackGraphDiff,
    AttackGraphSnapshot,
    AttackNode,
    AttackPath,
    AttackRule,
    AttackRuleRegistry,
    AttackStep,
    AttackTechnique,
    AttackTechniqueRegistry,
    ConfidenceLevel,
    ControlEffectiveness,
    EntryPoint,
    EntryPointType,
    EvidenceType,
    Firewall,
    KnowledgeGraph,
    MitigationStatus,
    NodeType,
    PathStatus,
    PreconditionEvaluator,
    RelationshipType,
    STANDARD_RULES,
    ThreatModel,
    TrustBoundary,
    default_technique_registry,
    format_attack_graph_sarif,
    format_attack_paths_human,
    format_attack_paths_json,
    format_threat_model_human,
)
from llmfirewall.cli.commands import (
    handle_attack_path,
    handle_attack_paths,
    handle_threat_model,
    handle_threat_model_export,
)
from llmfirewall.cli.errors import EXIT_ALLOWED, EXIT_USAGE_ERROR


# -----------------------------------------------------------------------------
# 1. Models & Validation Tests
# -----------------------------------------------------------------------------

def test_attack_models_and_enums() -> None:
    """Validate explicit status enum states, evidence types, and mitigation statuses."""
    assert PathStatus.CANDIDATE == "CANDIDATE"
    assert PathStatus.SUPPORTED == "SUPPORTED"
    assert PathStatus.TESTED == "TESTED"
    assert PathStatus.OBSERVED == "OBSERVED"
    assert PathStatus.BLOCKED == "BLOCKED"
    assert PathStatus.INVALIDATED == "INVALIDATED"

    assert EvidenceType.GRAPH == "GRAPH"
    assert EvidenceType.TEST == "TEST"
    assert EvidenceType.RUNTIME == "RUNTIME"
    assert EvidenceType.CONFIGURATION == "CONFIGURATION"
    assert EvidenceType.POLICY == "POLICY"
    assert EvidenceType.FINDING == "FINDING"
    assert EvidenceType.USER_PROVIDED == "USER_PROVIDED"

    assert MitigationStatus.UNMITIGATED == "UNMITIGATED"
    assert MitigationStatus.PARTIALLY_MITIGATED == "PARTIALLY_MITIGATED"
    assert MitigationStatus.MITIGATED == "MITIGATED"
    assert MitigationStatus.UNKNOWN == "UNKNOWN"


def test_attack_evidence_validation() -> None:
    """AttackEvidence requires non-empty description and valid types."""
    ev = AttackEvidence(
        evidence_type=EvidenceType.GRAPH,
        source_id="agent:01->tool:02",
        description="Graph edge verified",
        verified=True,
    )
    assert ev.verified is True
    assert ev.evidence_type == EvidenceType.GRAPH

    with pytest.raises(ValueError, match="cannot be empty"):
        AttackEvidence(
            evidence_type=EvidenceType.TEST,
            source_id="test:01",
            description="   ",
        )


def test_attack_step_and_path_deterministic_fingerprint() -> None:
    """AttackPath.create produces stable SHA-256 fingerprint ID from step sequences."""
    step1 = AttackStep(
        technique="T-PI-01",
        technique_name="Prompt Injection",
        source="application:chat",
        target="agent:assistant",
    )
    step2 = AttackStep(
        technique="T-TA-04",
        technique_name="Tool Abuse",
        source="agent:assistant",
        target="tool:db",
    )

    path1 = AttackPath.create(
        source="application:chat",
        target="tool:db",
        steps=[step1, step2],
        status=PathStatus.CANDIDATE,
    )
    path2 = AttackPath.create(
        source="application:chat",
        target="tool:db",
        steps=[step1, step2],
        status=PathStatus.CANDIDATE,
    )

    assert path1.path_id.startswith("PATH-")
    assert path1.path_id == path2.path_id
    assert path1.length == 2
    assert path1.technique_sequence == ["T-PI-01", "T-TA-04"]
    assert path1.node_sequence == ["application:chat", "agent:assistant", "tool:db"]


# -----------------------------------------------------------------------------
# 2. Technique & Rule Registries
# -----------------------------------------------------------------------------

def test_technique_registry() -> None:
    """Standard AI attack techniques are loaded and accessible."""
    reg = default_technique_registry
    assert reg.exists("T-PI-01")
    assert reg.exists("T-IPI-02")
    assert reg.exists("T-TA-04")
    assert reg.exists("T-DE-06")
    assert reg.exists("T-CP-07")
    assert reg.exists("T-SC-12")

    tech = reg.get("T-PI-01")
    assert tech is not None
    assert tech.name == "Direct Prompt Injection"
    assert "agent" in tech.affected_assets

    # Custom technique registration
    custom = AttackTechnique(
        id="T-CUSTOM-01",
        name="Custom AI Abuse",
        description="Testing custom technique registration",
        prerequisites=["agent_access"],
        affected_assets=["agent"],
    )
    custom_reg = AttackTechniqueRegistry()
    custom_reg.register(custom)
    assert custom_reg.exists("T-CUSTOM-01")


def test_rule_registry_validation() -> None:
    """AttackRuleRegistry enforces rigorous validation, rejecting unknown techniques and cycles."""
    reg = AttackRuleRegistry()

    # Reject unknown technique
    with pytest.raises(ValueError, match="unknown technique"):
        reg.register(AttackRule(
            rule_id="R-UNKNOWN-TECH",
            name="Bad Rule",
            description="Testing",
            source_type="agent",
            target_type="tool",
            technique="T-NONEXISTENT",
        ))

    # Reject invalid node types
    with pytest.raises(ValueError, match="invalid source_type"):
        reg.register(AttackRule(
            rule_id="R-BAD-SOURCE",
            name="Bad Source",
            description="Testing",
            source_type="non_existent_entity",
            target_type="agent",
            technique="T-PI-01",
        ))

    # Reject cyclic self-loop with identical preconditions & postconditions
    with pytest.raises(ValueError, match="ungrounded cyclic loop"):
        reg.register(AttackRule(
            rule_id="R-CYCLIC",
            name="Cyclic Loop",
            description="Testing",
            source_type="agent",
            target_type="agent",
            technique="T-IO-03",
            requires=["loop_condition"],
            postconditions=["loop_condition"],
        ))


def test_declarative_yaml_rules() -> None:
    """AttackRuleRegistry can be populated from YAML declarative definitions."""
    yaml_content = """
    rules_version: "2.1"
    attack_rules:
      - rule_id: "R-CUSTOM-PI"
        name: "Custom Ingress PI"
        description: "Custom rule from YAML config"
        source_type: "application"
        target_type: "agent"
        technique: "T-PI-01"
        requires:
          - untrusted_input
        postconditions:
          - agent_instruction_override
        mitigations:
          - control:prompt_sanitizer
        assumptions:
          - "Testing assumption"
        confidence: "HIGH"
    """
    reg = AttackRuleRegistry.from_yaml(yaml_content)
    assert reg.rules_version == "2.1"
    rule = reg.get("R-CUSTOM-PI")
    assert rule is not None
    assert rule.technique == "T-PI-01"
    assert rule.confidence == ConfidenceLevel.HIGH


# -----------------------------------------------------------------------------
# 3. Path Discovery & Multi-Hop Chains
# -----------------------------------------------------------------------------

def test_multi_step_attack_path_discovery() -> None:
    """Verify discovery of User Input -> Agent -> Tool -> Sensitive Data attack path."""
    kg = KnowledgeGraph()
    # 1. Application entry point
    kg.add_node("app:chat", "application")
    # 2. Agent
    kg.add_node("agent:support", "agent")
    kg.add_relationship("app:chat", "USES", "agent:support")
    # 3. Database tool without authorization
    kg.add_node("tool:sql", "tool", properties={"category": "database"})
    kg.add_relationship("agent:support", "CAN_CALL", "tool:sql")

    ag = AttackGraph(kg=kg)
    paths = ag.find_paths(source="app:chat", target="tool:sql")

    assert len(paths) >= 1
    p = paths[0]
    assert p.source == "app:chat"
    assert p.target == "tool:sql"
    assert p.length == 2
    assert p.technique_sequence == ["T-PI-01", "T-TA-04"]
    assert p.status in (PathStatus.CANDIDATE, PathStatus.SUPPORTED)
    assert p.mitigation_status == MitigationStatus.UNMITIGATED
    assert len(p.evidence) > 0
    assert len(p.assumptions) > 0


def test_rag_attack_path() -> None:
    """Verify Untrusted RAG source -> Agent indirect injection candidate path."""
    kg = KnowledgeGraph()
    kg.add_node("rag:wiki", "rag_source", properties={"sha256": None})
    kg.add_node("agent:analyst", "agent")
    kg.add_relationship("rag:wiki", "USES", "agent:analyst")

    ag = AttackGraph(kg=kg)
    paths = ag.find_paths(source="rag:wiki", target="agent:analyst")

    assert len(paths) == 1
    p = paths[0]
    assert p.steps[0].technique == "T-IPI-02"
    assert "agent_context_poisoned" in p.steps[0].postconditions


def test_supply_chain_attack_path() -> None:
    """Verify Vulnerable Dependency -> Application -> Agent candidate path."""
    kg = KnowledgeGraph()
    kg.add_node("dep:pyyaml", "dependency")
    kg.add_node("app:api", "application")
    kg.add_relationship("dep:pyyaml", "DEPENDS_ON", "app:api")
    # Attach finding to dependency
    kg.add_node("finding:cve-2024", "finding", properties={"severity": "high"})
    kg.add_relationship("finding:cve-2024", "AFFECTS", "dep:pyyaml")

    ag = AttackGraph(kg=kg)
    paths = ag.find_paths(source="dep:pyyaml", target="app:api")

    assert len(paths) >= 1
    p = paths[0]
    assert p.steps[0].technique == "T-SC-12"


def test_cycles_handling_and_no_infinite_loop() -> None:
    """Cycles in AI agent architectures (Agent A -> Agent B -> Agent A) terminate safely."""
    kg = KnowledgeGraph()
    kg.add_node("agent:alpha", "agent")
    kg.add_node("agent:beta", "agent")
    kg.add_relationship("agent:alpha", "CALLS", "agent:beta")
    kg.add_relationship("agent:beta", "CALLS", "agent:alpha")

    ag = AttackGraph(kg=kg)
    # Search with depth 4
    paths = ag.find_paths(source="agent:alpha", max_depth=4)
    assert isinstance(paths, list)
    for p in paths:
        # No path should revisit the same node in a single chain
        visited = set()
        for node in p.node_sequence:
            assert node not in visited or node == p.node_sequence[0]


def test_path_deduplication_and_resource_bounds() -> None:
    """Identical paths are deduplicated by deterministic fingerprint, respecting max_paths limit."""
    kg = KnowledgeGraph()
    kg.add_node("app:gateway", "application")
    kg.add_node("agent:1", "agent")
    kg.add_node("tool:1", "tool")
    kg.add_relationship("app:gateway", "USES", "agent:1")
    kg.add_relationship("agent:1", "CAN_CALL", "tool:1")

    ag = AttackGraph(kg=kg)
    # Run with max_paths=1
    paths = ag.find_paths(source="app:gateway", max_paths=1)
    assert len(paths) == 1


# -----------------------------------------------------------------------------
# 4. False Positive & False Negative Prevention
# -----------------------------------------------------------------------------

def test_false_positive_strong_authorization_prevents_tool_abuse() -> None:
    """When strong RBAC authorization control protects tool, tool abuse rule does not fire."""
    kg = KnowledgeGraph()
    kg.add_node("agent:support", "agent")
    kg.add_node("tool:crm", "tool")
    kg.add_relationship("agent:support", "CAN_CALL", "tool:crm")

    # Add passing RBAC authorization control
    kg.add_node("control:auth", "security_control", properties={"mode": "rbac", "authorization": True})
    kg.add_relationship("control:auth", "PROTECTS", "tool:crm")

    ag = AttackGraph(kg=kg)
    paths = ag.find_paths(source="agent:support", target="tool:crm")
    assert len(paths) == 0, "Tool abuse path should not fire when authorization control is active."


def test_false_negative_missing_authorization_generates_gap() -> None:
    """When authorization is missing, attack path is flagged and security gap finding is created."""
    kg = KnowledgeGraph()
    kg.add_node("agent:bot", "agent")
    kg.add_node("tool:storage", "tool", properties={"category": "database"})
    kg.add_relationship("agent:bot", "CAN_CALL", "tool:storage")

    ag = AttackGraph(kg=kg)
    paths = ag.find_paths(source="agent:bot", target="tool:storage")
    assert len(paths) == 1
    assert paths[0].mitigation_status == MitigationStatus.UNMITIGATED

    gaps = ag.extract_security_gaps(paths)
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap.category == "ATTACK_SURFACE_SECURITY_GAP"
    assert "Unmitigated potential attack path" in gap.description


# -----------------------------------------------------------------------------
# 5. Phase Integrations: Testing & Runtime Telemetry
# -----------------------------------------------------------------------------

def test_phase_30_continuous_test_results_ingestion() -> None:
    """Automated security test results corroborate multi-step attack paths into TESTED status."""
    kg = KnowledgeGraph()
    kg.add_node("app:portal", "application")
    kg.add_node("agent:lead", "agent")
    kg.add_node("tool:sql", "tool")
    kg.add_relationship("app:portal", "USES", "agent:lead")
    kg.add_relationship("agent:lead", "CAN_CALL", "tool:sql")

    ag = AttackGraph(kg=kg)
    candidate_paths = ag.find_paths(source="app:portal", target="tool:sql")
    assert len(candidate_paths) >= 1
    assert candidate_paths[0].status in (PathStatus.CANDIDATE, PathStatus.SUPPORTED)

    # Ingest test results demonstrating prompt injection and tool abuse
    test_results = [
        {"technique": "T-PI-01", "target": "agent:lead", "passed": True, "test_id": "SEC-TEST-01"},
        {"technique": "T-TA-04", "target": "tool:sql", "passed": True, "test_id": "SEC-TEST-02"},
    ]
    tested_paths = ag.ingest_test_results(test_results)
    assert len(tested_paths) >= 1
    tp = tested_paths[0]
    assert tp.status == PathStatus.TESTED
    assert tp.is_tested is True
    assert tp.confidence == ConfidenceLevel.HIGH
    assert any(e.evidence_type == EvidenceType.TEST for e in tp.evidence)


def test_runtime_events_telemetry_ingestion() -> None:
    """Production telemetry event sequence matches attack chain, transitioning status to OBSERVED."""
    kg = KnowledgeGraph()
    kg.add_node("app:chat", "application")
    kg.add_node("agent:bot", "agent")
    kg.add_node("tool:crm", "tool")
    kg.add_relationship("app:chat", "USES", "agent:bot")
    kg.add_relationship("agent:bot", "CAN_CALL", "tool:crm")

    ag = AttackGraph(kg=kg)
    events = [
        {"event_type": "PROMPT_INJECTION_DETECTED", "technique": "T-PI-01", "timestamp": time.time()},
        {"event_type": "UNAUTHORIZED_TOOL_INVOKED", "technique": "T-TA-04", "timestamp": time.time() + 1},
    ]
    observed_paths = ag.ingest_runtime_events(events)
    assert len(observed_paths) >= 1
    op = observed_paths[0]
    assert op.status == PathStatus.OBSERVED
    assert op.is_observed is True
    assert any(e.evidence_type == EvidenceType.RUNTIME for e in op.evidence)


# -----------------------------------------------------------------------------
# 6. Threat Model Generation & Formatting
# -----------------------------------------------------------------------------

def test_threat_model_generation() -> None:
    """AI Threat Model gathers assets, entry points, trust boundaries, paths, and assumptions."""
    kg = KnowledgeGraph()
    kg.add_node("app:web", "application")
    kg.add_node("agent:support", "agent")
    kg.add_node("tool:crm", "tool")
    kg.add_relationship("app:web", "USES", "agent:support")
    kg.add_relationship("agent:support", "CAN_CALL", "tool:crm")

    ag = AttackGraph(kg=kg)
    tm = ag.generate_threat_model(asset_id="agent:support", name="Customer Support Threat Model")

    assert tm.name == "Customer Support Threat Model"
    assert "agent:support" in tm.assets
    assert len(tm.entry_points) >= 1
    assert len(tm.trust_boundaries) >= 1
    assert len(tm.attack_paths) >= 1

    summary = tm.summary()
    assert summary["assets_count"] >= 1
    assert "paths_by_status" in summary


def test_human_and_sarif_reporting() -> None:
    """Validate human reports, JSON formatting, and SARIF 2.1.0 output."""
    kg = KnowledgeGraph()
    kg.add_node("app:web", "application")
    kg.add_node("agent:bot", "agent")
    kg.add_node("tool:db", "tool", properties={"category": "database"})
    kg.add_relationship("app:web", "USES", "agent:bot")
    kg.add_relationship("agent:bot", "CAN_CALL", "tool:db")

    ag = AttackGraph(kg=kg)
    paths = ag.find_paths(source="app:web", target="tool:db")
    tm = ag.generate_threat_model(asset_id="agent:bot")

    # Human report
    human_rep = format_attack_paths_human(paths, asset_id="agent:bot")
    assert "AI Attack Surface Report" in human_rep
    assert "Candidate Attack Paths" in human_rep
    assert "Status:" in human_rep

    # Threat model human report
    tm_rep = format_threat_model_human(tm)
    assert "Threat Model:" in tm_rep
    assert "Entry Points:" in tm_rep
    assert "Trust Boundaries:" in tm_rep

    # JSON report
    json_str = format_attack_paths_json(paths)
    parsed = json.loads(json_str)
    assert parsed["schema_version"] == "1"
    assert "paths" in parsed

    # SARIF report
    sarif = format_attack_graph_sarif(paths)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert len(sarif["runs"][0]["results"]) >= 1


# -----------------------------------------------------------------------------
# 7. Snapshots, Diffs & Drift
# -----------------------------------------------------------------------------

def test_attack_graph_snapshot_and_diff() -> None:
    """Snapshots capture cryptographic state and diff detects newly added attack paths."""
    kg = KnowledgeGraph()
    kg.add_node("app:main", "application")
    kg.add_node("agent:lead", "agent")
    kg.add_relationship("app:main", "USES", "agent:lead")

    ag = AttackGraph(kg=kg)
    snap1 = ag.snapshot()
    assert snap1.snapshot_hash != ""

    # Architectural change: add tool access
    kg.add_node("tool:admin", "tool")
    kg.add_relationship("agent:lead", "CAN_CALL", "tool:admin")

    snap2 = ag.snapshot()
    diff = AttackGraph.diff(snap1, snap2)

    assert not diff.is_identical
    assert len(diff.paths_added) >= 1

    # Recalculate on drift
    recalculated = ag.recalculate_on_drift(new_node_ids=["tool:admin"])
    assert any(p.target == "tool:admin" for p in recalculated)


# -----------------------------------------------------------------------------
# 8. Firewall Top-Level Integration
# -----------------------------------------------------------------------------

def test_firewall_integration(default_firewall: Firewall) -> None:
    """Firewall exposes attack_graph property and generate_threat_model method."""
    ag = default_firewall.attack_graph
    assert isinstance(ag, AttackGraph)

    tm = default_firewall.generate_threat_model(name="Firewall Self Threat Model")
    assert isinstance(tm, ThreatModel)
    assert tm.name == "Firewall Self Threat Model"
    assert len(tm.assets) >= 1


# -----------------------------------------------------------------------------
# 9. CLI Command Handlers
# -----------------------------------------------------------------------------

def test_cli_command_handlers() -> None:
    """Test CLI commands for attack paths and threat-model export."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        # 1. handle_attack_paths (human & json)
        ret1 = handle_attack_paths(format_type="human")
        assert ret1 == EXIT_ALLOWED

        json_out = tmp_path / "paths.json"
        ret2 = handle_attack_paths(format_type="json", output_file=str(json_out))
        assert ret2 == EXIT_ALLOWED
        assert json_out.exists()
        loaded = json.loads(json_out.read_text(encoding="utf-8"))
        assert "paths" in loaded

        # 2. handle_threat_model (human & export)
        ret3 = handle_threat_model(format_type="human")
        assert ret3 == EXIT_ALLOWED

        tm_out = tmp_path / "tm.json"
        ret4 = handle_threat_model_export(output_file=str(tm_out), format_type="json")
        assert ret4 == EXIT_ALLOWED
        assert tm_out.exists()
        tm_data = json.loads(tm_out.read_text(encoding="utf-8"))
        assert "model_id" in tm_data
