"""Comprehensive test suite for Phase 32 — AI Security Knowledge Graph."""

import json
import os
import tempfile
import threading
from pathlib import Path
import pytest

from llmfirewall.graph.models import (
    NodeType,
    RelationshipType,
    Node,
    Relationship,
    ControlStatus,
    GraphPath,
    GraphSnapshot,
    GraphDiff,
    SecurityDiff,
)
from llmfirewall.graph.stores import InMemoryGraphStore, SQLiteGraphStore
from llmfirewall.graph.engine import KnowledgeGraph
from llmfirewall.graph.reporting import (
    format_impact_human,
    format_blast_radius_human,
    format_coverage_human,
    format_graph_diff_human,
    format_node_show_human,
    format_path_human,
)
from llmfirewall.firewall import Firewall


@pytest.fixture
def empty_graph() -> KnowledgeGraph:
    """Provide an empty in-memory knowledge graph."""
    return KnowledgeGraph()


@pytest.fixture
def populated_graph() -> KnowledgeGraph:
    """Provide a populated AI security knowledge graph."""
    kg = KnowledgeGraph()
    # Nodes
    kg.add_node("app:chat", node_type="application", properties={"env": "prod"})
    kg.add_node("agent:triage", node_type="agent", properties={"role": "assistant"})
    kg.add_node("model:gpt-4o", node_type="model", properties={"provider": "openai"})
    kg.add_node("tool:web_search", node_type="tool", properties={"category": "network"})
    kg.add_node("tool:database", node_type="tool", properties={"category": "storage"})
    kg.add_node("policy:strict_ai", node_type="policy", properties={"version": "1.2"})
    kg.add_node("control:injection_guard", node_type="security_control", properties={"mode": "block"})
    kg.add_node("control:auth_filter", node_type="security_control", properties={"mode": "rbac"})
    kg.add_node("test:pi_eval_01", node_type="security_test", properties={"status": "passing"})
    kg.add_node("finding:vuln_01", node_type="finding", properties={"severity": "high", "rule_id": "SEC-01"})
    kg.add_node("threat:prompt_injection", node_type="threat", properties={"cwe": "CWE-1426"})
    kg.add_node("dep:cryptography", node_type="dependency", properties={"version": "42.0.0"})

    # Relationships
    kg.add_relationship("app:chat", "USES", "agent:triage")
    kg.add_relationship("agent:triage", "USES", "model:gpt-4o")
    kg.add_relationship("agent:triage", "CAN_CALL", "tool:web_search")
    kg.add_relationship("agent:triage", "CAN_CALL", "tool:database")
    kg.add_relationship("agent:triage", "GOVERNED_BY", "policy:strict_ai")
    kg.add_relationship("control:injection_guard", "PROTECTS", "agent:triage")
    kg.add_relationship("control:auth_filter", "PROTECTS", "tool:database")
    kg.add_relationship("test:pi_eval_01", "TESTS", "control:injection_guard")
    kg.add_relationship("finding:vuln_01", "AFFECTS", "agent:triage")
    kg.add_relationship("finding:vuln_01", "MITIGATED_BY", "control:injection_guard")
    kg.add_relationship("control:injection_guard", "MITIGATES", "threat:prompt_injection")
    kg.add_relationship("app:chat", "DEPENDS_ON", "dep:cryptography")
    return kg


class TestNodeManagement:
    """Test node CRUD, deduplication, and identity stability."""

    def test_add_and_get_node(self, empty_graph: KnowledgeGraph):
        node = empty_graph.add_node("agent:triage", node_type=NodeType.AGENT, properties={"version": "1.0"})
        assert node.id == "agent:triage"
        assert node.type == "agent"
        assert node.properties["version"] == "1.0"

        fetched = empty_graph.get_node("agent:triage")
        assert fetched is not None
        assert fetched.id == "agent:triage"

    def test_node_deduplication(self, empty_graph: KnowledgeGraph):
        """Adding the same node twice updates properties without duplicating the logical node."""
        n1 = empty_graph.add_node("agent:triage", node_type="agent", properties={"role": "support"})
        assert empty_graph.store.node_count() == 1

        n2 = empty_graph.add_node("agent:triage", node_type="agent", properties={"role": "lead", "team": "sec"})
        assert empty_graph.store.node_count() == 1
        assert n2.properties["role"] == "lead"
        assert n2.properties["team"] == "sec"

    def test_invalid_node_type_rejected(self, empty_graph: KnowledgeGraph):
        with pytest.raises(ValueError, match="Invalid node type"):
            empty_graph.add_node("x:1", node_type="unregistered_type")

    def test_custom_node_type_registration(self, empty_graph: KnowledgeGraph):
        empty_graph.register_node_type("custom_sensor")
        node = empty_graph.add_node("sensor:01", node_type="custom_sensor")
        assert node.type == "custom_sensor"

    def test_node_removal_and_cascade(self, populated_graph: KnowledgeGraph):
        """Removing a node removes its incident relationships to prevent dangling edges."""
        assert populated_graph.get_node("agent:triage") is not None
        assert populated_graph.store.get_in_edges("agent:triage")
        assert populated_graph.store.get_out_edges("agent:triage")

        removed = populated_graph.remove_node("agent:triage", cascade=True)
        assert removed is True
        assert populated_graph.get_node("agent:triage") is None
        assert len(populated_graph.store.get_in_edges("agent:triage")) == 0
        assert len(populated_graph.store.get_out_edges("agent:triage")) == 0

    def test_find_nodes(self, populated_graph: KnowledgeGraph):
        tools = populated_graph.find_nodes(type="tool")
        assert len(tools) == 2
        tool_ids = {t.id for t in tools}
        assert "tool:web_search" in tool_ids
        assert "tool:database" in tool_ids


class TestRelationshipManagement:
    """Test relationship CRUD, deduplication, and edge integrity."""

    def test_add_and_get_relationship(self, empty_graph: KnowledgeGraph):
        empty_graph.add_node("agent:1", "agent")
        empty_graph.add_node("model:1", "model")

        rel = empty_graph.add_relationship("agent:1", RelationshipType.USES, "model:1")
        assert rel.source == "agent:1"
        assert rel.type == "USES"
        assert rel.target == "model:1"

        fetched = empty_graph.get_relationship("agent:1", "USES", "model:1")
        assert fetched is not None
        assert fetched.source == "agent:1"

    def test_relationship_deduplication(self, empty_graph: KnowledgeGraph):
        """Repeatedly adding the same directed relationship does not duplicate edges."""
        empty_graph.add_node("agent:1", "agent")
        empty_graph.add_node("model:1", "model")

        empty_graph.add_relationship("agent:1", "USES", "model:1", properties={"weight": 1})
        assert empty_graph.store.relationship_count() == 1

        empty_graph.add_relationship("agent:1", "USES", "model:1", properties={"weight": 2})
        assert empty_graph.store.relationship_count() == 1
        rel = empty_graph.get_relationship("agent:1", "USES", "model:1")
        assert rel.properties["weight"] == 2

    def test_relationship_endpoints_must_exist(self, empty_graph: KnowledgeGraph):
        empty_graph.add_node("agent:1", "agent")
        with pytest.raises(KeyError, match="Target node .* does not exist"):
            empty_graph.add_relationship("agent:1", "USES", "model:missing")

        with pytest.raises(KeyError, match="Source node .* does not exist"):
            empty_graph.add_relationship("agent:missing", "USES", "agent:1")

    def test_invalid_relationship_type_rejected(self, empty_graph: KnowledgeGraph):
        empty_graph.add_node("a:1", "agent")
        empty_graph.add_node("m:1", "model")
        with pytest.raises(ValueError, match="Invalid relationship type"):
            empty_graph.add_relationship("a:1", "UNKNOWN_VERB", "m:1")

    def test_custom_relationship_type_registration(self, empty_graph: KnowledgeGraph):
        empty_graph.register_relationship_type("DELEGATES_TO")
        empty_graph.add_node("a:1", "agent")
        empty_graph.add_node("a:2", "agent")
        rel = empty_graph.add_relationship("a:1", "DELEGATES_TO", "a:2")
        assert rel.type == "DELEGATES_TO"

    def test_remove_relationship(self, populated_graph: KnowledgeGraph):
        assert populated_graph.get_relationship("agent:triage", "CAN_CALL", "tool:web_search") is not None
        res = populated_graph.remove_relationship("agent:triage", "CAN_CALL", "tool:web_search")
        assert res is True
        assert populated_graph.get_relationship("agent:triage", "CAN_CALL", "tool:web_search") is None


class TestGraphTraversalAndPaths:
    """Test BFS/DFS path search, cycle protection, and bounded traversal."""

    def test_find_shortest_path(self, populated_graph: KnowledgeGraph):
        # app:chat -> agent:triage -> tool:database
        path = populated_graph.find_path("app:chat", "tool:database")
        assert path is not None
        assert path.source == "app:chat"
        assert path.target == "tool:database"
        assert path.length == 2
        assert path.nodes == ["app:chat", "agent:triage", "tool:database"]

    def test_find_all_paths_bounded(self, populated_graph: KnowledgeGraph):
        paths = populated_graph.find_paths("app:chat", "model:gpt-4o", max_depth=3)
        assert len(paths) >= 1
        assert paths[0].nodes == ["app:chat", "agent:triage", "model:gpt-4o"]

    def test_cycle_termination(self, empty_graph: KnowledgeGraph):
        """Cyclic graph must terminate without recursion errors or infinite loops."""
        empty_graph.add_node("n:a", "agent")
        empty_graph.add_node("n:b", "tool")
        empty_graph.add_node("n:c", "policy")

        # Cycle: a -> b -> c -> a
        empty_graph.add_relationship("n:a", "CAN_CALL", "n:b")
        empty_graph.add_relationship("n:b", "GOVERNED_BY", "n:c")
        empty_graph.add_relationship("n:c", "GOVERNS", "n:a")

        # Search for non-existent node from within cycle
        path = empty_graph.find_path("n:a", "n:nonexistent", max_depth=5)
        assert path is None

        # Reachability within cycle
        path = empty_graph.find_path("n:a", "n:c", max_depth=5)
        assert path is not None
        assert path.nodes == ["n:a", "n:b", "n:c"]

    def test_max_depth_enforcement(self, empty_graph: KnowledgeGraph):
        for i in range(10):
            empty_graph.add_node(f"node:{i}", "agent")
        for i in range(9):
            empty_graph.add_relationship(f"node:{i}", "PRECEDES", f"node:{i+1}")

        # Depth 3 should NOT reach node:5 (requires depth 5)
        path = empty_graph.find_path("node:0", "node:5", max_depth=3)
        assert path is None

        # Depth 6 should reach node:5
        path = empty_graph.find_path("node:0", "node:5", max_depth=6)
        assert path is not None
        assert path.length == 5


class TestSecurityImpactAndAnalysis:
    """Test security impact, blast radius, change impact, and evidence-based control coverage."""

    def test_security_impact(self, populated_graph: KnowledgeGraph):
        impact = populated_graph.security_impact("agent:triage")
        assert impact.asset_id == "agent:triage"
        assert impact.asset_type == "agent"
        assert "control:injection_guard" in impact.controls
        assert "policy:strict_ai" in impact.policies
        assert "finding:vuln_01" in impact.findings
        assert "threat:prompt_injection" in impact.threats
        assert "dep:cryptography" in impact.dependencies

    def test_blast_radius(self, populated_graph: KnowledgeGraph):
        blast = populated_graph.blast_radius("agent:triage")
        assert blast.source_id == "agent:triage"
        assert blast.total_reached >= 4
        # Downstream reachable assets from agent:triage:
        assert "model:gpt-4o" in blast.reachable_assets
        assert "tool:web_search" in blast.reachable_assets
        assert "tool:database" in blast.reachable_assets
        assert "policy:strict_ai" in blast.governing_policies

    def test_change_impact(self, populated_graph: KnowledgeGraph):
        # Changing model:gpt-4o affects agent:triage and app:chat
        impact = populated_graph.change_impact("model:gpt-4o")
        assert impact.changed_node == "model:gpt-4o"
        assert "agent:triage" in impact.affected_assets
        assert "app:chat" in impact.affected_assets
        assert "test:pi_eval_01" in impact.required_tests

    def test_policy_impact(self, populated_graph: KnowledgeGraph):
        p_impact = populated_graph.policy_impact("policy:strict_ai")
        assert p_impact.policy_id == "policy:strict_ai"
        assert "agent:triage" in p_impact.affected_agents
        assert "control:injection_guard" in p_impact.security_controls

    def test_finding_impact(self, populated_graph: KnowledgeGraph):
        f_impact = populated_graph.finding_impact("finding:vuln_01")
        assert f_impact.finding_id == "finding:vuln_01"
        assert "agent:triage" in f_impact.affected_assets
        assert "control:injection_guard" in f_impact.mitigating_controls

    def test_control_coverage_no_fake_coverage(self, populated_graph: KnowledgeGraph):
        """Verifies evidence-based control coverage (distinguishing tested vs configured)."""
        cov = populated_graph.control_coverage("agent:triage")
        assert cov.asset_id == "agent:triage"
        assert len(cov.controls) >= 1

        guard_item = next(c for c in cov.controls if c.control_id == "control:injection_guard")
        # Injection guard has test:pi_eval_01 passing, so status should be PASSING
        assert guard_item.status == ControlStatus.PASSING
        assert guard_item.evidence_test == "test:pi_eval_01"

        # Now test an untested control
        populated_graph.add_node("control:untested_sanitizer", "security_control")
        populated_graph.add_relationship("control:untested_sanitizer", "PROTECTS", "agent:triage")

        cov2 = populated_graph.control_coverage("agent:triage")
        untested_item = next(c for c in cov2.controls if c.control_id == "control:untested_sanitizer")
        assert untested_item.status == ControlStatus.CONFIGURED


class TestGraphSnapshotsAndDiff:
    """Test serialization, canonical hashing, and security-aware diffing."""

    def test_snapshot_and_deterministic_hashing(self, populated_graph: KnowledgeGraph):
        snap1 = populated_graph.snapshot()
        assert snap1.schema_version == "1.0.0"
        assert snap1.graph_hash is not None
        assert snap1.node_count == populated_graph.store.node_count()

        # Build duplicate graph with elements added in reverse order
        kg_rev = KnowledgeGraph()
        for node in reversed(populated_graph.find_nodes()):
            kg_rev.add_node(node.id, node.type, properties=node.properties)
        for rel in reversed(populated_graph.find_relationships()):
            kg_rev.add_relationship(rel.source, rel.type, rel.target, properties=rel.properties)

        snap2 = kg_rev.snapshot()
        # Canonical hash must be identical regardless of insertion order
        assert snap1.graph_hash == snap2.graph_hash

    def test_graph_diff_and_security_diff(self, populated_graph: KnowledgeGraph):
        snap_a = populated_graph.snapshot()

        # Mutate graph
        populated_graph.add_node("tool:dangerous_shell", "tool")
        populated_graph.add_relationship("agent:triage", "CAN_CALL", "tool:dangerous_shell")
        populated_graph.remove_node("control:auth_filter")

        snap_b = populated_graph.snapshot()

        diff = populated_graph.diff(snap_a, snap_b)
        assert len(diff.nodes_added) == 1
        assert diff.nodes_added[0] == "tool:dangerous_shell"
        assert len(diff.nodes_removed) == 1
        assert diff.nodes_removed[0] == "control:auth_filter"

        # Security-specific diff
        sec_diff = populated_graph.security_diff(snap_a, snap_b)
        assert "tool:dangerous_shell" in sec_diff.new_tool_ids
        assert "control:auth_filter" in sec_diff.removed_controls


class TestImportExportAndSecuritySanitization:
    """Test JSON import/export, DoS protection, and secret rejection."""

    def test_export_and_import_cycle(self, populated_graph: KnowledgeGraph):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            tf_path = tf.name

        try:
            populated_graph.export_to_file(tf_path)
            assert os.path.exists(tf_path)

            new_kg = KnowledgeGraph()
            count = new_kg.import_from_file(tf_path)
            assert count == populated_graph.store.node_count()
            assert new_kg.store.relationship_count() == populated_graph.store.relationship_count()

            # Hash verification
            assert populated_graph.snapshot().graph_hash == new_kg.snapshot().graph_hash
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_secret_scrubbing_in_properties(self, empty_graph: KnowledgeGraph):
        """Graph rejects or scrubs raw secrets from properties."""
        with pytest.raises(ValueError, match="Sensitive credential"):
            empty_graph.add_node("agent:leaky", "agent", properties={"api_key": "sk-secret-12345"})

        with pytest.raises(ValueError, match="Sensitive credential"):
            empty_graph.add_node("agent:leaky2", "agent", properties={"password": "admin-password"})

    def test_oversized_import_rejected(self, empty_graph: KnowledgeGraph):
        """Oversized payloads must be rejected to prevent Denial-of-Service."""
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as tf:
            # Write dummy data over 50MB
            tf.write(" " * (51 * 1024 * 1024))
            tf_path = tf.name

        try:
            with pytest.raises(ValueError, match="exceeds.*limit"):
                empty_graph.import_from_file(tf_path)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)


class TestSQLiteGraphStore:
    """Test SQLite persistent graph storage backend."""

    def test_sqlite_store_persistence(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
            db_path = tf.name

        try:
            # 1. Create and populate via SQLite store
            store1 = SQLiteGraphStore(db_path)
            kg1 = KnowledgeGraph(store=store1)
            kg1.add_node("agent:sec", "agent", {"role": "guard"})
            kg1.add_node("model:claude", "model", {"vendor": "anthropic"})
            kg1.add_relationship("agent:sec", "USES", "model:claude")
            assert store1.node_count() == 2
            assert store1.relationship_count() == 1
            store1.close()

            # 2. Re-open and verify persistence
            store2 = SQLiteGraphStore(db_path)
            kg2 = KnowledgeGraph(store=store2)
            assert kg2.store.node_count() == 2
            assert kg2.store.relationship_count() == 1
            n = kg2.get_node("agent:sec")
            assert n is not None
            assert n.properties["role"] == "guard"
            rel = kg2.get_relationship("agent:sec", "USES", "model:claude")
            assert rel is not None
            store2.close()
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)


class TestConcurrencyAndThreadSafety:
    """Test thread-safe concurrent mutations."""

    def test_concurrent_node_insertions(self, empty_graph: KnowledgeGraph):
        num_threads = 8
        nodes_per_thread = 50

        def worker(tid: int):
            for i in range(nodes_per_thread):
                empty_graph.add_node(f"node:{tid}_{i}", "agent", {"idx": i})

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert empty_graph.store.node_count() == num_threads * nodes_per_thread


class TestReportingFormatters:
    """Test human-readable formatters."""

    def test_formatters(self, populated_graph: KnowledgeGraph):
        impact = populated_graph.security_impact("agent:triage")
        text_impact = format_impact_human(impact)
        assert "Security Impact Analysis" in text_impact
        assert "agent:triage" in text_impact

        blast = populated_graph.blast_radius("agent:triage")
        text_blast = format_blast_radius_human(blast)
        assert "Security Blast Radius" in text_blast

        cov = populated_graph.control_coverage("agent:triage")
        text_cov = format_coverage_human(cov)
        assert "Control Coverage Assessment" in text_cov

        path = populated_graph.find_path("app:chat", "model:gpt-4o")
        text_path = format_path_human(path)
        assert "──[" in text_path


class TestFirewallIntegration:
    """Test Firewall integration with KnowledgeGraph."""

    def test_firewall_build_security_graph(self):
        fw = Firewall()
        kg = fw.build_security_graph()
        assert kg.store.node_count() >= 4
        assert kg.get_node("application:firewall") is not None
        assert kg.find_nodes(type="security_control")
        assert kg.find_nodes(type="policy")
