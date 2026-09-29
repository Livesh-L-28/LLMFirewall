"""KnowledgeGraph engine orchestrating nodes, relationships, traversal, and security impact analysis."""

from collections import deque
import hashlib
import json
import logging
from pathlib import Path
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from llmfirewall.audit import AuditLogger, default_audit_logger
from llmfirewall.core.models import Action, AuditEvent, Severity
from llmfirewall.graph.models import (
    BlastRadiusResult,
    ChangeImpactResult,
    ControlCoverageItem,
    ControlCoverageResult,
    ControlStatus,
    FindingImpactResult,
    GraphDiff,
    GraphPath,
    GraphSnapshot,
    Node,
    NodeType,
    PolicyImpactResult,
    Relationship,
    RelationshipType,
    SecurityDiff,
    SecurityImpactResult,
)
from llmfirewall.graph.stores.base import GraphStore
from llmfirewall.graph.stores.memory import InMemoryGraphStore

logger = logging.getLogger("llmfirewall.graph")


class GraphMetrics:
    """Thread-safe telemetry metrics for knowledge graph operations."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.graph_nodes_total = 0
        self.graph_relationships_total = 0
        self.graph_queries_total = 0
        self.graph_query_failures_total = 0
        self.graph_query_duration_ms = 0.0
        self.graph_import_total = 0
        self.graph_export_total = 0

    def record_query(self, duration_ms: float, success: bool = True) -> None:
        with self._lock:
            self.graph_queries_total += 1
            self.graph_query_duration_ms += duration_ms
            if not success:
                self.graph_query_failures_total += 1

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "graph_nodes_total": self.graph_nodes_total,
                "graph_relationships_total": self.graph_relationships_total,
                "graph_queries_total": self.graph_queries_total,
                "graph_query_failures_total": self.graph_query_failures_total,
                "graph_query_duration_ms": round(self.graph_query_duration_ms, 3),
                "graph_import_total": self.graph_import_total,
                "graph_export_total": self.graph_export_total,
            }

    def reset(self) -> None:
        with self._lock:
            self.graph_nodes_total = 0
            self.graph_relationships_total = 0
            self.graph_queries_total = 0
            self.graph_query_failures_total = 0
            self.graph_query_duration_ms = 0.0
            self.graph_import_total = 0
            self.graph_export_total = 0


class KnowledgeGraph:
    """Lightweight, in-process, extensible AI Security Knowledge Graph.
    
    Security & Architectural Invariants:
    1. Zero External DB Mandate: Operates locally in-memory or via standard SQLite without cloud or external services.
    2. Zero Secret Infiltration: Never persists raw credentials, private API keys, or raw prompt secrets.
    3. Bounded Traversal: DFS/BFS algorithms feature strict cycle detection and depth boundaries to protect against DoS.
    4. Deterministic Identity: Employs stable domain-based node IDs (e.g. 'agent:support', 'model:gpt-4o').
    5. Deduplication: Idempotent addition of nodes and directed edges prevents graph bloat.
    """

    def __init__(
        self,
        store: Optional[GraphStore] = None,
        audit_logger: Optional[AuditLogger] = None,
        max_nodes: int = 100_000,
        max_relationships: int = 500_000,
        max_depth: int = 8,
        max_query_results: int = 10_000,
    ) -> None:
        self.store = store or InMemoryGraphStore()
        self.audit_logger = audit_logger
        self.max_nodes = max_nodes
        self.max_relationships = max_relationships
        self.max_depth = max_depth
        self.max_query_results = max_query_results
        self.metrics = GraphMetrics()

        # Extensible type registries
        self._registered_node_types: Set[str] = {t.value for t in NodeType}
        self._registered_rel_types: Set[str] = {r.value for r in RelationshipType}
        self._lock = threading.RLock()

    # ---------------------------------------------------------------------------
    # Extensibility & Registration
    # ---------------------------------------------------------------------------

    def register_node_type(self, type_name: str) -> None:
        """Register a custom node entity type."""
        with self._lock:
            clean = type_name.strip().lower()
            if not clean:
                raise ValueError("Node type cannot be blank.")
            self._registered_node_types.add(clean)

    def register_relationship_type(self, type_name: str) -> None:
        """Register a custom relationship type verb."""
        with self._lock:
            clean = type_name.strip().upper()
            if not clean:
                raise ValueError("Relationship type cannot be blank.")
            self._registered_rel_types.add(clean)

    # ---------------------------------------------------------------------------
    # Node Operations
    # ---------------------------------------------------------------------------

    def add_node(
        self,
        node_or_id: Union[Node, str],
        node_type: Union[NodeType, str] = NodeType.CUSTOM.value,
        properties: Optional[Dict[str, Any]] = None,
    ) -> Node:
        """Add or update an entity node in the graph with automatic deduplication."""
        if isinstance(node_or_id, Node):
            node = node_or_id
        else:
            if isinstance(node_type, NodeType):
                t_str = node_type.value
            else:
                t_str = str(node_type).strip().lower()
            node = Node(
                id=str(node_or_id).strip(),
                type=t_str,
                properties=properties or {},
            )

        clean_type = node.type.strip().lower()
        if clean_type not in self._registered_node_types:
            raise ValueError(f"Invalid node type '{clean_type}'. Must be registered.")

        for k in (node.properties or {}):
            k_lower = str(k).lower()
            if any(s in k_lower for s in ("api_key", "password", "secret", "private_key", "token", "credential")):
                raise ValueError(f"Sensitive credential key '{k}' detected. Secrets cannot be stored in graph node properties.")

        if self.store.node_count() >= self.max_nodes and not self.store.get_node(node.id):
            raise RuntimeError(f"Maximum graph node capacity ({self.max_nodes}) exceeded.")

        res = self.store.add_node(node)
        self.metrics.graph_nodes_total = self.store.node_count()
        self._emit_audit("NODE_CREATED", {"node_id": res.id, "type": res.type})
        return res

    def add_nodes(self, nodes: List[Node]) -> List[Node]:
        """Batch add nodes to the graph."""
        return [self.add_node(n) for n in nodes]

    def get_node(self, node_id: str) -> Optional[Node]:
        """Retrieve a node by its identifier."""
        return self.store.get_node(node_id)

    def remove_node(self, node_id: str, cascade: bool = True) -> bool:
        """Remove a node and optionally clean up connected edges to prevent dangling relationships."""
        res = self.store.remove_node(node_id, cascade=cascade)
        if res:
            self.metrics.graph_nodes_total = self.store.node_count()
            self.metrics.graph_relationships_total = self.store.relationship_count()
            self._emit_audit("NODE_REMOVED", {"node_id": node_id, "cascade": cascade})
        return res

    def find_nodes(
        self,
        type: Optional[str] = None,
        property_filters: Optional[Dict[str, Any]] = None,
    ) -> List[Node]:
        """Search nodes by type and matching property attributes."""
        nodes = self.store.get_all_nodes(node_type=type)
        if not property_filters:
            return nodes

        filtered = []
        for n in nodes:
            match = True
            for k, v in property_filters.items():
                if n.properties.get(k) != v:
                    match = False
                    break
            if match:
                filtered.append(n)
        return filtered

    # ---------------------------------------------------------------------------
    # Relationship Operations
    # ---------------------------------------------------------------------------

    def add_relationship(
        self,
        relationship_or_source: Union[Relationship, str],
        rel_type: Optional[Union[RelationshipType, str]] = None,
        target: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
    ) -> Relationship:
        """Add a directed relationship edge between two existing nodes."""
        if isinstance(relationship_or_source, Relationship):
            rel = relationship_or_source
        else:
            if not rel_type or not target:
                raise ValueError("rel_type and target must be provided when adding relationship by string IDs.")
            if isinstance(rel_type, RelationshipType):
                r_type = rel_type.value
            else:
                r_type = str(rel_type).strip().upper()
            rel = Relationship(
                source=str(relationship_or_source).strip(),
                type=r_type,
                target=str(target).strip(),
                properties=properties or {},
            )

        clean_type = rel.type.strip().upper()
        if clean_type not in self._registered_rel_types:
            raise ValueError(f"Invalid relationship type '{clean_type}'. Must be registered.")

        if not self.store.get_node(rel.source):
            raise KeyError(f"Source node '{rel.source}' does not exist in knowledge graph.")
        if not self.store.get_node(rel.target):
            raise KeyError(f"Target node '{rel.target}' does not exist in knowledge graph.")

        for k in (rel.properties or {}):
            k_lower = str(k).lower()
            if any(s in k_lower for s in ("api_key", "password", "secret", "private_key", "token", "credential")):
                raise ValueError(f"Sensitive credential key '{k}' detected in relationship properties.")

        if self.store.relationship_count() >= self.max_relationships and not self.store.get_relationship(rel.source, rel.type, rel.target):
            raise RuntimeError(f"Maximum graph relationship capacity ({self.max_relationships}) exceeded.")

        res = self.store.add_relationship(rel)
        self.metrics.graph_relationships_total = self.store.relationship_count()
        self._emit_audit("RELATIONSHIP_CREATED", {
            "source": res.source,
            "type": res.type,
            "target": res.target,
        })
        return res

    def add_relationships(self, relationships: List[Relationship]) -> List[Relationship]:
        """Batch add relationships to the graph."""
        return [self.add_relationship(r) for r in relationships]

    def get_relationship(self, source: str, type: str, target: str) -> Optional[Relationship]:
        """Retrieve relationship by source, type verb, and target."""
        return self.store.get_relationship(source, type, target)

    def remove_relationship(self, source: str, type: str, target: str) -> bool:
        """Remove a specific relationship edge."""
        res = self.store.remove_relationship(source, type, target)
        if res:
            self.metrics.graph_relationships_total = self.store.relationship_count()
            self._emit_audit("RELATIONSHIP_REMOVED", {
                "source": source,
                "type": type.strip().upper(),
                "target": target,
            })
        return res

    def find_relationships(
        self,
        source: Optional[str] = None,
        target: Optional[str] = None,
        type: Optional[str] = None,
    ) -> List[Relationship]:
        """Search relationships by source, target, or relationship type."""
        norm_type = type.strip().upper() if type else None

        if source and not target:
            return self.store.get_out_edges(source, rel_type=norm_type)
        if target and not source:
            return self.store.get_in_edges(target, rel_type=norm_type)

        all_edges = self.store.get_all_relationships(rel_type=norm_type)
        if source and target:
            return [e for e in all_edges if e.source == source and e.target == target]
        return all_edges

    def get_neighbors(
        self,
        node_id: str,
        direction: str = "both",
        rel_type: Optional[str] = None,
    ) -> List[Node]:
        """Retrieve adjacent nodes connected to node_id."""
        return self.store.get_neighbors(node_id, direction=direction, rel_type=rel_type)

    # ---------------------------------------------------------------------------
    # Graph Validation
    # ---------------------------------------------------------------------------

    def validate(self) -> List[str]:
        """Verify graph integrity: no dangling edges, valid types, existing endpoints."""
        errors: List[str] = []
        all_nodes = {n.id: n for n in self.store.get_all_nodes()}

        for edge in self.store.get_all_relationships():
            if edge.source not in all_nodes:
                errors.append(f"Dangling edge: Source node '{edge.source}' does not exist in graph.")
            if edge.target not in all_nodes:
                errors.append(f"Dangling edge: Target node '{edge.target}' does not exist in graph.")

        return errors

    # ---------------------------------------------------------------------------
    # Traversal & Path Search (Cycle-Protected & Bounded)
    # ---------------------------------------------------------------------------

    def find_path(
        self,
        source: str,
        target: str,
        max_depth: Optional[int] = None,
    ) -> Optional[GraphPath]:
        """Find the shortest directed path from source to target using BFS with cycle protection."""
        paths = self.find_paths(source=source, target=target, max_depth=max_depth, max_paths=1)
        return paths[0] if paths else None

    def find_paths(
        self,
        source: str,
        target: str,
        max_depth: Optional[int] = None,
        max_paths: int = 10,
    ) -> List[GraphPath]:
        """Find up to max_paths directed paths between source and target with cycle detection and depth bounding."""
        t0 = time.perf_counter()
        depth_limit = min(max_depth or self.max_depth, self.max_depth)

        if not self.store.get_node(source) or not self.store.get_node(target):
            self.metrics.record_query((time.perf_counter() - t0) * 1000.0, success=False)
            return []

        if source == target:
            self.metrics.record_query((time.perf_counter() - t0) * 1000.0, success=True)
            return [GraphPath(source_id=source, target_id=target, nodes=[source], length=0)]

        found_paths: List[GraphPath] = []
        # Queue item: (current_node, [nodes_visited], [rel_types])
        queue: deque = deque([(source, [source], [])])

        while queue and len(found_paths) < max_paths:
            curr, path_nodes, path_rels = queue.popleft()

            if len(path_rels) >= depth_limit:
                continue

            for edge in self.store.get_out_edges(curr):
                next_node = edge.target
                if next_node == target:
                    completed_path = GraphPath(
                        source_id=source,
                        target_id=target,
                        nodes=path_nodes + [next_node],
                        relationships=path_rels + [edge.type],
                        length=len(path_rels) + 1,
                    )
                    found_paths.append(completed_path)
                    if len(found_paths) >= max_paths:
                        break
                elif next_node not in path_nodes:  # Cycle prevention
                    queue.append((
                        next_node,
                        path_nodes + [next_node],
                        path_rels + [edge.type],
                    ))

        duration_ms = (time.perf_counter() - t0) * 1000.0
        self.metrics.record_query(duration_ms, success=True)
        return found_paths

    # ---------------------------------------------------------------------------
    # Security Impact Analysis
    # ---------------------------------------------------------------------------

    def security_impact(
        self,
        asset_id: str,
        max_depth: int = 2,
    ) -> SecurityImpactResult:
        """Identify all security controls, findings, policies, tests, threats, and dependencies affecting an asset."""
        t0 = time.perf_counter()
        target_node = self.store.get_node(asset_id)
        if not target_node:
            raise ValueError(f"Asset node '{asset_id}' not found in knowledge graph.")

        visited: Set[str] = {asset_id}
        queue: deque = deque([(asset_id, 0)])

        findings: List[str] = []
        controls: List[str] = []
        policies: List[str] = []
        tests: List[str] = []
        threats: List[str] = []
        dependencies: List[str] = []
        finding_details: List[Dict[str, Any]] = []
        control_details: List[Dict[str, Any]] = []
        policy_details: List[Dict[str, Any]] = []
        test_details: List[Dict[str, Any]] = []
        threat_details: List[Dict[str, Any]] = []
        dependency_details: List[Dict[str, Any]] = []

        direct_neighbors = self.store.get_neighbors(asset_id, direction="both")
        directly_connected_count = len(direct_neighbors)

        while queue:
            curr_id, depth = queue.popleft()
            if depth >= max_depth:
                continue

            # Check neighbors in both directions
            for neighbor in self.store.get_neighbors(curr_id, direction="both"):
                if neighbor.id not in visited:
                    visited.add(neighbor.id)
                    ntype = neighbor.type
                    item = {"id": neighbor.id, "type": neighbor.type, "properties": neighbor.properties}

                    if ntype == NodeType.FINDING.value:
                        findings.append(neighbor.id)
                        finding_details.append(item)
                    elif ntype == NodeType.SECURITY_CONTROL.value:
                        controls.append(neighbor.id)
                        control_details.append(item)
                    elif ntype == NodeType.POLICY.value:
                        policies.append(neighbor.id)
                        policy_details.append(item)
                    elif ntype == NodeType.SECURITY_TEST.value:
                        tests.append(neighbor.id)
                        test_details.append(item)
                    elif ntype in (NodeType.THREAT.value, NodeType.ATTACK_TECHNIQUE.value):
                        threats.append(neighbor.id)
                        threat_details.append(item)
                    elif ntype == NodeType.DEPENDENCY.value:
                        dependencies.append(neighbor.id)
                        dependency_details.append(item)

                    queue.append((neighbor.id, depth + 1))

        duration_ms = (time.perf_counter() - t0) * 1000.0
        self.metrics.record_query(duration_ms, success=True)

        return SecurityImpactResult(
            asset_id=asset_id,
            asset_type=target_node.type,
            findings=findings,
            controls=controls,
            policies=policies,
            tests=tests,
            threats=threats,
            dependencies=dependencies,
            finding_details=finding_details,
            control_details=control_details,
            policy_details=policy_details,
            test_details=test_details,
            threat_details=threat_details,
            dependency_details=dependency_details,
            directly_connected_count=directly_connected_count,
            total_impact_count=len(visited) - 1,
        )

    # ---------------------------------------------------------------------------
    # Blast Radius Analysis
    # ---------------------------------------------------------------------------

    def blast_radius(
        self,
        asset_id: str,
        max_depth: int = 3,
    ) -> BlastRadiusResult:
        """Measure outward cascading blast radius if an asset (model, tool, dependency) changes or is compromised."""
        t0 = time.perf_counter()
        target_node = self.store.get_node(asset_id)
        if not target_node:
            raise ValueError(f"Asset node '{asset_id}' not found in knowledge graph.")

        visited: Set[str] = {asset_id}
        queue: deque = deque([(asset_id, [asset_id], [])])

        apps: Set[str] = set()
        agents: Set[str] = set()
        tools: Set[str] = set()
        models: Set[str] = set()
        policies: Set[str] = set()
        findings: Set[str] = set()
        propagation_paths: List[GraphPath] = []
        max_d_seen = 0

        while queue:
            curr_id, path_nodes, path_rels = queue.popleft()
            d = len(path_rels)
            if d > max_d_seen:
                max_d_seen = d

            if d >= max_depth:
                continue

            # Traverse outward: outgoing edges and incoming 'USES', 'CALLS', 'DEPENDS_ON'
            candidates = []
            for e in self.store.get_out_edges(curr_id):
                candidates.append((e.target, e.type))
            for e in self.store.get_in_edges(curr_id):
                if e.type in (
                    RelationshipType.USES.value,
                    RelationshipType.CALLS.value,
                    RelationshipType.CAN_CALL.value,
                    RelationshipType.DEPENDS_ON.value,
                    RelationshipType.AFFECTS.value,
                ):
                    candidates.append((e.source, f"INVERSE_{e.type}"))

            for next_id, rel_label in candidates:
                if next_id not in visited:
                    visited.add(next_id)
                    node = self.store.get_node(next_id)
                    if node:
                        ntype = node.type
                        if ntype == NodeType.APPLICATION.value:
                            apps.add(node.id)
                        elif ntype == NodeType.AGENT.value:
                            agents.add(node.id)
                        elif ntype == NodeType.TOOL.value:
                            tools.add(node.id)
                        elif ntype == NodeType.MODEL.value:
                            models.add(node.id)
                        elif ntype == NodeType.POLICY.value:
                            policies.add(node.id)
                        elif ntype == NodeType.FINDING.value:
                            findings.add(node.id)

                    path = GraphPath(
                        source_id=asset_id,
                        target_id=next_id,
                        nodes=path_nodes + [next_id],
                        relationships=path_rels + [rel_label],
                        length=d + 1,
                    )
                    propagation_paths.append(path)
                    queue.append((next_id, path_nodes + [next_id], path_rels + [rel_label]))

        duration_ms = (time.perf_counter() - t0) * 1000.0
        self.metrics.record_query(duration_ms, success=True)

        return BlastRadiusResult(
            source_asset_id=asset_id,
            source_asset_type=target_node.type,
            impacted_applications=sorted(list(apps)),
            impacted_agents=sorted(list(agents)),
            impacted_tools=sorted(list(tools)),
            impacted_models=sorted(list(models)),
            impacted_policies=sorted(list(policies)),
            impacted_findings=sorted(list(findings)),
            total_impacted_nodes=len(visited) - 1,
            max_depth_reached=max_d_seen,
            propagation_paths=propagation_paths,
        )

    # ---------------------------------------------------------------------------
    # Targeted Impact Queries
    # ---------------------------------------------------------------------------

    def change_impact(self, changed_node_id: str) -> ChangeImpactResult:
        """Identify assets requiring re-evaluation or regression tests following a component change."""
        affected: Set[str] = set()
        required_tests: Set[str] = set()

        queue = deque([changed_node_id])
        visited = {changed_node_id}
        while queue:
            curr = queue.popleft()
            for edge in self.store.get_in_edges(curr):
                if edge.source not in visited:
                    visited.add(edge.source)
                    queue.append(edge.source)
                    s_node = self.store.get_node(edge.source)
                    if s_node:
                        if s_node.type in (NodeType.APPLICATION.value, NodeType.AGENT.value, NodeType.TOOL.value, NodeType.MODEL.value):
                            affected.add(s_node.id)
                        elif s_node.type == NodeType.SECURITY_TEST.value:
                            required_tests.add(s_node.id)
            for edge in self.store.get_out_edges(curr):
                if edge.target not in visited:
                    visited.add(edge.target)
                    queue.append(edge.target)
                    t_node = self.store.get_node(edge.target)
                    if t_node:
                        if t_node.type in (NodeType.APPLICATION.value, NodeType.AGENT.value, NodeType.TOOL.value, NodeType.MODEL.value):
                            affected.add(t_node.id)
                        elif t_node.type == NodeType.SECURITY_TEST.value:
                            required_tests.add(t_node.id)

        for asset in list(affected):
            for edge in self.store.get_in_edges(asset):
                if edge.type in (RelationshipType.TESTED_BY.value, RelationshipType.TESTS.value):
                    required_tests.add(edge.source)
            for edge in self.store.get_out_edges(asset):
                if edge.type in (RelationshipType.TESTED_BY.value, RelationshipType.TESTS.value):
                    required_tests.add(edge.target)

        # Also search for tests evaluating controls of affected assets
        for asset in list(affected):
            for edge in self.store.get_in_edges(asset):
                if edge.type in (RelationshipType.PROTECTS.value, "PROTECTS"):
                    ctrl_id = edge.source
                    for e in self.store.get_in_edges(ctrl_id):
                        if e.type in (RelationshipType.TESTS.value, RelationshipType.TESTED_BY.value):
                            required_tests.add(e.source)
                    for e in self.store.get_out_edges(ctrl_id):
                        if e.type in (RelationshipType.TESTS.value, RelationshipType.TESTED_BY.value):
                            required_tests.add(e.target)

        return ChangeImpactResult(
            changed_node=changed_node_id,
            affected_assets=sorted(list(affected)),
            required_tests=sorted(list(required_tests)),
        )

    def policy_impact(self, policy_id: str) -> PolicyImpactResult:
        """Identify all assets governed or protected by a specific security policy."""
        governed_agents: Set[str] = set()
        governed_tools: Set[str] = set()
        governed_models: Set[str] = set()
        protected_controls: Set[str] = set()
        affected_tests: Set[str] = set()
        affected_findings: Set[str] = set()

        for edge in self.store.get_in_edges(policy_id):
            node = self.store.get_node(edge.source)
            if node:
                if node.type == NodeType.AGENT.value:
                    governed_agents.add(node.id)
                elif node.type == NodeType.TOOL.value:
                    governed_tools.add(node.id)
                elif node.type == NodeType.MODEL.value:
                    governed_models.add(node.id)
                elif node.type == NodeType.SECURITY_CONTROL.value:
                    protected_controls.add(node.id)

        for edge in self.store.get_out_edges(policy_id):
            node = self.store.get_node(edge.target)
            if node:
                if node.type == NodeType.AGENT.value:
                    governed_agents.add(node.id)
                elif node.type == NodeType.TOOL.value:
                    governed_tools.add(node.id)
                elif node.type == NodeType.MODEL.value:
                    governed_models.add(node.id)
                elif node.type == NodeType.SECURITY_CONTROL.value:
                    protected_controls.add(node.id)

        # For governed agents, include their protecting controls and findings
        for ag in list(governed_agents):
            for edge in self.store.get_in_edges(ag):
                node = self.store.get_node(edge.source)
                if node and node.type == NodeType.SECURITY_CONTROL.value:
                    protected_controls.add(node.id)
                elif node and node.type == NodeType.FINDING.value:
                    affected_findings.add(node.id)
            for edge in self.store.get_out_edges(ag):
                node = self.store.get_node(edge.target)
                if node and node.type == NodeType.SECURITY_CONTROL.value:
                    protected_controls.add(node.id)
                elif node and node.type == NodeType.FINDING.value:
                    affected_findings.add(node.id)

        for ctrl in list(protected_controls):
            for edge in self.store.get_in_edges(ctrl):
                node = self.store.get_node(edge.source)
                if node and node.type == NodeType.SECURITY_TEST.value:
                    affected_tests.add(node.id)

        return PolicyImpactResult(
            policy_id=policy_id,
            affected_agents=sorted(list(governed_agents)),
            affected_models=sorted(list(governed_models)),
            affected_tools=sorted(list(governed_tools)),
            security_controls=sorted(list(protected_controls)),
            affected_tests=sorted(list(affected_tests)),
            affected_findings=sorted(list(affected_findings)),
        )

    def finding_impact(self, finding_id: str) -> FindingImpactResult:
        """Identify all assets and mitigating controls directly affected by a security finding."""
        affected: Set[str] = set()
        mitigating: Set[str] = set()

        for edge in self.store.get_out_edges(finding_id):
            if edge.type in (RelationshipType.AFFECTS.value, "AFFECTS"):
                affected.add(edge.target)
            elif edge.type in (RelationshipType.MITIGATED_BY.value, "MITIGATED_BY"):
                mitigating.add(edge.target)

        for edge in self.store.get_in_edges(finding_id):
            if edge.type in (RelationshipType.HAS_FINDING.value, "HAS_FINDING"):
                affected.add(edge.source)
            elif edge.type in (RelationshipType.MITIGATES.value, "MITIGATES"):
                mitigating.add(edge.source)

        return FindingImpactResult(
            finding_id=finding_id,
            affected_assets=sorted(list(affected)),
            mitigating_controls=sorted(list(mitigating)),
        )

    def control_coverage(self, asset_id: str) -> ControlCoverageResult:
        """Evidence-based security control coverage report for an asset (no fake coverage)."""
        target = self.store.get_node(asset_id)
        if not target:
            raise ValueError(f"Asset '{asset_id}' not found in knowledge graph.")

        controls_seen: Set[str] = set()
        items: List[ControlCoverageItem] = []
        passing_cnt = 0
        failing_cnt = 0

        # Find controls protecting this asset
        candidate_ctrl_ids = set()
        for edge in self.store.get_in_edges(asset_id):
            if edge.type in (RelationshipType.PROTECTS.value, RelationshipType.PROTECTED_BY.value, "PROTECTS", "PROTECTED_BY"):
                candidate_ctrl_ids.add(edge.source)
        for edge in self.store.get_out_edges(asset_id):
            if edge.type in (RelationshipType.PROTECTED_BY.value, "PROTECTED_BY"):
                candidate_ctrl_ids.add(edge.target)

        for ctrl_id in sorted(list(candidate_ctrl_ids)):
            if ctrl_id in controls_seen:
                continue
            controls_seen.add(ctrl_id)
            ctrl_node = self.store.get_node(ctrl_id)
            if not ctrl_node:
                continue

            ctrl_status = ControlStatus.CONFIGURED
            verified_test = None
            evidence = None

            # Check if control is tested:
            test_edges = []
            for e in self.store.get_in_edges(ctrl_node.id):
                if e.type in (RelationshipType.TESTS.value, RelationshipType.TESTED_BY.value, "TESTS", "TESTED_BY"):
                    test_edges.append(e.source)
            for e in self.store.get_out_edges(ctrl_node.id):
                if e.type in (RelationshipType.TESTED_BY.value, RelationshipType.TESTS.value, "TESTED_BY", "TESTS"):
                    test_edges.append(e.target)

            if test_edges:
                verified_test = test_edges[0]
                test_node = self.store.get_node(verified_test)
                if test_node:
                    props = test_node.properties
                    status_str = str(props.get("status", "")).lower()
                    passed_val = props.get("passed")
                    if passed_val is True or status_str in ("passing", "pass", "passed", "success"):
                        ctrl_status = ControlStatus.PASSING
                        passing_cnt += 1
                    elif passed_val is False or status_str in ("failing", "fail", "failed"):
                        ctrl_status = ControlStatus.FAILING
                        failing_cnt += 1
                    else:
                        ctrl_status = ControlStatus.TESTED
            else:
                # Check active findings
                finding_edges = self.store.get_out_edges(ctrl_node.id, rel_type=RelationshipType.MITIGATED_BY.value)
                if finding_edges:
                    ctrl_status = ControlStatus.PASSING
                    passing_cnt += 1

            items.append(ControlCoverageItem(
                control_id=ctrl_node.id,
                control_name=ctrl_node.properties.get("name", ctrl_node.id),
                status=ctrl_status,
                verified_by_test=verified_test,
                evidence=evidence,
            ))

        total = len(items)
        rate = passing_cnt / max(1, total) if total > 0 else 0.0

        return ControlCoverageResult(
            asset_id=asset_id,
            asset_type=target.type,
            controls=items,
            total_controls=total,
            passing_controls=passing_cnt,
            failing_controls=failing_cnt,
            coverage_rate=round(rate, 3),
        )

    # ---------------------------------------------------------------------------
    # Snapshots, Diff & Hash
    # ---------------------------------------------------------------------------

    def snapshot(self, graph_version: str = "1.0") -> GraphSnapshot:
        """Capture an immutable, serializable, SHA-256 hashed snapshot of the graph."""
        nodes = self.store.get_all_nodes()
        edges = self.store.get_all_relationships()
        return GraphSnapshot.create(
            nodes=nodes,
            relationships=edges,
            graph_version=graph_version,
        )

    def graph_hash(self) -> str:
        """Compute the deterministic cryptographic SHA-256 digest of current graph contents."""
        return self.snapshot().graph_hash

    @staticmethod
    def diff(previous: GraphSnapshot, current: GraphSnapshot) -> GraphDiff:
        """Compute structural differences between two graph snapshots."""
        prev_nodes = {n.id: n for n in previous.nodes}
        curr_nodes = {n.id: n for n in current.nodes}

        nodes_added = sorted([nid for nid in curr_nodes if nid not in prev_nodes])
        nodes_removed = sorted([nid for nid in prev_nodes if nid not in curr_nodes])
        nodes_changed = sorted([
            nid for nid in curr_nodes
            if nid in prev_nodes and curr_nodes[nid].properties != prev_nodes[nid].properties
        ])

        prev_edges = {r.edge_key: r for r in previous.relationships}
        curr_edges = {r.edge_key: r for r in current.relationships}

        rels_added = sorted([k for k in curr_edges if k not in prev_edges])
        rels_removed = sorted([k for k in prev_edges if k not in curr_edges])

        is_identical = (
            len(nodes_added) == 0
            and len(nodes_removed) == 0
            and len(nodes_changed) == 0
            and len(rels_added) == 0
            and len(rels_removed) == 0
            and previous.graph_hash == current.graph_hash
        )

        return GraphDiff(
            nodes_added=nodes_added,
            nodes_removed=nodes_removed,
            nodes_changed=nodes_changed,
            relationships_added=rels_added,
            relationships_removed=rels_removed,
            is_identical=is_identical,
        )

    @staticmethod
    def security_diff(previous: GraphSnapshot, current: GraphSnapshot) -> SecurityDiff:
        """Highlight security-relevant diffs (new tool access, new capabilities, models, findings)."""
        diff = KnowledgeGraph.diff(previous, current)
        curr_nodes = {n.id: n for n in current.nodes}
        prev_nodes = {n.id: n for n in previous.nodes}

        new_tools: List[Dict[str, str]] = []
        for ek in diff.relationships_added:
            parts = ek.split("|")
            if len(parts) == 3 and parts[1] in (RelationshipType.CAN_CALL.value, RelationshipType.CAN_ACCESS.value):
                new_tools.append({"agent": parts[0], "relation": parts[1], "target": parts[2]})

        new_caps = [nid for nid in diff.nodes_added if getattr(curr_nodes.get(nid), "type", None) == NodeType.CAPABILITY.value]
        new_deps = [nid for nid in diff.nodes_added if getattr(curr_nodes.get(nid), "type", None) == NodeType.DEPENDENCY.value]
        new_pols = [nid for nid in diff.nodes_added if getattr(curr_nodes.get(nid), "type", None) == NodeType.POLICY.value]
        new_finds = [nid for nid in diff.nodes_added if getattr(curr_nodes.get(nid), "type", None) == NodeType.FINDING.value]

        model_changes: List[Dict[str, str]] = []
        for nid in diff.nodes_changed:
            if getattr(curr_nodes.get(nid), "type", None) == NodeType.MODEL.value:
                old_h = prev_nodes[nid].properties.get("sha256", "") if nid in prev_nodes else ""
                new_h = curr_nodes[nid].properties.get("sha256", "") if nid in curr_nodes else ""
                if old_h != new_h:
                    model_changes.append({"model_id": nid, "old_hash": old_h, "new_hash": new_h})

        removed_ctrls = [nid for nid in diff.nodes_removed if getattr(prev_nodes.get(nid), "type", None) == NodeType.SECURITY_CONTROL.value]

        has_impact = bool(new_tools or new_caps or model_changes or new_deps or new_finds or removed_ctrls)

        return SecurityDiff(
            new_tool_access=new_tools,
            new_capabilities=new_caps,
            model_changes=model_changes,
            new_dependencies=new_deps,
            new_policies=new_pols,
            new_findings=new_finds,
            removed_controls=removed_ctrls,
            has_security_impact=has_impact,
        )

    # ---------------------------------------------------------------------------
    # Serialization & File Import/Export
    # ---------------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Convert graph to JSON-serializable dictionary."""
        return self.snapshot().model_dump(mode="json")

    def to_json(self, indent: int = 2) -> str:
        """Export graph to formatted JSON string without secret tokens."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(
        cls,
        data: Dict[str, Any],
        store: Optional[GraphStore] = None,
    ) -> "KnowledgeGraph":
        """Instantiate graph from dictionary envelope with validation."""
        graph = cls(store=store)

        if not isinstance(data, dict):
            raise ValueError("Imported graph root must be a dictionary.")

        raw_nodes = data.get("nodes", [])
        raw_edges = data.get("relationships", [])

        if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
            raise ValueError("Malformed graph: 'nodes' and 'relationships' must be lists.")

        for n_data in raw_nodes:
            graph.add_node(Node(**n_data))

        for r_data in raw_edges:
            graph.add_relationship(Relationship(**r_data))

        validation_errors = graph.validate()
        if validation_errors:
            raise ValueError(f"Imported graph integrity validation failed: {validation_errors}")

        return graph

    @classmethod
    def from_json(cls, json_str: str, store: Optional[GraphStore] = None) -> "KnowledgeGraph":
        """Instantiate graph from JSON string."""
        return cls.from_dict(json.loads(json_str), store=store)

    def export_to_file(self, file_path: Union[str, Path]) -> str:
        """Export graph to local JSON file."""
        path = Path(file_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        content = self.to_json()
        path.write_text(content, encoding="utf-8")
        self.metrics.graph_export_total += 1
        self._emit_audit("GRAPH_EXPORTED", {"output_file": str(path), "node_count": self.store.node_count()})
        return str(path)

    def import_from_file(self, file_path: Union[str, Path], clear_existing: bool = False) -> int:
        """Import graph from local JSON file with input validation and DoS bounds."""
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Graph file not found: {file_path}")

        # Protect against oversized files (max 50MB)
        if path.stat().st_size > 50 * 1024 * 1024:
            raise ValueError("Graph import file exceeds maximum size limit (50MB).")

        content = path.read_text(encoding="utf-8")
        data = json.loads(content)

        if clear_existing:
            self.store.clear()

        imported_graph = self.from_dict(data)
        for node in imported_graph.store.get_all_nodes():
            self.add_node(node)
        for edge in imported_graph.store.get_all_relationships():
            self.add_relationship(edge)

        self.metrics.graph_import_total += 1
        self._emit_audit("GRAPH_IMPORTED", {
            "source_file": str(path),
            "node_count": self.store.node_count(),
            "relationship_count": self.store.relationship_count(),
        })
        return self.store.node_count()

    # ---------------------------------------------------------------------------
    # Domain Ingestion Helpers (Phase 28-31 Reusability)
    # ---------------------------------------------------------------------------

    def ingest_agent(
        self,
        agent_id: str,
        name: str = "",
        model_name: Optional[str] = None,
        capabilities: Optional[List[str]] = None,
        tools: Optional[List[str]] = None,
        policy_id: Optional[str] = None,
    ) -> Node:
        """Ingest an agent entity and wire its capabilities, tools, model, and policy relationships."""
        agent_node = self.add_node(
            node_or_id=f"agent:{agent_id}",
            node_type=NodeType.AGENT.value,
            properties={"name": name or agent_id, "agent_id": agent_id},
        )

        if model_name:
            model_node = self.add_node(f"model:{model_name}", node_type=NodeType.MODEL.value, properties={"name": model_name})
            self.add_relationship(agent_node.id, RelationshipType.USES.value, model_node.id)

        if policy_id:
            policy_node = self.add_node(f"policy:{policy_id}", node_type=NodeType.POLICY.value, properties={"policy_id": policy_id})
            self.add_relationship(agent_node.id, RelationshipType.GOVERNED_BY.value, policy_node.id)

        if tools:
            for t in tools:
                tool_node = self.add_node(f"tool:{t}", node_type=NodeType.TOOL.value, properties={"tool_name": t})
                self.add_relationship(agent_node.id, RelationshipType.CAN_CALL.value, tool_node.id)

        if capabilities:
            for cap in capabilities:
                cap_node = self.add_node(f"capability:{cap}", node_type=NodeType.CAPABILITY.value, properties={"capability": cap})
                self.add_relationship(agent_node.id, RelationshipType.CAN_ACCESS.value, cap_node.id)

        return agent_node

    def ingest_evaluation_report(self, report: Any) -> None:
        """Ingest Phase 30 security evaluation report outcomes, tests, and findings."""
        suite_id = f"test_suite:{getattr(report, 'suite_name', 'default')}"
        suite_node = self.add_node(suite_id, node_type=NodeType.SECURITY_TEST.value, properties={
            "suite_name": getattr(report, "suite_name", ""),
            "suite_version": getattr(report, "suite_version", ""),
            "pass_rate": getattr(report, "metrics", {}).pass_rate if hasattr(report, "metrics") else 1.0,
        })

        for res in getattr(report, "results", []):
            test_node = self.add_node(f"test:{res.test_id}", node_type=NodeType.SECURITY_TEST.value, properties={
                "test_id": res.test_id,
                "category": getattr(res.category, "value", str(res.category)),
                "passed": res.passed,
                "severity": getattr(res.severity, "value", str(res.severity)),
            })
            self.add_relationship(suite_node.id, RelationshipType.CONTAINS.value, test_node.id)

            if not res.passed and res.finding:
                f = res.finding
                finding_node = self.add_node(f"finding:{f.finding_id}", node_type=NodeType.FINDING.value, properties={
                    "finding_id": f.finding_id,
                    "description": f.description,
                    "severity": getattr(f.severity, "value", str(f.severity)),
                    "category": f.category,
                })
                self.add_relationship(test_node.id, RelationshipType.HAS_FINDING.value, finding_node.id)

    def ingest_snapshot(self, snapshot: Any) -> None:
        """Ingest Phase 28 supply-chain security snapshot into graph relationships."""
        snap_id = f"snapshot:{getattr(snapshot, 'snapshot_hash', 'current')[:16]}"
        snap_node = self.add_node(snap_id, node_type=NodeType.BASELINE.value, properties={
            "snapshot_hash": getattr(snapshot, "snapshot_hash", ""),
            "app_version": getattr(snapshot.deployment, "application_version", "unknown") if hasattr(snapshot, "deployment") else "unknown",
        })

        for m in getattr(snapshot, "models", []):
            m_node = self.add_node(f"model:{m.name}", node_type=NodeType.MODEL.value, properties={
                "name": m.name,
                "version": m.version,
                "sha256": getattr(m, "sha256", ""),
                "format": getattr(m.format, "value", str(m.format)) if hasattr(m, "format") else "unknown",
            })
            self.add_relationship(snap_node.id, RelationshipType.CONTAINS.value, m_node.id)

        for dep in getattr(snapshot, "dependencies", []):
            d_node = self.add_node(f"dependency:{dep.name}", node_type=NodeType.DEPENDENCY.value, properties={
                "name": dep.name,
                "version": dep.version,
                "sha256": getattr(dep, "sha256", ""),
            })
            self.add_relationship(snap_node.id, RelationshipType.CONTAINS.value, d_node.id)

    def ingest_governance_result(self, result: Any) -> None:
        """Ingest Phase 31 governance release outcome and gate decisions."""
        rel_id = f"release:{getattr(result, 'release_id', 'unknown')}"
        rel_node = self.add_node(rel_id, node_type=NodeType.RELEASE.value, properties={
            "release_id": getattr(result, "release_id", "unknown"),
            "decision": getattr(result.decision, "value", str(result.decision)) if hasattr(result, "decision") else "UNKNOWN",
            "passed": getattr(result, "passed", False),
            "policy_version": getattr(result, "policy_version", "1.0"),
        })

        for g in getattr(result, "failed_gates", []):
            ctrl_node = self.add_node(f"control:{g.gate_id}", node_type=NodeType.SECURITY_CONTROL.value, properties={
                "gate_id": g.gate_id,
                "passed": False,
                "reason": g.reason,
            })
            self.add_relationship(rel_node.id, RelationshipType.BLOCKED_BY.value, ctrl_node.id)

    def _emit_audit(self, event_type: str, details: Dict[str, Any]) -> None:
        """Emit audit log event for graph mutations."""
        if not self.audit_logger:
            return
        try:
            event = AuditEvent(
                scan_id=f"GRAPH-{details.get('node_id') or details.get('source') or 'event'}",
                action_taken=Action.ALLOW,
                risk_score=0.0,
                max_severity=Severity.LOW,
                metadata={
                    "graph_event": event_type,
                    **details,
                },
            )
            self.audit_logger.emit(event)
        except Exception:
            pass
