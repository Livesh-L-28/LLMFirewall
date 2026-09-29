"""AttackGraph engine built on top of KnowledgeGraph for AI threat modeling and multi-step attack path analysis."""

from collections import deque
import hashlib
import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from llmfirewall.attack_graph.models import (
    AttackEvidence,
    AttackGraphDiff,
    AttackGraphSnapshot,
    AttackNode,
    AttackPath,
    AttackStep,
    ConfidenceLevel,
    ControlEffectiveness,
    EntryPoint,
    EntryPointType,
    EvidenceType,
    MitigationStatus,
    PathStatus,
    ThreatModel,
    TrustBoundary,
)
from llmfirewall.attack_graph.rules import AttackRuleRegistry, STANDARD_RULES
from llmfirewall.attack_graph.techniques import default_technique_registry
from llmfirewall.audit import AuditLogger
from llmfirewall.core.models import Action, AuditEvent, Severity
from llmfirewall.governance.findings import GovernanceFinding
from llmfirewall.graph.engine import KnowledgeGraph
from llmfirewall.graph.models import Node, NodeType, RelationshipType

logger = logging.getLogger("llmfirewall.attack_graph")


class AttackGraphMetrics:
    """Thread-safe bounded telemetry metrics for attack graph operations without unbounded asset labels."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.attack_path_queries_total = 0
        self.attack_paths_discovered_total = 0
        self.attack_paths_tested_total = 0
        self.attack_paths_observed_total = 0
        self.threat_models_created_total = 0
        self.attack_rule_evaluations_total = 0
        self.attack_rule_failures_total = 0

    def record_query(self, discovered_count: int = 0) -> None:
        with self._lock:
            self.attack_path_queries_total += 1
            self.attack_paths_discovered_total += discovered_count

    def record_tested(self, count: int = 1) -> None:
        with self._lock:
            self.attack_paths_tested_total += count

    def record_observed(self, count: int = 1) -> None:
        with self._lock:
            self.attack_paths_observed_total += count

    def record_threat_model(self) -> None:
        with self._lock:
            self.threat_models_created_total += 1

    def record_rule_eval(self, count: int = 1, failed: bool = False) -> None:
        with self._lock:
            self.attack_rule_evaluations_total += count
            if failed:
                self.attack_rule_failures_total += 1

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "attack_path_queries_total": self.attack_path_queries_total,
                "attack_paths_discovered_total": self.attack_paths_discovered_total,
                "attack_paths_tested_total": self.attack_paths_tested_total,
                "attack_paths_observed_total": self.attack_paths_observed_total,
                "threat_models_created_total": self.threat_models_created_total,
                "attack_rule_evaluations_total": self.attack_rule_evaluations_total,
                "attack_rule_failures_total": self.attack_rule_failures_total,
            }

    def reset(self) -> None:
        with self._lock:
            self.attack_path_queries_total = 0
            self.attack_paths_discovered_total = 0
            self.attack_paths_tested_total = 0
            self.attack_paths_observed_total = 0
            self.threat_models_created_total = 0
            self.attack_rule_evaluations_total = 0
            self.attack_rule_failures_total = 0


class AttackGraph:
    """Attack Graph layer orchestrating AI threat modeling, rule evaluation, and bounded path discovery.
    
    Invariants:
    - Never claim an attacker can definitely compromise a system from graph relationships alone.
    - Traversal is strictly bounded by max_depth, max_paths, max_nodes_visited, and timeout.
    - Graph cycles are detected and prevented during search.
    - Distinguishes CANDIDATE, SUPPORTED, TESTED, OBSERVED, BLOCKED, and INVALIDATED paths.
    - Caching is automatically invalidated upon graph or rule changes.
    """

    def __init__(
        self,
        kg: Optional[KnowledgeGraph] = None,
        rules_registry: Optional[AttackRuleRegistry] = None,
        graph_version: str = "1.0",
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        self.kg: KnowledgeGraph = kg if kg is not None else KnowledgeGraph()
        self.rules_registry: AttackRuleRegistry = (
            rules_registry if rules_registry is not None else AttackRuleRegistry()
        )
        self.graph_version = graph_version
        self.audit_logger = audit_logger
        self.metrics = AttackGraphMetrics()
        self._lock = threading.RLock()

        # Configured Entry Points and Trust Boundaries
        self._entry_points: Dict[str, EntryPoint] = {}
        self._trust_boundaries: Dict[str, TrustBoundary] = {}

        # Cache for discovered paths: cache_key -> List[AttackPath]
        self._path_cache: Dict[str, List[AttackPath]] = {}
        self._cached_kg_hash: str = ""

        # Auto-discover initial entry points and boundaries if any present
        self._auto_discover_components()

    # -------------------------------------------------------------------------
    # Audit & Telemetry
    # -------------------------------------------------------------------------

    def _emit_audit(self, event_type: str, details: Dict[str, Any]) -> None:
        """Safely record an audit event without crashing if logger is absent or fails."""
        if not self.audit_logger:
            return
        try:
            event = AuditEvent(
                scan_id=f"ATTACK-{details.get('path_id') or details.get('model_id') or 'event'}",
                action_taken=Action.ALLOW,
                risk_score=0.0,
                max_severity=Severity.LOW,
                metadata={
                    "attack_graph_event": event_type,
                    **details,
                },
            )
            self.audit_logger.emit(event)
        except Exception as exc:
            logger.warning("Failed to emit audit event %s: %s", event_type, exc)

    def invalidate_cache(self) -> None:
        """Clear cached attack path traversals."""
        with self._lock:
            self._path_cache.clear()
            self._cached_kg_hash = ""

    # -------------------------------------------------------------------------
    # Entry Points Management
    # -------------------------------------------------------------------------

    def register_entry_point(self, entry_point: EntryPoint) -> None:
        """Register a known system ingress channel."""
        with self._lock:
            self._entry_points[entry_point.entry_point_id] = entry_point
            self.invalidate_cache()

    def list_entry_points(self) -> List[EntryPoint]:
        """List all active entry points."""
        with self._lock:
            return list(self._entry_points.values())

    def get_entry_point(self, entry_point_id: str) -> Optional[EntryPoint]:
        """Retrieve entry point by ID."""
        with self._lock:
            return self._entry_points.get(entry_point_id)

    # -------------------------------------------------------------------------
    # Trust Boundaries Management
    # -------------------------------------------------------------------------

    def register_trust_boundary(self, boundary: TrustBoundary) -> None:
        """Register an architectural trust demarcation line."""
        with self._lock:
            self._trust_boundaries[boundary.boundary_id] = boundary
            self.invalidate_cache()

    def list_trust_boundaries(self) -> List[TrustBoundary]:
        """List all registered trust boundaries."""
        with self._lock:
            return list(self._trust_boundaries.values())

    def get_trust_boundary(self, boundary_id: str) -> Optional[TrustBoundary]:
        """Retrieve trust boundary by ID."""
        with self._lock:
            return self._trust_boundaries.get(boundary_id)

    # -------------------------------------------------------------------------
    # Auto-Discovery of Ingress & Boundaries
    # -------------------------------------------------------------------------

    def _auto_discover_components(self) -> None:
        """Heuristically populate entry points and trust boundaries from underlying KnowledgeGraph."""
        for node in self.kg.find_nodes():
            n_type = node.type.lower()
            props = node.properties or {}

            # Detect entry points
            if (
                n_type in (NodeType.APPLICATION.value, NodeType.PROMPT.value, "entry_point", "user")
                or props.get("entry_point") is True
                or props.get("ingress") is True
            ):
                ep_id = f"ep:{node.id}"
                if ep_id not in self._entry_points:
                    ep_type = EntryPointType.CHAT_INPUT
                    if "api" in node.id.lower() or "http" in node.id.lower():
                        ep_type = EntryPointType.HTTP_API
                    elif "doc" in node.id.lower() or "rag" in node.id.lower():
                        ep_type = EntryPointType.DOCUMENT_INGESTION
                    elif "file" in node.id.lower():
                        ep_type = EntryPointType.FILE_UPLOAD

                    self._entry_points[ep_id] = EntryPoint(
                        entry_point_id=ep_id,
                        name=props.get("name") or props.get("label") or node.id,
                        type=ep_type,
                        target_asset_id=node.id,
                        untrusted=True,
                        description=f"Auto-discovered ingress point for asset '{node.id}'.",
                    )

        # Detect trust boundaries from relationships
        for edge in self.kg.find_relationships():
            src_node = self.kg.get_node(edge.source)
            tgt_node = self.kg.get_node(edge.target)
            if not src_node or not tgt_node:
                continue

            # User -> Application / Agent
            if src_node.type in ("user", NodeType.APPLICATION.value) and tgt_node.type == NodeType.AGENT.value:
                b_id = f"tb:{src_node.id}_to_{tgt_node.id}"
                if b_id not in self._trust_boundaries:
                    self._trust_boundaries[b_id] = TrustBoundary(
                        boundary_id=b_id,
                        name=f"Ingress Boundary: {src_node.id} -> {tgt_node.id}",
                        source_entity=src_node.id,
                        target_entity=tgt_node.id,
                        trust_level_from="untrusted",
                        trust_level_to="trusted_execution",
                        description="External prompt input to privileged agent execution boundary.",
                    )

            # Agent -> Tool
            elif src_node.type == NodeType.AGENT.value and tgt_node.type == NodeType.TOOL.value:
                b_id = f"tb:{src_node.id}_to_{tgt_node.id}"
                if b_id not in self._trust_boundaries:
                    self._trust_boundaries[b_id] = TrustBoundary(
                        boundary_id=b_id,
                        name=f"Action Boundary: {src_node.id} -> {tgt_node.id}",
                        source_entity=src_node.id,
                        target_entity=tgt_node.id,
                        trust_level_from="agent_reasoning",
                        trust_level_to="external_side_effects",
                        description="Agent reasoning to external tool side-effect invocation boundary.",
                    )

    # -------------------------------------------------------------------------
    # Path Discovery Engine
    # -------------------------------------------------------------------------

    def find_paths(
        self,
        source: Optional[str] = None,
        target: Optional[str] = None,
        max_depth: int = 5,
        max_paths: int = 100,
        max_nodes_visited: int = 5000,
        timeout: float = 10.0,
        filter_status: Optional[PathStatus] = None,
    ) -> List[AttackPath]:
        """Discover bounded multi-step attack paths across graph components.
        
        Args:
            source: Optional starting asset ID or entry point ID. If None, all entry points are used.
            target: Optional target asset ID. If specified, only paths ending at target are returned.
            max_depth: Maximum hop depth allowed (default 5).
            max_paths: Hard limit on total paths returned (default 100).
            max_nodes_visited: Traversal budget cap (default 5000).
            timeout: Maximum search duration in seconds (default 10.0).
            filter_status: Optional status filter.
            
        Returns:
            List of deduplicated, evidence-backed AttackPath objects.
        """
        # Validate arguments to prevent unbounded traversal
        max_depth = max(1, min(max_depth, 20))
        max_paths = max(1, min(max_paths, 1000))
        max_nodes_visited = max(10, min(max_nodes_visited, 50000))
        timeout = max(0.1, min(timeout, 60.0))

        start_time = time.time()

        # Cache key construction
        cache_key = f"{source}:{target}:{max_depth}:{max_paths}:{filter_status}"
        with self._lock:
            # Check if underlying knowledge graph has changed
            current_kg_hash = self.kg.snapshot().graph_hash
            if self._cached_kg_hash == current_kg_hash and cache_key in self._path_cache:
                cached = self._path_cache[cache_key]
                self.metrics.record_query(len(cached))
                return cached

        # Auto-discover newly added nodes as entry points if necessary
        self._auto_discover_components()

        # Resolve starting origins
        origins: List[str] = []
        if source:
            # If source is an entry point ID, resolve its target asset
            if source in self._entry_points:
                origins.append(self._entry_points[source].target_asset_id)
            else:
                # Direct asset node ID
                origins.append(source)
        else:
            # Ingress from all discovered entry points or root nodes
            if self._entry_points:
                origins = [ep.target_asset_id for ep in self._entry_points.values()]
            else:
                origins = [n.id for n in self.kg.find_nodes()]

        # Deduplicate origins and verify existence in KnowledgeGraph
        valid_origins = [o for o in set(origins) if self.kg.get_node(o) is not None]

        discovered_paths: Dict[str, AttackPath] = {}
        nodes_visited = 0

        # Traversal queue: (current_node_id, [AttackStep], set_of_visited_node_ids, origin_id)
        queue: deque[Tuple[str, List[AttackStep], Set[str], str]] = deque()

        for origin in valid_origins:
            queue.append((origin, [], {origin}, origin))

        # Bounded BFS Traversal
        while queue:
            # Check resource constraints
            if nodes_visited >= max_nodes_visited or (time.time() - start_time) > timeout:
                break
            if len(discovered_paths) >= max_paths:
                break

            current_id, current_steps, visited, origin_id = queue.popleft()
            nodes_visited += 1

            current_node = self.kg.get_node(current_id)
            if not current_node:
                continue

            # Inspect outgoing edges from current node
            out_edges = self.kg.store.get_out_edges(current_id)
            for edge in out_edges:
                neighbor_id = edge.target

                # Cycle Prevention: Do not revisit nodes already in current chain
                if neighbor_id in visited:
                    continue

                neighbor_node = self.kg.get_node(neighbor_id)
                if not neighbor_node:
                    continue

                # Evaluate inference rules across this hop
                try:
                    candidate_steps = self.rules_registry.evaluate_hop(
                        self.kg, current_node, neighbor_node
                    )
                    self.metrics.record_rule_eval(len(candidate_steps), failed=False)
                except Exception as exc:
                    logger.warning("Error evaluating hop %s -> %s: %s", current_id, neighbor_id, exc)
                    self.metrics.record_rule_eval(1, failed=True)
                    continue

                if not candidate_steps:
                    continue

                for step in candidate_steps:
                    new_steps = current_steps + [step]
                    new_visited = visited | {neighbor_id}

                    # Determine if this step sequence forms an attack path
                    is_target_match = (target is not None and neighbor_id == target)
                    is_general_path = (target is None and len(new_steps) >= 1)

                    if is_target_match or is_general_path:
                        path = self._construct_path(origin_id, neighbor_id, new_steps)
                        if filter_status is None or path.status == filter_status:
                            discovered_paths[path.path_id] = path

                        if len(discovered_paths) >= max_paths:
                            break

                    # Continue expanding if within depth bounds and not reached final target
                    if len(new_steps) < max_depth:
                        if target is None or neighbor_id != target:
                            queue.append((neighbor_id, new_steps, new_visited, origin_id))

        results = list(discovered_paths.values())

        # Update cache and metrics
        with self._lock:
            self._cached_kg_hash = current_kg_hash
            self._path_cache[cache_key] = results
            self.metrics.record_query(len(results))

            for p in results:
                self._emit_audit(
                    "ATTACK_PATH_DISCOVERED",
                    {
                        "path_id": p.path_id,
                        "source": p.source,
                        "target": p.target,
                        "status": p.status.value,
                        "length": p.length,
                    },
                )

        return results

    def _construct_path(
        self,
        source: str,
        target: str,
        steps: List[AttackStep],
    ) -> AttackPath:
        """Construct AttackPath, calculating overall mitigation status, confidence, and verification state."""
        # 1. Determine overall mitigation status
        all_mitigated = True
        any_mitigated = False
        all_unmitigated = True

        for s in steps:
            if s.mitigation_status == MitigationStatus.MITIGATED:
                any_mitigated = True
                all_unmitigated = False
            elif s.mitigation_status == MitigationStatus.UNMITIGATED:
                all_mitigated = False
            else:
                all_mitigated = False
                all_unmitigated = False

        if all_mitigated and steps:
            path_mitigation = MitigationStatus.MITIGATED
        elif all_unmitigated:
            path_mitigation = MitigationStatus.UNMITIGATED
        elif any_mitigated:
            path_mitigation = MitigationStatus.PARTIALLY_MITIGATED
        else:
            path_mitigation = MitigationStatus.UNKNOWN

        # 2. Determine path status
        # If fully mitigated by effective controls, path is BLOCKED
        if path_mitigation == MitigationStatus.MITIGATED:
            path_status = PathStatus.BLOCKED
        else:
            # Check if all preconditions strictly supported by graph relationships
            has_graph_evidence = all(len(s.evidence) > 0 for s in steps)
            path_status = PathStatus.SUPPORTED if has_graph_evidence else PathStatus.CANDIDATE

        # 3. Aggregate evidence, mitigations, and assumptions
        aggregated_evidence: List[AttackEvidence] = []
        aggregated_mitigations: List[str] = []
        aggregated_assumptions: List[str] = []

        for s in steps:
            aggregated_evidence.extend(s.evidence)
            aggregated_mitigations.extend(s.mitigations)
            aggregated_assumptions.extend(s.assumptions)

        # 4. Confidence derivation
        # Highest confidence step dictates or averages
        if any(s.confidence == ConfidenceLevel.HIGH for s in steps):
            confidence = ConfidenceLevel.HIGH
        elif any(s.confidence == ConfidenceLevel.MEDIUM for s in steps):
            confidence = ConfidenceLevel.MEDIUM
        else:
            confidence = ConfidenceLevel.LOW

        return AttackPath.create(
            source=source,
            target=target,
            steps=steps,
            status=path_status,
            evidence=aggregated_evidence,
            mitigations=sorted(list(set(aggregated_mitigations))),
            mitigation_status=path_mitigation,
            assumptions=sorted(list(set(aggregated_assumptions))),
            confidence=confidence,
        )

    # -------------------------------------------------------------------------
    # Multi-Step Test Results Ingestion (Phase 30 Integration)
    # -------------------------------------------------------------------------

    def ingest_test_results(
        self,
        test_results: List[Dict[str, Any]],
    ) -> List[AttackPath]:
        """Corroborate candidate attack paths using Phase 30 automated security test results.
        
        If automated tests verify the execution of each step in a chain:
        - Path status transitions to TESTED.
        - Verified test evidence is recorded.
        - Confidence elevates to HIGH.
        """
        all_paths = self.find_paths(max_depth=5)
        tested_paths: List[AttackPath] = []

        for path in all_paths:
            # Check if all steps in this path have corresponding successful test evidence
            steps_tested = 0
            new_steps: List[AttackStep] = []

            for step in path.steps:
                # Look for matching test result covering this technique or hop
                matching_test = None
                for tr in test_results:
                    t_tech = tr.get("technique") or tr.get("test_id", "")
                    target_match = tr.get("target") == step.target or not tr.get("target")
                    if (t_tech == step.technique or step.technique in t_tech) and target_match:
                        matching_test = tr
                        break

                if matching_test and matching_test.get("passed") is True:
                    steps_tested += 1
                    test_evidence = AttackEvidence(
                        evidence_type=EvidenceType.TEST,
                        source_id=str(matching_test.get("test_id", "security-test")),
                        description=f"Automated test confirmed execution of technique {step.technique} against {step.target}.",
                        verified=True,
                        metadata=matching_test,
                    )
                    updated_step = AttackStep(
                        step_id=step.step_id,
                        technique=step.technique,
                        technique_name=step.technique_name,
                        source=step.source,
                        target=step.target,
                        preconditions=step.preconditions,
                        postconditions=step.postconditions,
                        evidence=step.evidence + [test_evidence],
                        confidence=ConfidenceLevel.HIGH,
                        mitigations=step.mitigations,
                        mitigation_status=step.mitigation_status,
                        assumptions=step.assumptions,
                    )
                    new_steps.append(updated_step)
                else:
                    new_steps.append(step)

            # Only transition to TESTED if all steps in chain were demonstrated
            if steps_tested == len(path.steps) and len(path.steps) > 0:
                tested_path = AttackPath.create(
                    source=path.source,
                    target=path.target,
                    steps=new_steps,
                    status=PathStatus.TESTED,
                    evidence=path.evidence + [
                        AttackEvidence(
                            evidence_type=EvidenceType.TEST,
                            source_id="test-suite-corroboration",
                            description="All multi-step attack hops confirmed by automated test suite.",
                            verified=True,
                        )
                    ],
                    mitigations=path.mitigations,
                    mitigation_status=path.mitigation_status,
                    assumptions=path.assumptions,
                    confidence=ConfidenceLevel.HIGH,
                )
                tested_paths.append(tested_path)
                self.metrics.record_tested(1)
                self._emit_audit(
                    "ATTACK_PATH_TESTED",
                    {"path_id": tested_path.path_id, "steps_count": len(tested_path.steps)},
                )

        self.invalidate_cache()
        return tested_paths

    # -------------------------------------------------------------------------
    # Observed Runtime Events Ingestion (Telemetry Integration)
    # -------------------------------------------------------------------------

    def ingest_runtime_events(
        self,
        events: List[Dict[str, Any]],
    ) -> List[AttackPath]:
        """Identify confirmed multi-step attack paths observed in production telemetry events.
        
        Transitions path status to OBSERVED with verbatim event references.
        """
        all_paths = self.find_paths(max_depth=5)
        observed_paths: List[AttackPath] = []

        for path in all_paths:
            # Check if event sequence correlates with path techniques
            event_techniques = [e.get("technique") or e.get("event_type") for e in events]
            path_techniques = path.technique_sequence

            # Subsequence match
            it = iter(event_techniques)
            if all(any(tech in item for item in it if item) for tech in path_techniques):
                obs_evidence = [
                    AttackEvidence(
                        evidence_type=EvidenceType.RUNTIME,
                        source_id=str(e.get("event_id", f"evt-{idx}")),
                        description=f"Runtime security telemetry observed event: {e.get('event_type')}",
                        verified=True,
                        metadata={"timestamp": e.get("timestamp")},
                    )
                    for idx, e in enumerate(events)
                ]

                obs_path = AttackPath.create(
                    source=path.source,
                    target=path.target,
                    steps=path.steps,
                    status=PathStatus.OBSERVED,
                    evidence=path.evidence + obs_evidence,
                    mitigations=path.mitigations,
                    mitigation_status=path.mitigation_status,
                    assumptions=path.assumptions,
                    confidence=ConfidenceLevel.HIGH,
                )
                observed_paths.append(obs_path)
                self.metrics.record_observed(1)
                self._emit_audit(
                    "ATTACK_PATH_OBSERVED",
                    {"path_id": obs_path.path_id, "event_count": len(events)},
                )

        return observed_paths

    # -------------------------------------------------------------------------
    # Threat Modeling Engine
    # -------------------------------------------------------------------------

    def generate_threat_model(
        self,
        asset_id: Optional[str] = None,
        name: Optional[str] = None,
    ) -> ThreatModel:
        """Synthesize a complete AI Threat Model for an asset or the full architecture.
        
        Args:
            asset_id: Optional root asset ID (e.g. agent or application). If None, system-wide.
            name: Human-readable threat model name.
        """
        self._auto_discover_components()

        # Identify in-scope assets
        if asset_id:
            # Include asset_id and all reachable connected nodes up to radius 3
            reachable_ids = {asset_id}
            queue = deque([(asset_id, 0)])
            while queue:
                curr, dist = queue.popleft()
                if dist >= 3:
                    continue
                for edge in self.kg.store.get_out_edges(curr):
                    if edge.target not in reachable_ids:
                        reachable_ids.add(edge.target)
                        queue.append((edge.target, dist + 1))
                for edge in self.kg.store.get_in_edges(curr):
                    if edge.source not in reachable_ids:
                        reachable_ids.add(edge.source)
                        queue.append((edge.source, dist + 1))
            target_assets = sorted(list(reachable_ids))
        else:
            target_assets = sorted([n.id for n in self.kg.find_nodes()])

        # Discover paths targeting or originating from these assets
        paths = self.find_paths(max_depth=5)
        in_scope_paths = [
            p for p in paths
            if p.source in target_assets or p.target in target_assets
        ]

        # Filter entry points and trust boundaries
        in_scope_eps = [
            ep for ep in self.list_entry_points()
            if ep.target_asset_id in target_assets
        ]
        in_scope_tbs = [
            tb for tb in self.list_trust_boundaries()
            if tb.source_entity in target_assets or tb.target_entity in target_assets
        ]

        # Gather active security controls protecting in-scope assets
        controls: Set[str] = set()
        for a_id in target_assets:
            for edge in self.kg.store.get_in_edges(a_id):
                if edge.type in (RelationshipType.PROTECTS.value, "PROTECTED_BY"):
                    controls.add(edge.source)
            for edge in self.kg.store.get_out_edges(a_id):
                if edge.type in (RelationshipType.PROTECTED_BY.value, "PROTECTED_BY"):
                    controls.add(edge.target)

        # Collect assumptions
        assumptions: Set[str] = set()
        for p in in_scope_paths:
            assumptions.update(p.assumptions)

        # Count unmitigated security gaps
        unmitigated_count = sum(
            1 for p in in_scope_paths
            if p.mitigation_status == MitigationStatus.UNMITIGATED
        )

        model_name = name or (f"Threat Model: {asset_id}" if asset_id else "AI Architecture Threat Model")

        tm = ThreatModel(
            name=model_name,
            version=self.graph_version,
            assets=target_assets,
            entry_points=in_scope_eps,
            trust_boundaries=in_scope_tbs,
            attack_paths=in_scope_paths,
            security_controls=sorted(list(controls)),
            assumptions=sorted(list(assumptions)),
            security_gaps_count=unmitigated_count,
        )

        self.metrics.record_threat_model()
        self._emit_audit(
            "THREAT_MODEL_CREATED",
            {
                "model_id": tm.model_id,
                "name": tm.name,
                "assets_count": len(tm.assets),
                "paths_count": len(tm.attack_paths),
                "gaps_count": tm.security_gaps_count,
            },
        )
        return tm

    # -------------------------------------------------------------------------
    # Governance & Security Gap Findings (Phase 31 Integration)
    # -------------------------------------------------------------------------

    def extract_security_gaps(
        self,
        paths: Optional[List[AttackPath]] = None,
    ) -> List[GovernanceFinding]:
        """Convert unmitigated candidate attack paths into actionable GovernanceFinding objects."""
        candidate_paths = paths if paths is not None else self.find_paths(max_depth=5)
        findings: List[GovernanceFinding] = []

        for path in candidate_paths:
            if path.mitigation_status == MitigationStatus.UNMITIGATED and path.status != PathStatus.BLOCKED:
                hops_str = " -> ".join(path.node_sequence)
                techs_str = ", ".join(path.technique_sequence)
                finding = GovernanceFinding.from_test_finding(
                    category="ATTACK_SURFACE_SECURITY_GAP",
                    severity=Severity.HIGH,
                    description=(
                        f"Unmitigated potential attack path '{path.path_id}' from '{path.source}' to '{path.target}'. "
                        f"Sequence: {hops_str}. Techniques: [{techs_str}]. Assumptions: {'; '.join(path.assumptions)}."
                    ),
                    rule_id=f"GAP-{path.path_id}",
                    resource=path.target,
                    metadata={
                        "path_id": path.path_id,
                        "source": path.source,
                        "target": path.target,
                        "length": path.length,
                        "technique_sequence": path.technique_sequence,
                        "assumptions": path.assumptions,
                    },
                )
                findings.append(finding)

        return findings

    # -------------------------------------------------------------------------
    # Snapshots & Diffs (Baselines & Drift Integration)
    # -------------------------------------------------------------------------

    def snapshot(self, graph_version: Optional[str] = None) -> AttackGraphSnapshot:
        """Create a tamper-evident, canonical snapshot of all attack paths, entry points, and boundaries."""
        paths = self.find_paths(max_depth=5)
        eps = self.list_entry_points()
        tbs = self.list_trust_boundaries()
        kg_hash = self.kg.snapshot().graph_hash

        version = graph_version or self.graph_version
        return AttackGraphSnapshot.create(
            paths=paths,
            entry_points=eps,
            trust_boundaries=tbs,
            source_graph_hash=kg_hash,
            graph_version=version,
            rules_version=self.rules_registry.rules_version,
        )

    @staticmethod
    def diff(
        previous: AttackGraphSnapshot,
        current: AttackGraphSnapshot,
    ) -> AttackGraphDiff:
        """Compute the architectural security drift between two attack graph snapshots."""
        prev_paths = {p.path_id: p for p in previous.paths}
        curr_paths = {p.path_id: p for p in current.paths}

        prev_path_ids = set(prev_paths.keys())
        curr_path_ids = set(curr_paths.keys())

        added = sorted(list(curr_path_ids - prev_path_ids))
        removed = sorted(list(prev_path_ids - curr_path_ids))

        changed: List[str] = []
        for p_id in curr_path_ids.intersection(prev_path_ids):
            p1 = prev_paths[p_id]
            p2 = curr_paths[p_id]
            if (
                p1.status != p2.status
                or p1.mitigation_status != p2.mitigation_status
                or p1.confidence != p2.confidence
                or set(p1.mitigations) != set(p2.mitigations)
            ):
                changed.append(p_id)

        # New entry points
        prev_eps = {e.entry_point_id for e in previous.entry_points}
        curr_eps = {e.entry_point_id for e in current.entry_points}
        new_eps = sorted(list(curr_eps - prev_eps))

        # New techniques
        prev_techs = {
            tech
            for p in previous.paths
            for tech in p.technique_sequence
        }
        curr_techs = {
            tech
            for p in current.paths
            for tech in p.technique_sequence
        }
        new_techs = sorted(list(curr_techs - prev_techs))

        # New trust boundaries
        prev_tbs = {b.boundary_id for b in previous.trust_boundaries}
        curr_tbs = {b.boundary_id for b in current.trust_boundaries}
        new_tbs = sorted(list(curr_tbs - prev_tbs))

        is_identical = (
            not added
            and not removed
            and not changed
            and not new_eps
            and not new_techs
            and not new_tbs
        )

        return AttackGraphDiff(
            paths_added=added,
            paths_removed=removed,
            paths_changed=sorted(changed),
            new_entry_points=new_eps,
            new_techniques=new_techs,
            new_trust_boundaries=new_tbs,
            is_identical=is_identical,
        )

    def recalculate_on_drift(
        self,
        new_node_ids: Optional[List[str]] = None,
        new_edge_keys: Optional[List[str]] = None,
    ) -> List[AttackPath]:
        """Invalidate cache and recalculate attack paths when architectural drift is detected."""
        self.invalidate_cache()
        affected_paths: List[AttackPath] = []
        all_paths = self.find_paths(max_depth=5)

        if not new_node_ids and not new_edge_keys:
            return all_paths

        affected_nodes = set(new_node_ids or [])
        for edge_key in (new_edge_keys or []):
            parts = edge_key.split("->")
            if len(parts) == 2:
                affected_nodes.add(parts[0].strip())
                affected_nodes.add(parts[1].strip())

        for p in all_paths:
            if any(node_id in affected_nodes for node_id in p.node_sequence):
                affected_paths.append(p)

        return affected_paths
