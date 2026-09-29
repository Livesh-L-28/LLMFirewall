"""Data models, node and relationship representations for AI Security Knowledge Graph (Phase 32)."""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field, field_validator


class NodeType(str, Enum):
    """Standardized controlled taxonomy of knowledge graph node classifications."""
    APPLICATION = "application"
    MODEL = "model"
    AGENT = "agent"
    TOOL = "tool"
    PROMPT = "prompt"
    POLICY = "policy"
    SECURITY_CONTROL = "security_control"
    RAG_SOURCE = "rag_source"
    DOCUMENT = "document"
    DEPENDENCY = "dependency"
    FINDING = "finding"
    THREAT = "threat"
    ATTACK_TECHNIQUE = "attack_technique"
    SECURITY_TEST = "security_test"
    BASELINE = "baseline"
    RELEASE = "release"
    INCIDENT = "incident"
    CONFIGURATION = "configuration"
    CAPABILITY = "capability"
    CUSTOM = "custom"


class RelationshipType(str, Enum):
    """Controlled taxonomy of directed security graph relationships."""
    USES = "USES"
    CALLS = "CALLS"
    CAN_ACCESS = "CAN_ACCESS"
    CAN_CALL = "CAN_CALL"
    GOVERNED_BY = "GOVERNED_BY"
    GOVERNS = "GOVERNS"
    PROTECTED_BY = "PROTECTED_BY"
    PROTECTS = "PROTECTS"
    DEPENDS_ON = "DEPENDS_ON"
    CONTAINS = "CONTAINS"
    GENERATED_FROM = "GENERATED_FROM"
    DERIVED_FROM = "DERIVED_FROM"
    TESTED_BY = "TESTED_BY"
    TESTS = "TESTS"
    HAS_FINDING = "HAS_FINDING"
    AFFECTS = "AFFECTS"
    MITIGATED_BY = "MITIGATED_BY"
    MITIGATES = "MITIGATES"
    DETECTS = "DETECTS"
    PRODUCES = "PRODUCES"
    INVOLVES = "INVOLVES"
    BLOCKED_BY = "BLOCKED_BY"
    DEPLOYED_AS = "DEPLOYED_AS"
    PART_OF = "PART_OF"
    PRECEDES = "PRECEDES"
    TRIGGERS = "TRIGGERS"
    RELATED_TO = "RELATED_TO"
    SNAPSHOT_OF = "SNAPSHOT_OF"
    CUSTOM = "CUSTOM"


class Node(BaseModel):
    """Normalized, immutable entity node within the security knowledge graph.
    
    Invariants:
    1. Stable Identifiers: Deterministic node IDs based on domain entities (e.g. 'agent:support_agent').
    2. Zero Secrets: Properties strictly store non-secret metadata, hashes, versions, and identifiers.
    3. Extensibility: Supports standard and custom registered node types.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(..., min_length=1, max_length=256, description="Stable, unique entity identifier.")
    type: str = Field(default=NodeType.CUSTOM.value, description="Classification type of node entity.")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Safe metadata attributes (no secrets).")
    created_at: float = Field(default_factory=time.time, description="Creation epoch timestamp.")
    updated_at: float = Field(default_factory=time.time, description="Last update epoch timestamp.")

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Node ID cannot be empty or whitespace.")
        return clean

    @field_validator("type")
    @classmethod
    def normalize_type(cls, v: str) -> str:
        clean = v.strip().lower()
        if not clean:
            raise ValueError("Node type cannot be empty.")
        return clean

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class Relationship(BaseModel):
    """Normalized directed relationship connecting two entities in the knowledge graph.
    
    Invariants:
    1. Referential Integrity: Source and target must reference existing valid Node IDs.
    2. Deterministic Key: Unique combination of (source, type, target) prevents duplicate edges.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str = Field(..., min_length=1, max_length=256, description="Originating node ID.")
    type: str = Field(..., min_length=1, max_length=64, description="Relationship type verb (e.g. 'USES', 'CAN_CALL').")
    target: str = Field(..., min_length=1, max_length=256, description="Destination node ID.")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Relationship metadata (e.g. permissions, timestamp).")
    created_at: float = Field(default_factory=time.time, description="Creation epoch timestamp.")

    @field_validator("type")
    @classmethod
    def normalize_type(cls, v: str) -> str:
        clean = v.strip().upper()
        if not clean:
            raise ValueError("Relationship type cannot be empty.")
        return clean

    @property
    def edge_key(self) -> str:
        """Deterministic unique tuple key for deduplication."""
        return f"{self.source}|{self.type}|{self.target}"

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class GraphPath(BaseModel):
    """A bounded directed path connecting a source node to a target node through the graph."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    source_id: str = Field(..., description="Starting node ID.")
    target_id: str = Field(..., description="Terminal node ID.")
    nodes: List[str] = Field(default_factory=list, description="Ordered sequence of node IDs along path.")
    relationships: List[str] = Field(default_factory=list, description="Ordered sequence of relationship types along path.")
    length: int = Field(default=0, ge=0, description="Path hop count.")

    @property
    def source(self) -> str:
        return self.source_id

    @property
    def target(self) -> str:
        return self.target_id


class GraphSnapshot(BaseModel):
    """Tamper-evident, serializable snapshot of the entire security knowledge graph."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(default="1.0.0", description="Snapshot schema version.")
    graph_version: str = Field(default="1.0", description="Version of graph state.")
    timestamp: float = Field(default_factory=time.time, description="Capture epoch timestamp.")
    node_count: int = Field(default=0, ge=0, description="Total nodes captured.")
    relationship_count: int = Field(default=0, ge=0, description="Total relationships captured.")
    nodes: List[Node] = Field(default_factory=list, description="All graph nodes.")
    relationships: List[Relationship] = Field(default_factory=list, description="All graph relationships.")
    graph_hash: str = Field(default="", description="Cryptographic SHA-256 digest over canonicalized graph.")

    @classmethod
    def create(
        cls,
        nodes: List[Node],
        relationships: List[Relationship],
        graph_version: str = "1.0",
        timestamp: Optional[float] = None,
    ) -> "GraphSnapshot":
        """Factory computing the deterministic graph_hash over canonical representation."""
        now = timestamp if timestamp is not None else time.time()
        sorted_nodes = sorted(nodes, key=lambda n: n.id)
        sorted_edges = sorted(relationships, key=lambda r: r.edge_key)

        canonical = {
            "schema_version": "1.0.0",
            "graph_version": graph_version,
            "nodes": [
                {"id": n.id, "type": n.type, "properties": n.properties}
                for n in sorted_nodes
            ],
            "relationships": [
                {"source": r.source, "type": r.type, "target": r.target, "properties": r.properties}
                for r in sorted_edges
            ],
        }
        serialized = json.dumps(canonical, sort_keys=True)
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        return cls(
            schema_version="1.0.0",
            graph_version=graph_version,
            timestamp=now,
            node_count=len(sorted_nodes),
            relationship_count=len(sorted_edges),
            nodes=sorted_nodes,
            relationships=sorted_edges,
            graph_hash=digest,
        )

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.model_dump(mode="json"), indent=indent, sort_keys=True)


class GraphDiff(BaseModel):
    """Detailed structural difference between two graph snapshots."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    nodes_added: List[str] = Field(default_factory=list, description="IDs of added nodes.")
    nodes_removed: List[str] = Field(default_factory=list, description="IDs of removed nodes.")
    nodes_changed: List[str] = Field(default_factory=list, description="IDs of nodes whose properties were modified.")
    relationships_added: List[str] = Field(default_factory=list, description="Edge keys of added relationships.")
    relationships_removed: List[str] = Field(default_factory=list, description="Edge keys of removed relationships.")
    is_identical: bool = Field(default=False, description="True if graphs are structurally identical.")

    def summary(self) -> Dict[str, Any]:
        return {
            "is_identical": self.is_identical,
            "nodes_added_count": len(self.nodes_added),
            "nodes_removed_count": len(self.nodes_removed),
            "nodes_changed_count": len(self.nodes_changed),
            "relationships_added_count": len(self.relationships_added),
            "relationships_removed_count": len(self.relationships_removed),
        }


class SecurityDiff(BaseModel):
    """Curated security-relevant changes between graph states for release assurance and drift analysis."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    new_tool_access: List[Dict[str, str]] = Field(default_factory=list, description="Newly granted tool access relations.")
    new_capabilities: List[str] = Field(default_factory=list, description="New agent capability nodes.")
    model_changes: List[Dict[str, str]] = Field(default_factory=list, description="Model swaps or version changes.")
    new_dependencies: List[str] = Field(default_factory=list, description="New software dependencies introduced.")
    new_policies: List[str] = Field(default_factory=list, description="New security policies governing assets.")
    new_findings: List[str] = Field(default_factory=list, description="New security findings attached to assets.")
    removed_controls: List[str] = Field(default_factory=list, description="Security controls that were removed.")
    has_security_impact: bool = Field(default=False, description="True if any security-critical changes occurred.")

    @property
    def new_tool_ids(self) -> List[str]:
        return [item.get("target", "") for item in self.new_tool_access]


class SecurityImpactResult(BaseModel):
    """Security impact analysis identifying all related security context around an asset."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    asset_id: str = Field(..., description="Target asset node ID.")
    asset_type: str = Field(..., description="Classification of target asset.")
    findings: List[str] = Field(default_factory=list, description="Security finding IDs.")
    controls: List[str] = Field(default_factory=list, description="Security control IDs.")
    policies: List[str] = Field(default_factory=list, description="Governing policy IDs.")
    tests: List[str] = Field(default_factory=list, description="Evaluating test IDs.")
    threats: List[str] = Field(default_factory=list, description="Targeting threat and attack IDs.")
    dependencies: List[str] = Field(default_factory=list, description="Underlying dependency IDs.")
    finding_details: List[Dict[str, Any]] = Field(default_factory=list)
    control_details: List[Dict[str, Any]] = Field(default_factory=list)
    policy_details: List[Dict[str, Any]] = Field(default_factory=list)
    test_details: List[Dict[str, Any]] = Field(default_factory=list)
    threat_details: List[Dict[str, Any]] = Field(default_factory=list)
    dependency_details: List[Dict[str, Any]] = Field(default_factory=list)
    directly_connected_count: int = Field(default=0, ge=0)
    total_impact_count: int = Field(default=0, ge=0)


class BlastRadiusResult(BaseModel):
    """Outward blast radius analysis measuring cascading exposure when an asset changes or is compromised."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    source_asset_id: str = Field(..., description="Originating asset ID.")
    source_asset_type: str = Field(..., description="Originating asset type.")
    impacted_applications: List[str] = Field(default_factory=list)
    impacted_agents: List[str] = Field(default_factory=list)
    impacted_tools: List[str] = Field(default_factory=list)
    impacted_models: List[str] = Field(default_factory=list)
    impacted_policies: List[str] = Field(default_factory=list)
    impacted_findings: List[str] = Field(default_factory=list)
    total_impacted_nodes: int = Field(default=0, ge=0)
    max_depth_reached: int = Field(default=0, ge=0)
    propagation_paths: List[GraphPath] = Field(default_factory=list)

    @property
    def source_id(self) -> str:
        return self.source_asset_id

    @property
    def total_reached(self) -> int:
        return self.total_impacted_nodes

    @property
    def reachable_assets(self) -> List[str]:
        return sorted(list(set(self.impacted_applications + self.impacted_agents + self.impacted_tools + self.impacted_models)))

    @property
    def governing_policies(self) -> List[str]:
        return self.impacted_policies

    @property
    def associated_findings(self) -> List[str]:
        return self.impacted_findings


class ChangeImpactResult(BaseModel):
    """Result of change impact analysis identifying affected assets and required tests."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    changed_node: str = Field(..., description="ID of node that changed.")
    affected_assets: List[str] = Field(default_factory=list, description="Downstream assets affected.")
    required_tests: List[str] = Field(default_factory=list, description="Security tests requiring execution.")

    def __iter__(self):
        return iter(self.affected_assets)

    def __len__(self) -> int:
        return len(self.affected_assets)


class PolicyImpactResult(BaseModel):
    """Assets, controls, and tests governed or impacted by a policy."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    policy_id: str = Field(..., description="Target policy ID.")
    affected_agents: List[str] = Field(default_factory=list)
    affected_models: List[str] = Field(default_factory=list)
    affected_tools: List[str] = Field(default_factory=list)
    security_controls: List[str] = Field(default_factory=list)
    affected_tests: List[str] = Field(default_factory=list)
    affected_findings: List[str] = Field(default_factory=list)

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)


class FindingImpactResult(BaseModel):
    """Assets and controls affected by a security finding."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str = Field(..., description="Target finding ID.")
    affected_assets: List[str] = Field(default_factory=list)
    mitigating_controls: List[str] = Field(default_factory=list)

    def __iter__(self):
        return iter(self.affected_assets)

    def __len__(self) -> int:
        return len(self.affected_assets)


class ControlStatus(str, Enum):
    """Verified operational status of a security control protecting an asset."""
    CONFIGURED = "configured"
    TESTED = "tested"
    PASSING = "passing"
    FAILING = "failing"
    UNKNOWN = "unknown"


class ControlCoverageItem(BaseModel):
    """Status assessment for an individual security control."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    control_id: str = Field(...)
    control_name: str = Field(...)
    status: ControlStatus = Field(default=ControlStatus.UNKNOWN)
    verified_by_test: Optional[str] = Field(default=None)
    evidence: Optional[str] = Field(default=None)

    @property
    def evidence_test(self) -> Optional[str]:
        return self.verified_by_test


class ControlCoverageResult(BaseModel):
    """Evidence-based security control coverage report for an asset (no fake coverage)."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    asset_id: str = Field(...)
    asset_type: str = Field(...)
    controls: List[ControlCoverageItem] = Field(default_factory=list)
    total_controls: int = Field(default=0, ge=0)
    passing_controls: int = Field(default=0, ge=0)
    failing_controls: int = Field(default=0, ge=0)
    coverage_rate: float = Field(default=0.0, ge=0.0, le=1.0)
