"""Domain models and schemas for Phase 33 — Attack Graph & AI Threat Modeling."""

from enum import Enum
import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Set
import uuid
from pydantic import BaseModel, ConfigDict, Field, field_validator


class PathStatus(str, Enum):
    """Explicit verification state of an attack path.
    
    Invariants:
    - Never claim an attacker can definitely compromise a system based solely on graph structure.
    - Status must be evidence-derived.
    """
    CANDIDATE = "CANDIDATE"      # Plausible based on topology and potential missing controls
    SUPPORTED = "SUPPORTED"      # Graph relationships and strict preconditions verified
    TESTED = "TESTED"            # Multi-step execution verified by automated security tests
    OBSERVED = "OBSERVED"        # Sequence confirmed by runtime telemetry events
    BLOCKED = "BLOCKED"          # Fully mitigated or prevented by passing security controls
    INVALIDATED = "INVALIDATED"  # Preconditions refuted or architectural change broke path


class EvidenceType(str, Enum):
    """Categorization of evidence supporting an attack step or path."""
    GRAPH = "GRAPH"                      # Structural relationship in security knowledge graph
    TEST = "TEST"                        # Security evaluation or red-team test outcome
    RUNTIME = "RUNTIME"                  # Runtime telemetry or observability security event
    CONFIGURATION = "CONFIGURATION"      # Snapshot or configuration verification
    POLICY = "POLICY"                    # Policy rule or missing guardrail specification
    FINDING = "FINDING"                  # Correlating vulnerability finding
    USER_PROVIDED = "USER_PROVIDED"      # Explicit threat modeling assumption or manual input


class MitigationStatus(str, Enum):
    """Defensive coverage status of an attack step or complete attack path."""
    UNMITIGATED = "UNMITIGATED"                  # No known defensive control exists (Security Gap)
    PARTIALLY_MITIGATED = "PARTIALLY_MITIGATED"  # Some controls exist, but unverified or gaps remain
    MITIGATED = "MITIGATED"                      # Effective, passing controls protect all steps
    UNKNOWN = "UNKNOWN"                          # Control status unverified


class ControlEffectiveness(str, Enum):
    """Operational verification status of a mitigating security control."""
    CONFIGURED = "CONFIGURED"  # Declared in configuration or policy
    TESTED = "TESTED"          # Linked to test suite
    PASSED = "PASSED"          # Verified passing by test
    FAILED = "FAILED"          # Tested but failing
    UNKNOWN = "UNKNOWN"        # Unverified


class EntryPointType(str, Enum):
    """Standardized entry points for AI systems."""
    HTTP_API = "HTTP_API"
    CHAT_INPUT = "CHAT_INPUT"
    FILE_UPLOAD = "FILE_UPLOAD"
    DOCUMENT_INGESTION = "DOCUMENT_INGESTION"
    TOOL_INPUT = "TOOL_INPUT"
    MCP_INPUT = "MCP_INPUT"
    AGENT_MESSAGE = "AGENT_MESSAGE"
    WEBHOOK = "WEBHOOK"
    EXTERNAL_API = "EXTERNAL_API"
    CUSTOM = "CUSTOM"


class ConfidenceLevel(str, Enum):
    """Evidence-derived confidence rating for attack step or path feasibility."""
    LOW = "LOW"        # Purely structural candidate with unverified assumptions
    MEDIUM = "MEDIUM"  # Supported by graph topology, configuration, and known weaknesses
    HIGH = "HIGH"      # Corroborated by automated test executions or runtime telemetry


class AttackEvidence(BaseModel):
    """Verifiable proof supporting the feasibility or observation of an attack step."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_type: EvidenceType = Field(..., description="Classification of evidence source.")
    source_id: str = Field(..., description="ID of originating entity, test, event, or finding.")
    description: str = Field(..., description="Human-readable explanation of what the evidence proves.")
    verified: bool = Field(default=False, description="True if cryptographically or programmatically confirmed.")
    timestamp: float = Field(default_factory=time.time, description="Epoch timestamp when evidence was recorded.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe auxiliary metadata (no secrets).")

    @field_validator("description")
    @classmethod
    def validate_desc(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Evidence description cannot be empty.")
        return clean


class AttackTechnique(BaseModel):
    """Structured AI-specific attack technique metadata."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(..., description="Stable technique identifier (e.g. T-PI-01).")
    name: str = Field(..., description="Human-readable technique name.")
    description: str = Field(..., description="Concise description of the attack method.")
    prerequisites: List[str] = Field(default_factory=list, description="Required preconditions for attack execution.")
    affected_assets: List[str] = Field(default_factory=list, description="Target asset types impacted.")
    detection_methods: List[str] = Field(default_factory=list, description="Recommended detectors or inspection methods.")
    mitigations: List[str] = Field(default_factory=list, description="Defensive security controls mitigating technique.")


class AttackNode(BaseModel):
    """An analytical attack graph node representing an asset or intermediate attack state."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(..., min_length=1, max_length=256, description="Stable attack node ID.")
    type: str = Field(default="attack_node", description="Node entity classification.")
    asset_id: str = Field(..., description="Referenced underlying KnowledgeGraph asset ID.")
    technique: Optional[str] = Field(default=None, description="Associated attack technique ID if state node.")
    preconditions: List[str] = Field(default_factory=list, description="Prerequisite conditions for this node.")
    evidence: List[AttackEvidence] = Field(default_factory=list, description="Evidence backing this node.")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Safe metadata properties (no secrets).")


class AttackStep(BaseModel):
    """An individual hop within a multi-step attack chain."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    step_id: str = Field(default_factory=lambda: f"step-{uuid.uuid4().hex[:8]}", description="Unique step ID.")
    technique: str = Field(..., description="Attack technique ID executing at this step.")
    technique_name: str = Field(default="", description="Descriptive name of technique.")
    source: str = Field(..., description="Source asset ID initiating this step.")
    target: str = Field(..., description="Target asset ID impacted by this step.")
    preconditions: List[str] = Field(default_factory=list, description="Required conditions that must hold true.")
    postconditions: List[str] = Field(default_factory=list, description="New capabilities or states yielded by step.")
    evidence: List[AttackEvidence] = Field(default_factory=list, description="Evidence supporting this hop.")
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.LOW, description="Evidence-derived confidence rating.")
    mitigations: List[str] = Field(default_factory=list, description="Security control IDs mitigating this step.")
    mitigation_status: MitigationStatus = Field(default=MitigationStatus.UNKNOWN, description="Mitigation status.")
    assumptions: List[str] = Field(default_factory=list, description="Explicit assumptions required for step.")

    @property
    def step_key(self) -> str:
        """Deterministic fingerprint key for step deduplication."""
        return f"{self.source}──[{self.technique}]──>{self.target}"


class AttackPath(BaseModel):
    """A multi-step directed sequence through the architecture leading to potential compromise."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    path_id: str = Field(..., description="Deterministic or unique attack path identifier.")
    source: str = Field(..., description="Initial entry point or originating asset ID.")
    target: str = Field(..., description="Crown jewel asset or impacted resource ID.")
    steps: List[AttackStep] = Field(default_factory=list, description="Sequential hops in the attack chain.")
    status: PathStatus = Field(default=PathStatus.CANDIDATE, description="Verification state of path.")
    evidence: List[AttackEvidence] = Field(default_factory=list, description="Aggregated evidence supporting path.")
    mitigations: List[str] = Field(default_factory=list, description="Security controls mitigating this path.")
    mitigation_status: MitigationStatus = Field(default=MitigationStatus.UNKNOWN, description="Overall mitigation status.")
    assumptions: List[str] = Field(default_factory=list, description="Explicit assumptions made along path.")
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.LOW, description="Overall confidence level.")
    created_at: float = Field(default_factory=time.time, description="Creation epoch timestamp.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe auxiliary metadata.")

    @classmethod
    def create(
        cls,
        source: str,
        target: str,
        steps: List[AttackStep],
        status: PathStatus = PathStatus.CANDIDATE,
        evidence: Optional[List[AttackEvidence]] = None,
        mitigations: Optional[List[str]] = None,
        mitigation_status: MitigationStatus = MitigationStatus.UNKNOWN,
        assumptions: Optional[List[str]] = None,
        confidence: ConfidenceLevel = ConfidenceLevel.LOW,
    ) -> "AttackPath":
        """Factory computing deterministic path_id from step sequence."""
        step_keys = [s.step_key for s in steps]
        combined = f"{source}::{'->'.join(step_keys)}::{target}"
        h = hashlib.sha256(combined.encode("utf-8")).hexdigest()[:12]
        path_id = f"PATH-{h.upper()}"
        return cls(
            path_id=path_id,
            source=source,
            target=target,
            steps=steps,
            status=status,
            evidence=evidence or [],
            mitigations=mitigations or [],
            mitigation_status=mitigation_status,
            assumptions=assumptions or [],
            confidence=confidence,
        )

    @property
    def length(self) -> int:
        """Hop count of the attack path."""
        return len(self.steps)

    @property
    def technique_sequence(self) -> List[str]:
        """Ordered sequence of attack technique IDs along path."""
        return [s.technique for s in self.steps]

    @property
    def node_sequence(self) -> List[str]:
        """Ordered sequence of node IDs traversed along path."""
        if not self.steps:
            return [self.source, self.target] if self.source != self.target else [self.source]
        seq = [self.steps[0].source]
        for s in self.steps:
            seq.append(s.target)
        return seq

    @property
    def is_mitigated(self) -> bool:
        """True if path is fully protected by verified controls."""
        return self.mitigation_status == MitigationStatus.MITIGATED or self.status == PathStatus.BLOCKED

    @property
    def is_tested(self) -> bool:
        """True if path has been confirmed through automated security testing."""
        return self.status == PathStatus.TESTED

    @property
    def is_observed(self) -> bool:
        """True if path has been witnessed in runtime telemetry."""
        return self.status == PathStatus.OBSERVED

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class TrustBoundary(BaseModel):
    """Demarcation line where security context, privilege, or trust assumptions change."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    boundary_id: str = Field(..., description="Unique boundary identifier (e.g. user_to_app).")
    name: str = Field(..., description="Descriptive boundary name.")
    source_entity: str = Field(..., description="Source entity ID on lower-trust or higher-trust side.")
    target_entity: str = Field(..., description="Target entity ID across the boundary.")
    trust_level_from: str = Field(default="untrusted", description="Trust level before crossing.")
    trust_level_to: str = Field(default="trusted", description="Trust level after crossing.")
    description: str = Field(default="", description="Rationale and assumptions for this boundary.")


class EntryPoint(BaseModel):
    """Configured architectural ingress point where external data or control enters the system."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    entry_point_id: str = Field(..., description="Unique entry point ID (e.g. ep:chat_api).")
    name: str = Field(..., description="Human-readable entry point name.")
    type: EntryPointType = Field(default=EntryPointType.CHAT_INPUT, description="Ingress channel type.")
    target_asset_id: str = Field(..., description="Asset receiving the ingress payload.")
    description: str = Field(default="", description="Details on ingress processing and sanitization.")
    untrusted: bool = Field(default=True, description="True if entry point accepts untrusted user/external data.")


class ThreatModel(BaseModel):
    """Comprehensive, auditable threat model document representing assets, boundaries, and attack paths."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    model_id: str = Field(default_factory=lambda: f"TM-{uuid.uuid4().hex[:8].upper()}", description="Threat model ID.")
    name: str = Field(default="AI System Threat Model", description="Descriptive threat model name.")
    version: str = Field(default="1.0", description="Threat model schema version.")
    created_at: float = Field(default_factory=time.time, description="Creation epoch timestamp.")
    assets: List[str] = Field(default_factory=list, description="IDs of protected assets.")
    entry_points: List[EntryPoint] = Field(default_factory=list, description="Identified entry points.")
    trust_boundaries: List[TrustBoundary] = Field(default_factory=list, description="Identified trust boundaries.")
    attack_paths: List[AttackPath] = Field(default_factory=list, description="Discovered candidate and verified attack paths.")
    security_controls: List[str] = Field(default_factory=list, description="Identified defensive security controls.")
    assumptions: List[str] = Field(default_factory=list, description="Recorded threat modeling assumptions.")
    security_gaps_count: int = Field(default=0, ge=0, description="Count of unmitigated attack paths.")

    def summary(self) -> Dict[str, Any]:
        """Compact summary of threat model findings."""
        by_status = {}
        for p in self.attack_paths:
            by_status[p.status.value] = by_status.get(p.status.value, 0) + 1
        return {
            "model_id": self.model_id,
            "name": self.name,
            "version": self.version,
            "assets_count": len(self.assets),
            "entry_points_count": len(self.entry_points),
            "trust_boundaries_count": len(self.trust_boundaries),
            "total_attack_paths": len(self.attack_paths),
            "paths_by_status": by_status,
            "security_gaps_count": self.security_gaps_count,
            "controls_count": len(self.security_controls),
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


class AttackGraphSnapshot(BaseModel):
    """Tamper-evident, serializable snapshot of attack graph paths, entry points, and boundaries."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(default="1.0.0", description="Schema version.")
    graph_version: str = Field(default="1.0", description="Attack graph state version.")
    rules_version: str = Field(default="1.0", description="Version of rules evaluated.")
    created_at: float = Field(default_factory=time.time, description="Creation epoch timestamp.")
    source_graph_hash: str = Field(default="", description="Underlying KnowledgeGraph SHA-256 digest.")
    paths: List[AttackPath] = Field(default_factory=list, description="Captured attack paths.")
    entry_points: List[EntryPoint] = Field(default_factory=list, description="Captured entry points.")
    trust_boundaries: List[TrustBoundary] = Field(default_factory=list, description="Captured trust boundaries.")
    snapshot_hash: str = Field(default="", description="Cryptographic SHA-256 digest of canonicalized snapshot.")

    @classmethod
    def create(
        cls,
        paths: List[AttackPath],
        entry_points: List[EntryPoint],
        trust_boundaries: List[TrustBoundary],
        source_graph_hash: str = "",
        graph_version: str = "1.0",
        rules_version: str = "1.0",
        timestamp: Optional[float] = None,
    ) -> "AttackGraphSnapshot":
        now = timestamp if timestamp is not None else time.time()
        sorted_paths = sorted(paths, key=lambda p: p.path_id)
        sorted_eps = sorted(entry_points, key=lambda e: e.entry_point_id)
        sorted_tbs = sorted(trust_boundaries, key=lambda b: b.boundary_id)

        canonical = {
            "schema_version": "1.0.0",
            "graph_version": graph_version,
            "rules_version": rules_version,
            "source_graph_hash": source_graph_hash,
            "paths": [p.path_id for p in sorted_paths],
            "entry_points": [e.entry_point_id for e in sorted_eps],
            "trust_boundaries": [b.boundary_id for b in sorted_tbs],
        }
        digest = hashlib.sha256(json.dumps(canonical, sort_keys=True).encode("utf-8")).hexdigest()

        return cls(
            schema_version="1.0.0",
            graph_version=graph_version,
            rules_version=rules_version,
            created_at=now,
            source_graph_hash=source_graph_hash,
            paths=sorted_paths,
            entry_points=sorted_eps,
            trust_boundaries=sorted_tbs,
            snapshot_hash=digest,
        )

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.model_dump(mode="json"), indent=indent, sort_keys=True)


class AttackGraphDiff(BaseModel):
    """Comparative delta between two attack graph snapshots for drift analysis and governance."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    paths_added: List[str] = Field(default_factory=list, description="IDs of newly discovered attack paths.")
    paths_removed: List[str] = Field(default_factory=list, description="IDs of resolved or removed attack paths.")
    paths_changed: List[str] = Field(default_factory=list, description="IDs of paths with modified status or mitigations.")
    new_entry_points: List[str] = Field(default_factory=list, description="New entry points added.")
    new_techniques: List[str] = Field(default_factory=list, description="New attack techniques observed in paths.")
    new_trust_boundaries: List[str] = Field(default_factory=list, description="New trust boundaries crossed.")
    is_identical: bool = Field(default=False, description="True if snapshots are identical.")

    def summary(self) -> Dict[str, Any]:
        return {
            "is_identical": self.is_identical,
            "paths_added_count": len(self.paths_added),
            "paths_removed_count": len(self.paths_removed),
            "paths_changed_count": len(self.paths_changed),
            "new_entry_points_count": len(self.new_entry_points),
            "new_techniques_count": len(self.new_techniques),
            "new_trust_boundaries_count": len(self.new_trust_boundaries),
        }
