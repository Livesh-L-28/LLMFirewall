"""Domain models, enums, schemas, and snapshot models for Phase 36 — AI Security Compliance & Control Mapping."""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
import time
from typing import Any, Dict, List, Optional, Set, Union
import uuid
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from llmfirewall.core.models import Severity


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------

class ControlState(str, Enum):
    """Standardized compliance control implementation and evidence evaluation states.

    Semantics:
    - NOT_ASSESSED: Control is cataloged in the framework but has not yet been evaluated for the asset/environment.
    - NOT_APPLICABLE: Control does not apply to the asset type, environment, or scope (e.g. hardware security for a software prompt template).
    - NOT_IMPLEMENTED: Applicable control is required, but zero defensive security controls or policies exist.
    - PARTIALLY_IMPLEMENTED: Some required defensive controls exist, but others are missing from configuration.
    - IMPLEMENTED: Defensive security controls and policies are configured, but empirical security test evidence has not verified them.
    - PARTIALLY_EVIDENCED: Some required evidence exists and is valid, but other required evidence items are missing, untested, or stale.
    - EVIDENCED: Full required evidence exists, is fresh and valid, confirming the control is configured and effective.
    - FAILED: Negative evidence exists (e.g. failing security test, active exploit finding, conflicting evidence, or broken guardrail).
    - UNKNOWN: Incomplete observations, unobserved asset, or missing telemetry prevents assessing implementation or evidence.
    """
    NOT_ASSESSED = "NOT_ASSESSED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    PARTIALLY_IMPLEMENTED = "PARTIALLY_IMPLEMENTED"
    IMPLEMENTED = "IMPLEMENTED"
    PARTIALLY_EVIDENCED = "PARTIALLY_EVIDENCED"
    EVIDENCED = "EVIDENCED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class ApplicabilityStatus(str, Enum):
    """Whether a compliance control applies to a specific asset or environment."""
    APPLICABLE = "APPLICABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


class EvidenceType(str, Enum):
    """Taxonomy of evidence artifacts supporting compliance control assessments."""
    CONFIGURATION = "CONFIGURATION"
    POLICY = "POLICY"
    SECURITY_TEST = "SECURITY_TEST"
    FINDING = "FINDING"
    AUDIT_EVENT = "AUDIT_EVENT"
    POSTURE = "POSTURE"
    ATTACK_GRAPH = "ATTACK_GRAPH"
    ASSET_INVENTORY = "ASSET_INVENTORY"
    RUNTIME_EVENT = "RUNTIME_EVENT"
    DOCUMENT = "DOCUMENT"
    MANUAL_ATTESTATION = "MANUAL_ATTESTATION"


ComplianceEvidenceType = EvidenceType


class EvidenceValidity(str, Enum):
    """Current validity and freshness state of an evidence artifact."""
    VALID = "VALID"
    STALE = "STALE"
    REVOKED = "REVOKED"
    CONFLICTING = "CONFLICTING"
    UNKNOWN = "UNKNOWN"


class RemediationStatus(str, Enum):
    """Lifecycle status of an identified compliance control gap."""
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    ACCEPTED = "ACCEPTED"
    WAIVED = "WAIVED"
    UNKNOWN = "UNKNOWN"


class ExceptionStatus(str, Enum):
    """Lifecycle status of a formally granted compliance exception or waiver."""
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class MappingType(str, Enum):
    """Relationship classification for cross-framework control mappings."""
    EXACT = "EXACT"
    PARTIAL = "PARTIAL"
    RELATED = "RELATED"
    DERIVED = "DERIVED"
    ORGANIZATION_DEFINED = "ORGANIZATION_DEFINED"


# -----------------------------------------------------------------------------
# Secret Sanitization Helper
# -----------------------------------------------------------------------------

SECRET_PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9]{20,}", re.IGNORECASE),
    re.compile(r"ghp_[a-zA-Z0-9]{20,}", re.IGNORECASE),
    re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
    re.compile(r"(password|passwd|pwd|secret|api_key|apikey|private_key)\s*[:=]\s*[^\s]+", re.IGNORECASE),
]

CREDENTIAL_KEY_NAMES = {
    "api_key", "apikey", "secret", "token", "password", "passwd", "pwd",
    "credential", "private_key", "auth_token", "access_token", "refresh_token",
}
CREDENTIAL_SUFFIXES = ("_secret", "_password", "_passwd", "_token", "_credential", "_key")
NON_CREDENTIAL_PREFIXES = ("control:", "asset:", "tool:", "model:", "agent:", "detector:", "rule:", "package:", "framework:", "domain:")


def sanitize_compliance_metadata(data: Any) -> Any:
    """Recursively scrub credentials and secret patterns from compliance metadata."""
    if isinstance(data, dict):
        clean = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if isinstance(v, (dict, list)):
                clean[k] = sanitize_compliance_metadata(v)
            else:
                is_cred_key = (
                    (k_lower in CREDENTIAL_KEY_NAMES or any(k_lower.endswith(s) for s in CREDENTIAL_SUFFIXES))
                    and not any(k_lower.startswith(p) for p in NON_CREDENTIAL_PREFIXES)
                    and k_lower not in ("type", "version", "schema_version", "hash", "fingerprint", "status", "dimension", "id", "name", "created_at", "updated_at", "last_seen", "first_seen", "control_id", "framework_id")
                )
                if is_cred_key:
                    clean[k] = "[REDACTED_CREDENTIAL]"
                else:
                    clean[k] = sanitize_compliance_metadata(v)
        return clean
    elif isinstance(data, list):
        return [sanitize_compliance_metadata(item) for item in data]
    elif isinstance(data, str):
        for pattern in SECRET_PATTERNS:
            if pattern.search(data):
                return "[REDACTED_SECRET]"
        return data
    return data


# -----------------------------------------------------------------------------
# Compliance Control & Framework Models
# -----------------------------------------------------------------------------

class ComplianceControl(BaseModel):
    """Specification of an individual security control within a compliance framework."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(..., description="Full canonical control identifier (e.g. 'ai-baseline:AC-01').")
    framework_id: str = Field(..., description="Identifier of parent framework (e.g. 'ai-security-baseline').")
    control_id: str = Field(..., description="Short internal control ID within framework (e.g. 'AC-01').")
    title: str = Field(..., description="Human-readable title of the control.")
    description: str = Field(default="", description="Detailed specification of the control objective.")
    category: str = Field(default="general", description="Functional category (e.g. 'access_control', 'prompt_security').")
    domain: str = Field(default="General Security", description="Hierarchical domain grouping (e.g. 'Access Control').")
    requirements: List[str] = Field(default_factory=list, description="Specific declarative requirements comprising this control.")
    evidence_requirements: List[str] = Field(
        default_factory=list,
        description="Required evidence types or tokens (e.g. ['authorization_policy', 'authorization_test', 'production_configuration']).",
    )
    applicability: Dict[str, Any] = Field(
        default_factory=dict,
        description="Target asset types, environments, or condition filters defining where this control applies.",
    )

    @field_validator("id")
    @classmethod
    def validate_id_format(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Control ID cannot be empty.")
        return clean

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class ComplianceFramework(BaseModel):
    """Specification of a versioned, modular security compliance framework."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(..., description="Unique framework identifier (e.g. 'ai-security-baseline').")
    name: str = Field(..., description="Human-readable name of the framework.")
    version: str = Field(default="1.0.0", description="Framework version string.")
    description: str = Field(default="", description="Summary of framework goals and scope.")
    source: str = Field(default="LLMFirewall", description="Originating authority, standard, or organization.")
    publisher: Optional[str] = Field(default=None, description="Author or publishing organization.")
    domains: List[str] = Field(default_factory=list, description="List of recognized domains in this framework.")
    controls: Dict[str, ComplianceControl] = Field(default_factory=dict, description="Controls keyed by full control ID.")
    checksum: str = Field(default="", description="Cryptographic SHA-256 digest of framework controls.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe auxiliary metadata.")

    @model_validator(mode="before")
    @classmethod
    def calculate_checksum(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Enforce 5MB pack limit
            dumped = json.dumps(data, default=str)
            if len(dumped.encode("utf-8")) > 5 * 1024 * 1024:
                raise ValueError("Framework pack size exceeds maximum allowed limit of 5MB.")
            data["metadata"] = sanitize_compliance_metadata(data.get("metadata") or {})

            if not data.get("checksum"):
                ctrls = sorted(list(data.get("controls", {}).keys()))
                raw = f"{data.get('id')}:{data.get('version')}:{','.join(ctrls)}"
                data["checksum"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return data

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


# -----------------------------------------------------------------------------
# Evidence Model
# -----------------------------------------------------------------------------

class ComplianceEvidence(BaseModel):
    """Traceable, verifiable evidence artifact mapped to an asset and compliance control."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: f"EVID-{uuid.uuid4().hex[:8].upper()}", description="Unique evidence ID.")
    type: EvidenceType = Field(..., description="Classification category of evidence.")
    source: str = Field(..., description="Subsystem or tool that generated this evidence (e.g. 'llmfirewall.spm').")
    asset_id: str = Field(..., description="Target asset identifier.")
    control_id: str = Field(..., description="Associated compliance control identifier.")
    collected_at: float = Field(default_factory=time.time, description="Collection epoch timestamp.")
    expires_at: Optional[float] = Field(default=None, description="Expiration epoch timestamp if time-bounded.")
    last_verified: float = Field(default_factory=time.time, description="Last verification epoch timestamp.")
    content_reference: str = Field(
        ...,
        description="Safe identifier, test ID, finding ID, or cryptographic hash reference (no raw secrets).",
    )
    status: EvidenceValidity = Field(default=EvidenceValidity.VALID, description="Current validity state.")
    attestation: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Manual attestation statement details if type is MANUAL_ATTESTATION.",
    )
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe auxiliary metadata.")

    @field_validator("metadata", "attestation", mode="before")
    @classmethod
    def sanitize_metadata_fields(cls, v: Any) -> Any:
        if v is not None:
            return sanitize_compliance_metadata(v)
        return v

    @property
    def is_expired(self) -> bool:
        if self.expires_at is not None:
            return time.time() > self.expires_at
        return False

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


# -----------------------------------------------------------------------------
# Exceptions & Gaps
# -----------------------------------------------------------------------------

class ComplianceException(BaseModel):
    """Formally approved business or operational exception/waiver for a control gap."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    exception_id: str = Field(default_factory=lambda: f"CEXC-{uuid.uuid4().hex[:8].upper()}")
    control_id: str = Field(..., description="Associated compliance control ID.")
    asset_id: str = Field(..., description="Target asset ID.")
    reason: str = Field(..., description="Documented operational or business justification.")
    approved_by: str = Field(..., description="Approving officer, security team, or role.")
    created_at: float = Field(default_factory=time.time, description="Approval epoch timestamp.")
    expires_at: float = Field(..., description="Mandatory expiration epoch timestamp.")
    status: ExceptionStatus = Field(default=ExceptionStatus.ACTIVE, description="Current exception status.")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("approved_by")
    @classmethod
    def validate_approved_by(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Exception requires an explicit approving officer or role (approved_by cannot be empty).")
        return clean

    @property
    def is_active(self) -> bool:
        """Evaluate if exception is currently active and within its valid time window."""
        if self.status != ExceptionStatus.ACTIVE:
            return False
        return time.time() <= self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class ComplianceGap(BaseModel):
    """Actionable compliance deficiency, missing required evidence, or failed control."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    gap_id: str = Field(default_factory=lambda: f"CGAP-{uuid.uuid4().hex[:8].upper()}")
    framework_id: str = Field(..., description="Framework identifier.")
    control_id: str = Field(..., description="Target control identifier.")
    asset_id: str = Field(..., description="Target asset identifier.")
    title: str = Field(..., description="Concise gap title.")
    description: str = Field(..., description="Detailed technical deficiency description.")
    severity: Severity = Field(default=Severity.MEDIUM, description="Assessed severity level.")
    missing_evidence: List[str] = Field(default_factory=list, description="Specific missing evidence requirements.")
    related_findings: List[str] = Field(default_factory=list, description="Associated security finding IDs.")
    related_posture_gaps: List[str] = Field(default_factory=list, description="Associated Phase 35 posture gap IDs.")
    related_attack_paths: List[str] = Field(default_factory=list, description="Associated Phase 33 attack path IDs.")
    status: RemediationStatus = Field(default=RemediationStatus.OPEN, description="Remediation lifecycle state.")
    remediation_guidance: Optional[str] = Field(default=None, description="Actionable defensive remediation guidance.")
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


# -----------------------------------------------------------------------------
# Control Assessment & Mapping Models
# -----------------------------------------------------------------------------

class ControlAssessment(BaseModel):
    """Evidence-backed assessment result for a specific control applied to an asset or environment."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    assessment_id: str = Field(default_factory=lambda: f"ASSESS-{uuid.uuid4().hex[:8].upper()}")
    framework_id: str = Field(..., description="Parent framework identifier.")
    control_id: str = Field(..., description="Full canonical control identifier (e.g. 'ai-baseline:AC-01').")
    asset_id: str = Field(..., description="Assessed asset identifier.")
    status: ControlState = Field(default=ControlState.UNKNOWN, description="Synthesized evidence evaluation state.")
    applicability: ApplicabilityStatus = Field(default=ApplicabilityStatus.APPLICABLE)
    applicability_reason: str = Field(default="", description="Reason for applicability decision.")
    evidence: List[ComplianceEvidence] = Field(default_factory=list, description="Collected supporting evidence items.")
    missing_evidence: List[str] = Field(default_factory=list, description="List of unmet evidence requirements.")
    gaps: List[ComplianceGap] = Field(default_factory=list, description="Generated compliance gaps.")
    exceptions: List[ComplianceException] = Field(default_factory=list, description="Associated formal exceptions.")
    related_attack_paths: List[Dict[str, Any]] = Field(default_factory=list, description="Correlating attack paths.")
    related_findings: List[Dict[str, Any]] = Field(default_factory=list, description="Correlating security findings.")
    related_security_controls: List[str] = Field(default_factory=list, description="Associated defensive controls.")
    evidence_chain: Dict[str, Any] = Field(
        default_factory=dict,
        description="Detailed traceable chain: Requirement -> Control -> Asset -> Security Control -> Posture -> Test/Policy/Finding -> Evidence.",
    )
    assessed_at: float = Field(default_factory=time.time, description="Assessment epoch timestamp.")
    rules_version: str = Field(default="1.0.0", description="Assessment rule engine version.")
    fingerprint: str = Field(default="", description="Deterministic SHA-256 fingerprint for change tracking.")

    @model_validator(mode="before")
    @classmethod
    def compute_fingerprint(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if not data.get("fingerprint"):
                cid = str(data.get("control_id", ""))
                aid = str(data.get("asset_id", ""))
                st = str(data.get("status", "UNKNOWN"))
                gaps = sorted([g.get("gap_id", "") if isinstance(g, dict) else g.gap_id for g in data.get("gaps", [])])
                evids = sorted([e.get("id", "") if isinstance(e, dict) else e.id for e in data.get("evidence", [])])
                raw = f"{cid}|{aid}|{st}|{','.join(gaps)}|{','.join(evids)}"
                data["fingerprint"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return data

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class ControlMapping(BaseModel):
    """Many-to-many relationship mapping between compliance controls, assets, and internal controls."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    mapping_id: str = Field(default_factory=lambda: f"MAP-{uuid.uuid4().hex[:8].upper()}")
    control_id: str = Field(..., description="Target compliance control ID.")
    asset_id: Optional[str] = Field(default=None, description="Optional target asset ID.")
    posture_dimension: Optional[str] = Field(default=None, description="Associated Phase 35 PostureDimension.")
    security_control_id: Optional[str] = Field(default=None, description="Associated defensive control ID.")
    finding_id: Optional[str] = Field(default=None, description="Associated finding ID.")
    test_id: Optional[str] = Field(default=None, description="Associated security test ID.")
    attack_path_id: Optional[str] = Field(default=None, description="Associated attack path ID.")
    evidence_ids: List[str] = Field(default_factory=list, description="Correlating evidence IDs.")
    rationale: str = Field(default="", description="Justification explaining why mapping applies.")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class CrossFrameworkMapping(BaseModel):
    """Cross-framework mapping establishing conceptual relationships between distinct control frameworks."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    mapping_id: str = Field(default_factory=lambda: f"XMAP-{uuid.uuid4().hex[:8].upper()}")
    source_control_id: str = Field(..., description="Origin control ID (e.g. 'company-ai:AC-01').")
    target_control_id: str = Field(..., description="Target control ID (e.g. 'ai-baseline:AC-01').")
    mapping_type: MappingType = Field(default=MappingType.RELATED, description="Relationship classification.")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence factor.")
    rationale: str = Field(..., description="Factual explanation of relationship and uncovered gaps.")
    source: str = Field(default="LLMFirewall", description="Author or source of mapping definition.")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


# -----------------------------------------------------------------------------
# Snapshots & Regression Diffing
# -----------------------------------------------------------------------------

class ComplianceSnapshot(BaseModel):
    """Tamper-evident, reproducible baseline snapshot of compliance and control assessment state."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(default="1.0.0", description="Schema version.")
    framework_versions: Dict[str, str] = Field(default_factory=dict, description="Active framework versions.")
    catalog_version: str = Field(default="1.0.0", description="Control catalog version.")
    inventory_version: str = Field(default="1.0", description="Associated asset inventory version.")
    posture_version: str = Field(default="1.0", description="Associated posture snapshot version.")
    graph_version: str = Field(default="1.0", description="Associated knowledge graph version.")
    rules_version: str = Field(default="1.0.0", description="Assessment rules version.")
    created_at: float = Field(default_factory=time.time, description="Snapshot epoch timestamp.")
    assessments: Dict[str, ControlAssessment] = Field(default_factory=dict, description="Assessments keyed by 'control_id@asset_id'.")
    gaps: List[ComplianceGap] = Field(default_factory=list, description="Consolidated compliance gaps.")
    evidence: List[ComplianceEvidence] = Field(default_factory=list, description="Supporting evidence items.")
    exceptions: List[ComplianceException] = Field(default_factory=list, description="Active compliance exceptions.")
    summary: Dict[str, Any] = Field(default_factory=dict, description="Aggregated compliance metrics.")
    snapshot_hash: str = Field(default="", description="Cryptographic SHA-256 digest of canonical compliance state.")

    @classmethod
    def create(
        cls,
        assessments: Dict[str, ControlAssessment],
        gaps: Optional[List[ComplianceGap]] = None,
        evidence: Optional[List[ComplianceEvidence]] = None,
        exceptions: Optional[List[ComplianceException]] = None,
        framework_versions: Optional[Dict[str, str]] = None,
        catalog_version: str = "1.0.0",
        inventory_version: str = "1.0",
        posture_version: str = "1.0",
        graph_version: str = "1.0",
        rules_version: str = "1.0.0",
        summary: Optional[Dict[str, Any]] = None,
    ) -> "ComplianceSnapshot":
        now = time.time()
        sorted_assessments = dict(sorted(assessments.items()))
        all_gaps = gaps if gaps is not None else [gap for a in sorted_assessments.values() for gap in a.gaps]
        sorted_gaps = sorted(all_gaps, key=lambda g: g.gap_id)
        all_evid = evidence if evidence is not None else [e for a in sorted_assessments.values() for e in a.evidence]
        sorted_evid = sorted(list({e.id: e for e in all_evid}.values()), key=lambda e: e.id)
        sorted_exc = sorted(exceptions or [], key=lambda ex: ex.exception_id)

        canonical = {
            "schema_version": "1.0.0",
            "framework_versions": framework_versions or {},
            "catalog_version": catalog_version,
            "inventory_version": inventory_version,
            "posture_version": posture_version,
            "graph_version": graph_version,
            "rules_version": rules_version,
            "assessments": {k: a.fingerprint for k, a in sorted_assessments.items()},
            "gaps": [g.gap_id for g in sorted_gaps],
            "evidence": [e.id for e in sorted_evid],
        }
        digest = hashlib.sha256(json.dumps(canonical, sort_keys=True).encode("utf-8")).hexdigest()

        return cls(
            schema_version="1.0.0",
            framework_versions=framework_versions or {},
            catalog_version=catalog_version,
            inventory_version=inventory_version,
            posture_version=posture_version,
            graph_version=graph_version,
            rules_version=rules_version,
            created_at=now,
            assessments=sorted_assessments,
            gaps=sorted_gaps,
            evidence=sorted_evid,
            exceptions=sorted_exc,
            summary=summary or {},
            snapshot_hash=digest,
        )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


class ComplianceDiff(BaseModel):
    """Comparative delta between two compliance snapshots for detecting regressions and improvements."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    is_identical: bool = Field(default=False, description="True if snapshots are identical.")
    control_status_changed: List[str] = Field(default_factory=list, description="Controls with modified status.")
    regressions: List[str] = Field(default_factory=list, description="Specific compliance regressions detected.")
    new_gaps: List[ComplianceGap] = Field(default_factory=list, description="Newly identified compliance gaps.")
    resolved_gaps: List[ComplianceGap] = Field(default_factory=list, description="Previously open gaps now resolved.")
    evidence_expired: List[str] = Field(default_factory=list, description="Evidence items that expired.")
    controls_added: List[str] = Field(default_factory=list, description="Controls newly introduced.")
    controls_removed: List[str] = Field(default_factory=list, description="Controls decommissioned.")
    framework_changed: List[str] = Field(default_factory=list, description="Framework version changes.")
    summary: Dict[str, Any] = Field(default_factory=dict, description="Summary counts.")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")
