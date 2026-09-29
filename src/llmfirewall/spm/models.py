"""Domain models, enums, schemas, and snapshot models for Phase 35 — AI Security Posture Management (AI-SPM)."""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
import time
from typing import Any, Dict, List, Optional, Set
import uuid
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from llmfirewall.core.models import Severity


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------

class PostureState(str, Enum):
    """Overall security posture evaluation states.
    
    Criteria:
    - HEALTHY: Mandatory controls present and validated; security tests passing; no open HIGH/CRITICAL findings; no unmitigated attack paths.
    - ATTENTION_REQUIRED: Non-critical gaps exist (unverified authorization, unexecuted tests, unknown rate limiting/logging).
    - DEGRADED: A security control failed validation, a security test failed, or HIGH severity finding is open.
    - CRITICAL: A CRITICAL severity finding is open, an unmitigated attack path reaches sensitive data/tools, or perimeter control is ABSENT.
    - UNKNOWN: Insufficient observations or evidence available to assess security posture.
    """
    HEALTHY = "HEALTHY"
    ATTENTION_REQUIRED = "ATTENTION_REQUIRED"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class PostureDimension(str, Enum):
    """The 15 standardized AI security posture dimensions."""
    ASSET_SECURITY = "asset_security"
    MODEL_SECURITY = "model_security"
    AGENT_SECURITY = "agent_security"
    TOOL_SECURITY = "tool_security"
    PROMPT_SECURITY = "prompt_security"
    RAG_SECURITY = "rag_security"
    MEMORY_SECURITY = "memory_security"
    DATA_SECURITY = "data_security"
    DEPENDENCY_SECURITY = "dependency_security"
    CONFIGURATION_SECURITY = "configuration_security"
    ACCESS_CONTROL = "access_control"
    MONITORING = "monitoring"
    TESTING = "testing"
    GOVERNANCE = "governance"
    ATTACK_SURFACE = "attack_surface"


class ControlPresence(str, Enum):
    """Configuration presence state of a defensive security control."""
    PRESENT = "PRESENT"
    PARTIALLY_PRESENT = "PARTIALLY_PRESENT"
    ABSENT = "ABSENT"
    UNKNOWN = "UNKNOWN"


class ControlEffectiveness(str, Enum):
    """Empirical effectiveness of a defensive security control."""
    CONFIGURED = "CONFIGURED"
    TESTED = "TESTED"
    VALIDATED = "VALIDATED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class SecurityGapStatus(str, Enum):
    """Lifecycle status of an identified security gap."""
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"
    ACCEPTED = "ACCEPTED"
    UNVERIFIED = "UNVERIFIED"


class TestFreshness(str, Enum):
    """Freshness of security test coverage relative to asset changes."""
    __test__ = False
    FRESH = "FRESH"
    STALE = "STALE"
    UNTESTED = "UNTESTED"


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
NON_CREDENTIAL_PREFIXES = ("control:", "asset:", "tool:", "model:", "agent:", "detector:", "rule:", "package:")


def sanitize_posture_metadata(data: Any) -> Any:
    """Recursively scrub credentials and secret patterns from posture metadata."""
    if isinstance(data, dict):
        clean = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if isinstance(v, (dict, list)):
                clean[k] = sanitize_posture_metadata(v)
            else:
                is_cred_key = (
                    (k_lower in CREDENTIAL_KEY_NAMES or any(k_lower.endswith(s) for s in CREDENTIAL_SUFFIXES))
                    and not any(k_lower.startswith(p) for p in NON_CREDENTIAL_PREFIXES)
                    and k_lower not in ("type", "version", "schema_version", "hash", "fingerprint", "status", "dimension", "id", "name", "created_at", "updated_at", "last_seen", "first_seen")
                )
                if is_cred_key:
                    clean[k] = "[REDACTED_CREDENTIAL]"
                else:
                    clean[k] = sanitize_posture_metadata(v)
        return clean
    elif isinstance(data, list):
        return [sanitize_posture_metadata(item) for item in data]
    elif isinstance(data, str):
        for pattern in SECRET_PATTERNS:
            if pattern.search(data):
                return "[REDACTED_SECRET]"
        return data
    return data


# -----------------------------------------------------------------------------
# Component Posture Records
# -----------------------------------------------------------------------------

class ControlPostureRecord(BaseModel):
    """Detailed posture and effectiveness evidence for a specific security control."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    control_id: str = Field(..., description="Unique control identifier (e.g. 'control:prompt_injection_detector').")
    name: str = Field(..., description="Human-readable control name.")
    presence: ControlPresence = Field(default=ControlPresence.UNKNOWN, description="Whether control is configured.")
    effectiveness: ControlEffectiveness = Field(default=ControlEffectiveness.UNKNOWN, description="Empirical validation state.")
    tested: bool = Field(default=False, description="Whether security tests have evaluated this control.")
    last_tested: Optional[float] = Field(default=None, description="Epoch timestamp of most recent test execution.")
    test_freshness: TestFreshness = Field(default=TestFreshness.UNTESTED, description="Whether tests postdate asset changes.")
    evidence: List[str] = Field(default_factory=list, description="Explicit evidentiary notes supporting presence and effectiveness.")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class TestCoverageRecord(BaseModel):
    """Evidence-based security test coverage statistics for an asset."""
    __test__ = False
    model_config = ConfigDict(frozen=True, extra="forbid")

    total_tests: int = Field(default=0, ge=0, description="Total applicable security tests.")
    passed: int = Field(default=0, ge=0, description="Tests verified passing.")
    failed: int = Field(default=0, ge=0, description="Tests failing (policy violation or bypass).")
    not_executed: int = Field(default=0, ge=0, description="Tests specified but never executed.")
    last_tested: Optional[float] = Field(default=None, description="Most recent test timestamp.")
    is_stale: bool = Field(default=False, description="True if asset was modified after most recent test.")
    stale_reason: Optional[str] = Field(default=None, description="Reason test results are considered stale.")
    test_details: List[Dict[str, Any]] = Field(default_factory=list, description="Per-test execution summaries.")

    @property
    def pass_ratio(self) -> float:
        return (self.passed / self.total_tests) if self.total_tests > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class AttackSurfaceRecord(BaseModel):
    """Factual inventory attack surface evidence synthesized for an asset."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    tools_count: int = Field(default=0, ge=0)
    tools: List[str] = Field(default_factory=list)
    external_apis_count: int = Field(default=0, ge=0)
    external_apis: List[str] = Field(default_factory=list)
    memory_stores_count: int = Field(default=0, ge=0)
    memory_stores: List[str] = Field(default_factory=list)
    rag_sources_count: int = Field(default=0, ge=0)
    rag_sources: List[str] = Field(default_factory=list)
    entry_points_count: int = Field(default=0, ge=0)
    entry_points: List[str] = Field(default_factory=list)
    entry_point_postures: Dict[str, Dict[str, str]] = Field(
        default_factory=dict,
        description="Detailed posture per entry point: authentication, validation, rate_limiting, logging, monitoring."
    )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


# -----------------------------------------------------------------------------
# Security Gap
# -----------------------------------------------------------------------------

class SecurityGap(BaseModel):
    """Structured security gap representing missing defenses, unverified controls, or open risks."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    gap_id: str = Field(default_factory=lambda: f"GAP-{uuid.uuid4().hex[:8].upper()}", description="Unique gap identifier.")
    asset_id: str = Field(..., description="Target asset identifier.")
    dimension: str = Field(..., description="Associated posture dimension from PostureDimension.")
    title: str = Field(..., description="Concise gap title.")
    description: str = Field(..., description="Detailed description of the security deficiency.")
    severity: Severity = Field(default=Severity.MEDIUM, description="Assessed risk severity.")
    evidence: List[str] = Field(default_factory=list, description="Factual evidence demonstrating why gap exists.")
    related_control: Optional[str] = Field(default=None, description="Defensive control needed or deficient.")
    related_attack_path: Optional[str] = Field(default=None, description="Attack path enabled or unmitigated by gap.")
    status: SecurityGapStatus = Field(default=SecurityGapStatus.OPEN, description="Current resolution state.")
    remediation_guidance: Optional[str] = Field(default=None, description="Actionable recommendation to remediate.")
    created_at: float = Field(default_factory=time.time, description="Creation epoch timestamp.")
    updated_at: float = Field(default_factory=time.time, description="Most recent update timestamp.")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


# -----------------------------------------------------------------------------
# Security Posture
# -----------------------------------------------------------------------------

class SecurityPosture(BaseModel):
    """Comprehensive, evidence-based security posture evaluation for an individual AI asset or system."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    asset_id: str = Field(..., description="Target asset identifier (or 'system:environment' for aggregate).")
    asset_type: str = Field(default="agent", description="Classification type of asset.")
    asset_name: str = Field(default="", description="Human-readable asset title.")
    environment: str = Field(default="unknown", description="Deployment environment.")
    state: PostureState = Field(default=PostureState.UNKNOWN, description="Synthesized posture state.")
    state_reason: str = Field(default="", description="Evidence-based justification for the assessed state.")
    evaluated_at: float = Field(default_factory=time.time, description="Evaluation epoch timestamp.")

    controls: Dict[str, ControlPostureRecord] = Field(default_factory=dict, description="Active defensive controls.")
    findings: Dict[str, List[Dict[str, Any]]] = Field(
        default_factory=lambda: {"open": [], "resolved": [], "accepted": [], "suppressed": []},
        description="Associated security findings partitioned by status."
    )
    attack_paths: Dict[str, List[Dict[str, Any]]] = Field(
        default_factory=lambda: {"candidate": [], "supported": [], "tested": [], "observed": [], "blocked": []},
        description="Associated multi-step attack paths partitioned by status."
    )
    test_coverage: TestCoverageRecord = Field(default_factory=TestCoverageRecord, description="Test statistics.")
    attack_surface: AttackSurfaceRecord = Field(default_factory=AttackSurfaceRecord, description="Factual attack surface counts.")
    configuration: Dict[str, Any] = Field(default_factory=dict, description="Security-relevant configuration state.")
    policy_status: Dict[str, Any] = Field(default_factory=dict, description="Governing policy status, versions, conflicts.")
    drift: Dict[str, Any] = Field(default_factory=dict, description="Recorded architectural drift and test staleness.")
    dimensions: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="Per-dimension posture breakdowns.")
    security_gaps: List[SecurityGap] = Field(default_factory=list, description="Actionable security gaps.")
    unknowns: List[str] = Field(default_factory=list, description="Explicit areas of unknown posture or missing telemetry.")
    evidence: List[str] = Field(default_factory=list, description="Consolidated audit evidence trail.")
    fingerprint: str = Field(default="", description="Deterministic SHA-256 fingerprint for change detection.")

    @model_validator(mode="before")
    @classmethod
    def sanitize_and_fingerprint(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Enforce 64KB metadata limit on auxiliary config
            cfg = data.get("configuration") or {}
            dumped = json.dumps(cfg, default=str)
            if len(dumped.encode("utf-8")) > 65536:
                raise ValueError("Posture configuration metadata exceeds maximum size limit of 64KB.")
            data["configuration"] = sanitize_posture_metadata(cfg)

            # Auto-compute fingerprint if empty
            if not data.get("fingerprint"):
                aid = str(data.get("asset_id", ""))
                state = str(data.get("state", "UNKNOWN"))
                gaps = sorted([g.get("gap_id", "") if isinstance(g, dict) else g.gap_id for g in data.get("security_gaps", [])])
                ctrls = sorted([f"{k}:{v.get('presence') if isinstance(v, dict) else v.presence}" for k, v in data.get("controls", {}).items()])
                raw = f"{aid}|{state}|{','.join(gaps)}|{','.join(ctrls)}"
                data["fingerprint"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return data

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


# -----------------------------------------------------------------------------
# Posture Snapshot & Baseline Models
# -----------------------------------------------------------------------------

class PostureSnapshot(BaseModel):
    """Tamper-evident, reproducible baseline snapshot of AI security posture."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(default="1.0.0", description="Schema specification version.")
    posture_version: str = Field(default="1.0", description="Posture release version.")
    inventory_version: str = Field(default="1.0", description="Correlating inventory snapshot version.")
    graph_version: str = Field(default="1.0", description="Correlating knowledge graph version.")
    rules_version: str = Field(default="1.0.0", description="Posture rules engine version.")
    created_at: float = Field(default_factory=time.time, description="Creation epoch timestamp.")
    postures: Dict[str, SecurityPosture] = Field(default_factory=dict, description="Asset postures keyed by asset_id.")
    gaps: List[SecurityGap] = Field(default_factory=list, description="Consolidated security gaps.")
    summary: Dict[str, Any] = Field(default_factory=dict, description="Aggregated posture metrics.")
    snapshot_hash: str = Field(default="", description="Cryptographic SHA-256 digest of canonical posture.")

    @classmethod
    def create(
        cls,
        postures: Dict[str, SecurityPosture],
        gaps: Optional[List[SecurityGap]] = None,
        inventory_version: str = "1.0",
        graph_version: str = "1.0",
        rules_version: str = "1.0.0",
        posture_version: str = "1.0",
        summary: Optional[Dict[str, Any]] = None,
    ) -> "PostureSnapshot":
        now = time.time()
        sorted_postures = dict(sorted(postures.items()))
        all_gaps = gaps if gaps is not None else [gap for p in sorted_postures.values() for gap in p.security_gaps]
        sorted_gaps = sorted(all_gaps, key=lambda g: g.gap_id)

        canonical = {
            "schema_version": "1.0.0",
            "posture_version": posture_version,
            "inventory_version": inventory_version,
            "graph_version": graph_version,
            "rules_version": rules_version,
            "postures": {aid: p.fingerprint for aid, p in sorted_postures.items()},
            "gaps": [g.gap_id for g in sorted_gaps],
        }
        digest = hashlib.sha256(json.dumps(canonical, sort_keys=True).encode("utf-8")).hexdigest()

        return cls(
            schema_version="1.0.0",
            posture_version=posture_version,
            inventory_version=inventory_version,
            graph_version=graph_version,
            rules_version=rules_version,
            created_at=now,
            postures=sorted_postures,
            gaps=sorted_gaps,
            summary=summary or {},
            snapshot_hash=digest,
        )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


class PostureDiff(BaseModel):
    """Comparative delta between two posture snapshots for detecting regressions and improvements."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    is_identical: bool = Field(default=False, description="True if posture snapshots are identical.")
    posture_improved: List[str] = Field(default_factory=list, description="Asset IDs with improved posture state.")
    posture_degraded: List[str] = Field(default_factory=list, description="Asset IDs with degraded posture state.")
    controls_added: List[str] = Field(default_factory=list, description="New security controls detected.")
    controls_removed: List[str] = Field(default_factory=list, description="Security controls decommissioned or absent.")
    tests_became_stale: List[str] = Field(default_factory=list, description="Tests whose verification became stale.")
    new_security_gaps: List[SecurityGap] = Field(default_factory=list, description="Newly identified security gaps.")
    gaps_resolved: List[SecurityGap] = Field(default_factory=list, description="Previously open gaps now resolved.")
    attack_surface_changed: List[str] = Field(default_factory=list, description="Assets with expanded attack surface.")
    policy_conflicts_detected: List[str] = Field(default_factory=list, description="Policy discrepancies or conflicts.")
    regressions: List[str] = Field(default_factory=list, description="Specific security regressions detected.")
    summary: Dict[str, Any] = Field(default_factory=dict, description="Summary delta counts.")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")
