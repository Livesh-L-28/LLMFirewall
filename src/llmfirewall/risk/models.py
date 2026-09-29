"""Domain models, factors, enums, and history tracking for Phase 37: AI Security Risk & Prioritization Engine."""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Set, Union
import uuid
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from llmfirewall.compliance.models import sanitize_compliance_metadata


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------

class RiskLevel(str, Enum):
    """Deterministic, transparent risk severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    UNKNOWN = "UNKNOWN"


class RiskUncertainty(str, Enum):
    """Epistemic uncertainty classification of risk assessments."""
    CONFIRMED = "CONFIRMED"                      # Verified via empirical attack test or runtime event
    SUPPORTED = "SUPPORTED"                      # Supported by configuration, graph reachability, or policy
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"  # Incomplete telemetry, untested guardrails
    UNKNOWN = "UNKNOWN"                          # Zero telemetry or unobserved state; never assumed safe


class RiskTreatment(str, Enum):
    """Lifecycle treatment status of an identified security risk."""
    OPEN = "OPEN"
    MITIGATING = "MITIGATING"
    ACCEPTED = "ACCEPTED"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"


class RiskFactorType(str, Enum):
    """Taxonomy of independently evaluated risk factors."""
    IMPACT = "IMPACT"
    EXPOSURE = "EXPOSURE"
    EXPLOITABILITY = "EXPLOITABILITY"
    ASSET_CRITICALITY = "ASSET_CRITICALITY"
    ATTACK_PATH_REACHABILITY = "ATTACK_PATH_REACHABILITY"
    CONTROL_WEAKNESS = "CONTROL_WEAKNESS"
    EVIDENCE_CONFIDENCE = "EVIDENCE_CONFIDENCE"
    DATA_SENSITIVITY = "DATA_SENSITIVITY"
    BUSINESS_CONTEXT = "BUSINESS_CONTEXT"
    UNCERTAINTY = "UNCERTAINTY"


# -----------------------------------------------------------------------------
# Factor & Assessment Models
# -----------------------------------------------------------------------------

class RiskFactor(BaseModel):
    """Independently evaluated risk factor explaining why an issue is prioritized."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(..., description="Descriptive factor name (e.g. 'External Exposure').")
    factor_type: RiskFactorType = Field(..., description="Classification category.")
    score: float = Field(default=0.5, ge=0.0, le=1.0, description="Normalized factor score [0.0, 1.0].")
    weight: float = Field(default=1.0, ge=0.0, description="Relative significance weight.")
    description: str = Field(default="", description="Detailed factual explanation of the factor.")
    evidence_references: List[str] = Field(default_factory=list, description="Associated evidence or test IDs.")
    rationale: str = Field(default="", description="Why this factor contributed to the risk priority.")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class RiskAssessment(BaseModel):
    """Evidence-driven risk assessment explaining priority and reasoning."""
    model_config = ConfigDict(frozen=False, extra="forbid")

    id: str = Field(default_factory=lambda: f"RISK-{uuid.uuid4().hex[:8].upper()}")
    asset_id: str = Field(..., description="Target asset identifier (e.g. 'agent:support').")
    finding_id: Optional[str] = Field(default=None, description="Optional associated finding ID.")
    attack_path_id: Optional[str] = Field(default=None, description="Optional associated attack path ID.")
    control_id: Optional[str] = Field(default=None, description="Associated control or compliance ID.")
    title: str = Field(..., description="Concise human-readable risk title.")
    level: RiskLevel = Field(default=RiskLevel.UNKNOWN, description="Deterministic risk level.")
    impact: float = Field(default=0.5, ge=0.0, le=1.0, description="Assessed impact severity [0.0, 1.0].")
    exposure: str = Field(default="internal", description="Exposure context ('external', 'internal', 'isolated').")
    exploitability: float = Field(default=0.5, ge=0.0, le=1.0, description="Ease of exploitation indicator [0.0, 1.0].")
    evidence_confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence in underlying evidence.")
    asset_criticality: float = Field(default=0.5, ge=0.0, le=1.0, description="Business criticality of the asset.")
    business_context: Dict[str, Any] = Field(default_factory=dict, description="Safe business metadata (e.g. department, env).")
    uncertainty: RiskUncertainty = Field(default=RiskUncertainty.UNKNOWN, description="Epistemic uncertainty level.")
    factors: List[RiskFactor] = Field(default_factory=list, description="Independently evaluated risk factors.")
    rationale: str = Field(..., description="Explainable prioritization justification.")
    treatment: RiskTreatment = Field(default=RiskTreatment.OPEN, description="Remediation status.")
    inherited_from: Optional[str] = Field(default=None, description="Downstream asset from which risk was inherited.")
    remediation_guidance: Optional[str] = Field(default=None, description="Defensive remediation recommendations.")
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)

    @field_validator("business_context", mode="before")
    @classmethod
    def sanitize_business_context(cls, v: Any) -> Any:
        return sanitize_compliance_metadata(v or {})

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


# -----------------------------------------------------------------------------
# History, Snapshots & Regression Diffing
# -----------------------------------------------------------------------------

class RiskHistoryEntry(BaseModel):
    """Audit log entry capturing state transitions in an asset's risk posture."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    entry_id: str = Field(default_factory=lambda: f"RHIST-{uuid.uuid4().hex[:8].upper()}")
    risk_id: str = Field(...)
    asset_id: str = Field(...)
    timestamp: float = Field(default_factory=time.time)
    event_type: str = Field(..., description="'CREATED', 'CHANGED', 'INCREASED', 'DECREASED', 'RESOLVED', 'REOPENED'")
    previous_level: Optional[RiskLevel] = None
    new_level: RiskLevel
    reason: str = Field(..., description="Documented explanation for risk change or regression.")


class RiskSnapshot(BaseModel):
    """Tamper-evident snapshot of system-wide risk assessments."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    snapshot_id: str = Field(default_factory=lambda: f"RSNAP-{uuid.uuid4().hex[:8].upper()}")
    schema_version: str = Field(default="1.0.0")
    created_at: float = Field(default_factory=time.time)
    risks: Dict[str, RiskAssessment] = Field(default_factory=dict, description="Risk assessments keyed by risk_id.")
    summary: Dict[str, Any] = Field(default_factory=dict)
    snapshot_hash: str = Field(default="")

    @classmethod
    def create(
        cls,
        risks: Dict[str, RiskAssessment],
        summary: Optional[Dict[str, Any]] = None,
    ) -> "RiskSnapshot":
        now = time.time()
        sorted_risks = dict(sorted(risks.items()))
        canonical = {
            "schema_version": "1.0.0",
            "risks": {k: f"{r.level.value}:{r.impact}:{r.exposure}" for k, r in sorted_risks.items()},
        }
        digest = hashlib.sha256(json.dumps(canonical, sort_keys=True).encode("utf-8")).hexdigest()
        return cls(
            schema_version="1.0.0",
            created_at=now,
            risks=sorted_risks,
            summary=summary or {},
            snapshot_hash=digest,
        )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class RiskDiff(BaseModel):
    """Comparative diff between two risk snapshots identifying regressions."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    is_identical: bool = Field(default=False)
    regressions: List[str] = Field(default_factory=list, description="Specific RISK_INCREASED occurrences.")
    level_changes: List[str] = Field(default_factory=list, description="Risk level transitions.")
    new_risks: List[RiskAssessment] = Field(default_factory=list)
    resolved_risks: List[RiskAssessment] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")
