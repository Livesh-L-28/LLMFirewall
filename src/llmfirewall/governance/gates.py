"""SecurityGate specifications and GateType definitions for Phase 31."""

from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator

from llmfirewall.core.models import Severity


class GateType(str, Enum):
    """Controlled taxonomy of security governance gates."""
    TEST_GATE = "test"
    POLICY_GATE = "policy"
    MODEL_GATE = "model"
    DEPENDENCY_GATE = "dependency"
    CONFIGURATION_GATE = "configuration"
    DRIFT_GATE = "drift"
    PROVENANCE_GATE = "provenance"
    AGENT_GATE = "agent"
    RAG_GATE = "rag"
    CUSTOM_GATE = "custom"


class SecurityGate(BaseModel):
    """Declarative specification for an atomic security gate requirement."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(..., min_length=1, max_length=128, description="Unique, stable gate identifier.")
    type: GateType = Field(default=GateType.TEST_GATE, description="Type of gate requirement.")
    name: str = Field(default="", description="Human-readable gate title.")
    description: str = Field(default="", description="Security intent and criteria description.")
    required: bool = Field(default=True, description="Whether passing this gate is mandatory for release.")
    block_on: List[Severity] = Field(
        default_factory=list,
        description="Finding severities that trigger immediate BLOCK.",
    )
    review_on: List[Severity] = Field(
        default_factory=list,
        description="Finding severities that trigger human REVIEW.",
    )
    max_allowed_severity: Optional[Severity] = Field(
        default=None,
        description="Maximum acceptable finding severity (any severity strictly above this fails gate).",
    )
    minimum_pass_rate: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Minimum acceptable security test suite pass rate (0.0 to 1.0).",
    )
    required_tests: List[str] = Field(
        default_factory=list,
        description="Explicit list of test IDs that MUST be present and passed.",
    )
    change_classification: Optional[str] = Field(
        default=None,
        description="Security change classification trigger (e.g. MODEL, CAPABILITY, CONFIGURATION).",
    )
    enabled: bool = Field(default=True, description="Whether this gate is active in evaluation.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary safe metadata.")

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Gate ID cannot be empty or whitespace.")
        return clean

    @field_validator("name")
    @classmethod
    def default_name(cls, v: str, info: Any) -> str:
        if not v and "id" in info.data:
            return info.data["id"]
        return v
