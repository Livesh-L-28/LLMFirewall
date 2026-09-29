"""Metadata definitions for detectors."""

from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.models import ThreatType


class DetectorMetadata(BaseModel):
    """Declarative metadata describing a detector's identity and capabilities."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(..., min_length=1, description="Unique detector name (e.g. 'regex_secret_detector')")
    description: str = Field(..., min_length=1, description="Human-readable description of what it detects")
    version: str = Field(default="0.1.0", description="SemVer string of detector version")
    supported_threats: List[ThreatType] = Field(
        default_factory=list,
        description="List of ThreatTypes this detector can produce",
    )
    supported_directions: List[str] = Field(
        default_factory=lambda: ["input", "output"],
        description="Inspection directions supported: 'input', 'output', or both",
    )
    is_enabled_by_default: bool = Field(
        default=True,
        description="Whether this detector runs in default pipeline configs",
    )
    author: Optional[str] = Field(default=None, description="Detector author or maintainer")
