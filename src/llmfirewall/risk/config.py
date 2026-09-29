"""Configurable scoring weights and thresholds for the Risk Engine."""

from typing import Dict
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.models import Severity, ThreatType


class RiskConfig(BaseModel):
    """Configuration for risk scoring weights, decay factors, and thresholds."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    # Base risk points assigned to each severity level (scaled to 1.0)
    severity_weights: Dict[Severity, float] = Field(
        default_factory=lambda: {
            Severity.INFO: 0.05,
            Severity.LOW: 0.20,
            Severity.MEDIUM: 0.50,
            Severity.HIGH: 0.80,
            Severity.CRITICAL: 1.00,
        },
        description="Base severity weights in [0.0, 1.0]",
    )

    # Multipliers for critical threat categories
    category_multipliers: Dict[ThreatType, float] = Field(
        default_factory=lambda: {
            ThreatType.PROMPT_INJECTION: 1.0,
            ThreatType.JAILBREAK: 1.0,
            ThreatType.SECRET: 1.0,
            ThreatType.PII: 0.9,
            ThreatType.TOXICITY: 0.8,
            ThreatType.MALICIOUS_URL: 0.9,
            ThreatType.HALLUCINATION: 0.7,
            ThreatType.POLICY_VIOLATION: 0.8,
            ThreatType.CUSTOM: 0.8,
        },
        description="Threat-specific risk multipliers",
    )

    # Diminishing returns decay factor for multiple findings in the same category
    # Each subsequent finding after the primary contributes with exponential decay: decay_factor ** (k)
    decay_factor: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Decay rate for compounding repeated findings in the same category",
    )

    # Risk level threshold boundaries: score -> Severity rank
    info_threshold: float = Field(default=0.0, ge=0.0, le=1.0)
    low_threshold: float = Field(default=0.15, ge=0.0, le=1.0)
    medium_threshold: float = Field(default=0.40, ge=0.0, le=1.0)
    high_threshold: float = Field(default=0.70, ge=0.0, le=1.0)
    critical_threshold: float = Field(default=0.90, ge=0.0, le=1.0)

    def determine_risk_level(self, score: float) -> Severity:
        """Map a normalized risk score [0.0, 1.0] to a Risk Level (Severity)."""
        if score >= self.critical_threshold:
            return Severity.CRITICAL
        elif score >= self.high_threshold:
            return Severity.HIGH
        elif score >= self.medium_threshold:
            return Severity.MEDIUM
        elif score >= self.low_threshold:
            return Severity.LOW
        return Severity.INFO
