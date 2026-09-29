"""Configurable replacement token definitions for sensitive redaction."""

from typing import Dict, Optional
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.models import ThreatType


class RedactionConfig(BaseModel):
    """Configuration for token replacement templates during sensitive span redaction."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    # Standard replacement tokens by category / threat type
    category_tokens: Dict[str, str] = Field(
        default_factory=dict,
        description="User configured token overrides (e.g. {'email': '[EMAIL_REDACTED]'})",
    )

    # General fallback token
    default_token: str = Field(
        default="[REDACTED]",
        description="Fallback placeholder if category has no explicit token mapping",
    )

    def get_token_for(
        self,
        category: Optional[str] = None,
        threat_type: Optional[ThreatType] = None,
        default_suggestion: Optional[str] = None,
    ) -> str:
        """Resolve the replacement token based on category, threat type, or custom override."""
        # 1. User configured category override has highest priority
        if category and category in self.category_tokens:
            return self.category_tokens[category]

        # 2. User configured threat_type override
        if threat_type and threat_type.value in self.category_tokens:
            return self.category_tokens[threat_type.value]

        # 3. Detector's default suggested replacement text
        if default_suggestion:
            return default_suggestion

        # 4. Fallback default
        return self.default_token
