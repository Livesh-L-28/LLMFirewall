"""Prompt security context, trust level classification, and multi-turn state."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.runtime.models import TrustLevel


class PromptSourceType(str, Enum):
    """Source origin classification of prompt content."""
    USER = "user"
    RETRIEVED_DOCUMENT = "retrieved_document"
    TOOL_OUTPUT = "tool_output"
    AGENT_MEMORY = "agent_memory"
    SYSTEM = "system"
    DEVELOPER = "developer"
    UNKNOWN = "unknown"


class PromptSecurityContext(BaseModel):
    """Security context capturing trust boundaries, provenance, and turn metadata."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    source_type: PromptSourceType = Field(default=PromptSourceType.USER)
    trust_level: TrustLevel = Field(default=TrustLevel.USER)
    source_id: Optional[str] = Field(default=None, description="Identifier of the origin document, tool, or user")
    turn_index: int = Field(default=0, ge=0, description="Sequential index in multi-turn conversation")
    accumulated_threats: List[str] = Field(default_factory=list, description="Threat types recorded in previous turns")
    is_sandboxed: bool = Field(default=False, description="Whether execution runs in restricted capability sandbox")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Custom contextual metadata")


class MultiTurnSecurityState(BaseModel):
    """Maintains bounded historical security state across conversation turns."""
    model_config = ConfigDict(extra="forbid")

    session_id: str
    max_history_turns: int = Field(default=10, ge=1)
    turn_count: int = Field(default=0, ge=0)
    flagged_turn_count: int = Field(default=0, ge=0)
    detected_threats_history: List[str] = Field(default_factory=list)
    last_action: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def record_turn(self, threats: List[str], action: str) -> None:
        """Record turn security outcome and prune historical records beyond bounds."""
        self.turn_count += 1
        if threats:
            self.flagged_turn_count += 1
            self.detected_threats_history.extend(threats)
            # Bound history length
            if len(self.detected_threats_history) > self.max_history_turns * 5:
                self.detected_threats_history = self.detected_threats_history[-(self.max_history_turns * 5):]
        self.last_action = action

    @property
    def is_suspicious_session(self) -> bool:
        """True if multiple turns in the session have triggered security findings."""
        return self.flagged_turn_count >= 2
