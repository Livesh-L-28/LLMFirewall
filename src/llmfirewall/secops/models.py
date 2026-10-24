"""Data models for Security Operations (SecOps) automation playbooks."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field


class PlaybookActionType(str, Enum):
    """Supported automated response action types."""
    REVOKE_AGENT_CAPABILITY = "revoke_agent_capability"
    QUARANTINE_SESSION = "quarantine_session"
    DISPATCH_SOC_ALERT = "dispatch_soc_alert"
    ROTATE_CACHE = "rotate_cache"
    CONTAIN_INCIDENT = "contain_incident"
    CUSTOM = "custom"


class PlaybookStep(BaseModel):
    """Individual execution step within a security automation playbook."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    step_id: str = Field(default_factory=lambda: f"step-{uuid.uuid4().hex[:8]}", description="Unique step identifier")
    action_type: PlaybookActionType = Field(..., description="Action category to execute")
    description: str = Field(default="", description="Operator-visible explanation of step intent")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Action-specific parameters")
    requires_authorization: bool = Field(
        default=True,
        description="Whether consequential action requires explicit security authorization",
    )


class SecurityPlaybook(BaseModel):
    """Auditable security response workflow."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(..., min_length=1, max_length=64, description="Unique playbook identifier")
    name: str = Field(..., description="Human-friendly playbook name")
    description: str = Field(default="", description="Operational intent")
    enabled: bool = Field(default=True, description="Whether playbook is active")
    trigger_min_severity: str = Field(
        default="HIGH",
        description="Minimum incident/event severity required to trigger playbook",
    )
    steps: List[PlaybookStep] = Field(default_factory=list, description="Ordered response steps")


class StepExecutionResult(BaseModel):
    """Result of an individual playbook step execution."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    step_id: str
    action_type: PlaybookActionType
    status: str  # "SUCCESS", "SKIPPED", "DENIED", "FAILED", "SIMULATED"
    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PlaybookExecutionResult(BaseModel):
    """Comprehensive, auditable outcome of a security playbook execution."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    execution_id: str = Field(default_factory=lambda: f"exec-{uuid.uuid4().hex[:12]}")
    playbook_id: str
    playbook_name: str
    dry_run: bool = Field(default=False, description="Whether execution was simulated")
    status: str = Field(..., description="'SUCCESS', 'PARTIAL', 'DENIED', or 'FAILED'")
    authorized_by: Optional[str] = Field(default=None, description="Identity/role that authorized execution")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    step_results: List[StepExecutionResult] = Field(default_factory=list)
    audit_notes: List[str] = Field(default_factory=list)
