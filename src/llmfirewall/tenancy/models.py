"""Phase 63 — Enterprise Multi-Tenancy models and context."""

from datetime import datetime, timezone
from enum import Enum
import time
from typing import Any, Dict, List, Optional, Set
import uuid

from pydantic import BaseModel, ConfigDict, Field


class TenantTier(str, Enum):
    """Subscription or isolation tier for a tenant."""
    COMMUNITY = "COMMUNITY"
    STANDARD = "STANDARD"
    ENTERPRISE = "ENTERPRISE"
    GOVERNMENT = "GOVERNMENT"


class TenantContext(BaseModel):
    """Explicit tenant context defining multi-tenant isolation, policy, and rate limits."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_id: str = Field(..., min_length=1, max_length=128, description="Unique tenant or organization identifier")
    name: str = Field(..., max_length=256, description="Human readable organization or customer name")
    tier: TenantTier = Field(default=TenantTier.STANDARD, description="Service tier for isolation and limits")
    max_requests_per_minute: Optional[int] = Field(default=None, ge=1, description="Per-tenant rate limit")
    allowed_tools: Optional[List[str]] = Field(default=None, description="Whitelist of permitted tool names")
    quarantined: bool = Field(default=False, description="True if tenant is administrative suspended/quarantined")
    created_at: float = Field(default_factory=time.time)
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe custom metadata")
