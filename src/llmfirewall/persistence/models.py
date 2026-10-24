"""Data models for security data persistence."""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field


class StorageFilter(BaseModel):
    """Query filter parameters for stored security records."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_id: Optional[str] = Field(default=None, description="Optional tenant scope")
    record_type: Optional[str] = Field(default=None, description="Event type or record classification")
    start_time: Optional[datetime] = Field(default=None, description="Inclusive start range")
    end_time: Optional[datetime] = Field(default=None, description="Inclusive end range")
    limit: int = Field(default=100, ge=1, le=10000, description="Maximum records to return")
    offset: int = Field(default=0, ge=0, description="Offset for pagination")


class PersistenceRecord(BaseModel):
    """Standardized record wrapper for persisted security records with tamper-evident checksum."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique record identifier")
    tenant_id: Optional[str] = Field(default=None, description="Tenant partition ID if multi-tenant")
    record_type: str = Field(..., min_length=1, max_length=64, description="Category of persisted item")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC creation timestamp",
    )
    payload: Dict[str, Any] = Field(..., description="Structured security data payload")
    checksum: str = Field(default="", description="SHA-256 checksum of payload for integrity verification")

    def model_post_init(self, __context: Any) -> None:
        if not self.checksum:
            serialized = json.dumps(self.payload, sort_keys=True, default=str)
            digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
            object.__setattr__(self, "checksum", digest)

    def verify_integrity(self) -> bool:
        """Verify that payload matches checksum."""
        serialized = json.dumps(self.payload, sort_keys=True, default=str)
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        return digest == self.checksum
