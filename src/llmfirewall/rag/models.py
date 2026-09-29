"""Domain models, document statuses, trust levels, and context items for RAG security.

Phase 27: Advanced RAG & Context Security.
Guarantees:
- RETRIEVED CONTENT != INSTRUCTIONS
- Strict provenance tracking (source_id, document_id, chunk_id, author, connector)
- Instruction authority separation (SYSTEM/DEV vs RETRIEVED/TOOL/EXTERNAL)
- Deterministic hashing for duplicate and change detection
- Bounded metadata
"""

from __future__ import annotations

import hashlib
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.models import Action, Finding, Severity
from llmfirewall.runtime.models import TrustLevel


class DocumentSecurityStatus(str, Enum):
    """Lifecycle status of a scanned knowledge base document or chunk."""
    PENDING = "pending"
    SCANNED = "scanned"
    APPROVED = "approved"
    FLAGGED = "flagged"
    QUARANTINED = "quarantined"
    BLOCKED = "blocked"


class InstructionAuthority(str, Enum):
    """Explicit instruction authority permitted for a content source."""
    FULL = "full"          # System / Developer level instructions
    LIMITED = "limited"    # User prompt queries
    NONE = "none"          # Retrieved RAG context, tool results, external content


class SourceProvenance(BaseModel):
    """Immutable audit trail tracing content origin."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    source_id: str = Field(default_factory=lambda: f"src-{uuid.uuid4().hex[:8]}")
    document_id: Optional[str] = Field(default=None)
    chunk_id: Optional[str] = Field(default=None)
    connector: Optional[str] = Field(default="direct", description="Data connector or ingest mechanism")
    repository: Optional[str] = Field(default=None, description="Repository or database identifier")
    url_or_domain: Optional[str] = Field(default=None, description="Source domain or URL if web-derived")
    author: Optional[str] = Field(default=None, description="Document author or creator")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    version: str = Field(default="1.0")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ContextItem(BaseModel):
    """Structured, provenance-tracked context unit for RAG or agent memory."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    content: str = Field(..., description="Text content of this context piece")
    source_type: str = Field(default="retrieved_document", description="'retrieved_document', 'chunk', 'memory', 'tool_result', 'external'")
    trust_level: TrustLevel = Field(default=TrustLevel.UNTRUSTED)
    instruction_authority: InstructionAuthority = Field(default=InstructionAuthority.NONE)
    provenance: SourceProvenance = Field(default_factory=SourceProvenance)
    status: DocumentSecurityStatus = Field(default=DocumentSecurityStatus.APPROVED)
    findings: List[Finding] = Field(default_factory=list)
    content_hash: str = Field(default="")
    is_instructional: bool = Field(default=False, description="Flagged if text appears to mimic instructions")

    def __init__(self, **data: Any) -> None:
        if "content_hash" not in data or not data["content_hash"]:
            cnt = data.get("content", "")
            data["content_hash"] = hashlib.sha256(cnt.encode("utf-8")).hexdigest()
        super().__init__(**data)

    @property
    def is_quarantined_or_blocked(self) -> bool:
        return self.status in (DocumentSecurityStatus.QUARANTINED, DocumentSecurityStatus.BLOCKED)


class DocumentIngestionResult(BaseModel):
    """Result of scanning a document prior to indexing / vectorization."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    document_id: str
    status: DocumentSecurityStatus
    action: Action
    content_hash: str
    findings: List[Finding] = Field(default_factory=list)
    quarantine_reason: Optional[str] = Field(default=None)
    execution_time_ms: float = Field(default=0.0)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def is_safe(self) -> bool:
        return self.status == DocumentSecurityStatus.APPROVED and self.action == Action.ALLOW


class ContextSecurityDecision(BaseModel):
    """Security verdict on an assembled context or retrieved chunk set."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action: Action
    reason: str
    approved_items: List[ContextItem] = Field(default_factory=list)
    filtered_items: List[ContextItem] = Field(default_factory=list)
    quarantined_items: List[ContextItem] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    total_tokens: int = Field(default=0)
    total_bytes: int = Field(default=0)
    conflict_detected: bool = Field(default=False)
    budget_exceeded: bool = Field(default=False)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def is_blocked(self) -> bool:
        return self.action == Action.BLOCK

    @property
    def is_allowed(self) -> bool:
        return self.action in (Action.ALLOW, Action.WARN, Action.REDACT)
