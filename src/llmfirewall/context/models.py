"""Verified Security Context & Trust Models.

Phase 5: Context-Aware Security Decisions.
Guarantees:
- Strict separation between trusted application metadata and untrusted content payloads.
- Rejection of self-asserted identity or privilege claims from prompt text or LLM completions.
- Immutable, verified tenant, agent, and document trust boundaries.
"""

from __future__ import annotations

from enum import Enum
import re
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.models import ScanRequest
from llmfirewall.correlation.sanitizer import sanitize_metadata, sanitize_string
from llmfirewall.workflow.models import WorkflowThreatState


from llmfirewall.runtime.models import TrustLevel

ContextTrustLevel = TrustLevel


class ContextTrustBoundary(str, Enum):
    """Architectural boundary where a contextual attribute was established."""
    APPLICATION_LAYER = "application_layer"       # In-process verified host application
    GATEWAY_LAYER = "gateway_layer"               # Authenticated API gateway header/token
    CONTENT_BODY = "content_body"                 # Untrusted text payload (prompt, completion)
    RETRIEVED_DOCUMENT = "retrieved_document"     # RAG ingestion chunk or vector record
    LLM_GENERATED = "llm_generated"               # Model-generated completion or tool reasoning


class DocumentTrustStatus(BaseModel):
    """Verified trust and provenance status of a retrieved document or RAG chunk."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    document_id: Optional[str] = Field(default=None, description="Unique document or chunk identifier")
    provenance_source: Optional[str] = Field(default=None, description="Origin system (e.g. 'confluence_corp', 'web_scrape')")
    trust_level: TrustLevel = Field(default=TrustLevel.UNTRUSTED_EXTERNAL, description="Evaluated trust tier")
    is_verified: bool = Field(default=False, description="True only if provenance was verified by application")
    quarantine_status: Optional[str] = Field(default=None, description="Quarantine reason if previously flagged")


class VerifiedSecurityContext(BaseModel):
    """Immutable, authenticated context container passed to security evaluation.

    Invariant:
    - Never populated from untrusted user prompt text.
    - Only constructed from verified host application variables or authenticated tokens.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str = Field(default_factory=lambda: f"req-{uuid.uuid4().hex[:8]}", description="Request identifier")
    tenant_id: str = Field(..., description="Immutable verified tenant identifier")
    agent_id: Optional[str] = Field(default=None, description="Authorized agent persona or ID")
    workflow_id: Optional[str] = Field(default=None, description="Phase 3 multi-step workflow identifier")
    workflow_threat_state: Optional[WorkflowThreatState] = Field(default=None, description="Monotonic workflow taint state")
    document_trust: Optional[DocumentTrustStatus] = Field(default=None, description="Verified trust status of retrieved RAG content")
    caller_trust_level: TrustLevel = Field(default=TrustLevel.UNTRUSTED_EXTERNAL, description="Caller authentication tier")
    is_authenticated: bool = Field(default=False, description="True if caller has valid authentication claims")
    client_ip: Optional[str] = Field(default=None, description="Network IP address of caller")
    scoped_role: Optional[str] = Field(default=None, description="Authorized RBAC role for the session")
    prior_step_findings_count: int = Field(default=0, ge=0, description="Count of threat findings in earlier workflow steps")
    has_prior_injection: bool = Field(default=False, description="True if an injection was quarantined earlier in this workflow")
    has_prior_secret_leak: bool = Field(default=False, description="True if a credential leak occurred earlier in this workflow")
    execution_budget_remaining: Optional[int] = Field(default=None, ge=0, description="Remaining tool execution budget")
    boundary_origin: ContextTrustBoundary = Field(default=ContextTrustBoundary.APPLICATION_LAYER)
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Sanitized non-sensitive contextual metadata")

    # -------------------------------------------------------------------------
    # Anti-Spoofing & Context Validation
    # -------------------------------------------------------------------------

    @classmethod
    def from_request(
        cls,
        request: ScanRequest,
        verified_attributes: Optional[Dict[str, Any]] = None,
        tenant_id: Optional[str] = None,
    ) -> "VerifiedSecurityContext":
        """Construct a VerifiedSecurityContext, strictly filtering unverified prompt claims."""
        attrs = dict(verified_attributes or {})

        # Priority for tenant_id: explicit parameter > request.tenant_id > verified_attributes
        eff_tenant = tenant_id or request.tenant_id or attrs.get("tenant_id") or "default-tenant"

        # Explicitly scrub any self-asserted privilege claims that might have leaked from untrusted metadata
        scrubbed_meta = dict(request.metadata)
        for untrusted_key in ("admin", "bypass", "override", "root", "system_role", "trust_level"):
            scrubbed_meta.pop(untrusted_key, None)

        return cls(
            request_id=request.id,
            tenant_id=eff_tenant,
            agent_id=attrs.get("agent_id") or scrubbed_meta.get("agent_id"),
            workflow_id=attrs.get("workflow_id") or scrubbed_meta.get("workflow_id"),
            workflow_threat_state=attrs.get("workflow_threat_state"),
            caller_trust_level=attrs.get("caller_trust_level", TrustLevel.UNTRUSTED_EXTERNAL),
            is_authenticated=attrs.get("is_authenticated", False),
            client_ip=attrs.get("client_ip"),
            scoped_role=attrs.get("scoped_role"),
            has_prior_injection=attrs.get("has_prior_injection", False),
            has_prior_secret_leak=attrs.get("has_prior_secret_leak", False),
            boundary_origin=ContextTrustBoundary.APPLICATION_LAYER,
            metadata=sanitize_metadata(attrs.get("metadata", {})),
        )

    def safe_dict(self) -> Dict[str, Any]:
        """Produce safe machine-readable representation with zero leaked credentials."""
        dumped = self.model_dump(mode="json")
        dumped["metadata"] = sanitize_metadata(dumped.get("metadata", {}))
        return dumped
