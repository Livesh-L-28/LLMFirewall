"""Runtime models, boundaries, trust classifications, context, events, and decision types.

Phase 26: LLM & Agent Runtime Protection.
Guarantees:
- Strict trust boundaries (SYSTEM, DEVELOPER, USER, RETRIEVED, TOOL, UNTRUSTED)
- Content provenance & boundary tracking
- Normalized LLMRequest and LLMResponse representations
- Thread-safe and async-safe runtime state
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.exceptions import LLMFirewallError
from llmfirewall.core.models import Action, Finding, RiskScore, ScanResult, Severity, ThreatType
from llmfirewall.tools.models import ToolCall, ToolResult, ToolSecurityDecision


class TrustLevel(str, Enum):
    """Trust classification for content ingested or produced by LLM/agent runtimes."""
    SYSTEM = "system"
    DEVELOPER = "developer"
    USER = "user"
    RETRIEVED = "retrieved"
    TOOL = "tool"
    EXTERNAL = "external"
    UNTRUSTED = "untrusted"
    # Phase 27 extensions
    TRUSTED = "trusted"
    CONTROLLED = "controlled"
    UNKNOWN = "unknown"


class RuntimeBoundary(str, Enum):
    """Explicit lifecycle execution boundaries evaluated by the runtime engine."""
    USER_INPUT = "user_input"
    PROMPT = "prompt"
    LLM_REQUEST = "llm_request"
    LLM_RESPONSE = "llm_response"
    TOOL_REQUEST = "tool_request"
    TOOL_RESULT = "tool_result"
    AGENT_LOOP = "agent_loop"
    FINAL_RESPONSE = "final_response"
    # Phase 27 RAG & Context boundaries
    DOCUMENT_INGESTION = "document_ingestion"
    RETRIEVED_DOCUMENT = "retrieved_document"
    RETRIEVED_CHUNK = "retrieved_chunk"
    MEMORY = "memory"
    EXTERNAL_CONTENT = "external_content"


class RuntimeEventType(str, Enum):
    """Taxonomy of security-critical runtime events."""
    RUNTIME_STARTED = "runtime_started"
    USER_INPUT_RECEIVED = "user_input_received"
    PROMPT_CONSTRUCTED = "prompt_constructed"
    LLM_REQUEST_STARTED = "llm_request_started"
    LLM_RESPONSE_RECEIVED = "llm_response_received"
    TOOL_CALL_REQUESTED = "tool_call_requested"
    TOOL_CALL_ALLOWED = "tool_call_allowed"
    TOOL_CALL_BLOCKED = "tool_call_blocked"
    TOOL_RESULT_RECEIVED = "tool_result_received"
    TOOL_RESULT_BLOCKED = "tool_result_blocked"
    AGENT_ITERATION = "agent_iteration"
    LOOP_DETECTED = "loop_detected"
    LIMIT_EXCEEDED = "limit_exceeded"
    FINAL_RESPONSE_GENERATED = "final_response_generated"
    RUNTIME_COMPLETED = "runtime_completed"
    RUNTIME_BLOCKED = "runtime_blocked"
    RUNTIME_FAILED = "runtime_failed"
    # Phase 27 RAG Events
    DOCUMENT_SCANNED = "document_scanned"
    DOCUMENT_FLAGGED = "document_flagged"
    DOCUMENT_QUARANTINED = "document_quarantined"
    CONTEXT_ITEM_BLOCKED = "context_item_blocked"
    CONTEXT_ITEM_FILTERED = "context_item_filtered"
    CONTEXT_CONFLICT_DETECTED = "context_conflict_detected"
    CONTEXT_BUDGET_EXCEEDED = "context_budget_exceeded"
    MEMORY_BLOCKED = "memory_blocked"
    PROVENANCE_VIOLATION = "provenance_violation"


class RuntimeSecurityError(LLMFirewallError):
    """Base exception for runtime security enforcement and violations."""

    def __init__(
        self,
        message: str,
        boundary: RuntimeBoundary = RuntimeBoundary.AGENT_LOOP,
        decision: Optional[Any] = None,
        runtime_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.boundary = boundary
        self.decision = decision
        self.runtime_id = runtime_id
        self.trace_id = trace_id


class RuntimeLimitExceeded(RuntimeSecurityError):
    """Raised when an agent iteration limit, tool budget, or timeout is exceeded."""

    def __init__(
        self,
        limit_name: str,
        configured_limit: Any,
        observed_value: Any,
        runtime_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> None:
        msg = f"Runtime limit '{limit_name}' exceeded: configured {configured_limit}, observed {observed_value}."
        super().__init__(
            message=msg,
            boundary=RuntimeBoundary.AGENT_LOOP,
            runtime_id=runtime_id,
            trace_id=trace_id,
        )
        self.limit_name = limit_name
        self.configured_limit = configured_limit
        self.observed_value = observed_value


class RuntimeContext(BaseModel):
    """Immutable context envelope identifying execution identity, trace, and tenant."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    runtime_id: str = Field(default_factory=lambda: f"run-{uuid.uuid4().hex[:12]}")
    trace_id: str = Field(default_factory=lambda: f"trace-{uuid.uuid4().hex[:16]}")
    session_id: Optional[str] = Field(default=None)
    user_id: Optional[str] = Field(default=None)
    agent_id: Optional[str] = Field(default="default_agent")
    application_id: Optional[str] = Field(default=None)
    environment: str = Field(default="production")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ContentItem(BaseModel):
    """Piece of prompt or reasoning content annotated with source provenance and trust."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    text: str
    source: TrustLevel = Field(default=TrustLevel.UNTRUSTED)
    name: Optional[str] = Field(default=None)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class LLMMessage(BaseModel):
    """Normalized chat message for runtime inspection."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    role: str = Field(default="user", description="'system', 'user', 'assistant', or 'tool'")
    content: str = Field(default="")
    trust: TrustLevel = Field(default=TrustLevel.USER)
    tool_calls: Optional[List[Dict[str, Any]]] = Field(default=None)
    name: Optional[str] = Field(default=None)


class LLMRequest(BaseModel):
    """Provider-agnostic representation of an outbound LLM invocation."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    messages: List[LLMMessage] = Field(default_factory=list)
    model: str = Field(default="default-model")
    parameters: Dict[str, Any] = Field(default_factory=dict)
    provider: Optional[str] = Field(default=None)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def extract_untrusted_text(self) -> str:
        """Extract text originating from untrusted sources (user, retrieved, external)."""
        texts = []
        for m in self.messages:
            if m.trust in (TrustLevel.USER, TrustLevel.RETRIEVED, TrustLevel.EXTERNAL, TrustLevel.UNTRUSTED):
                if m.content:
                    texts.append(m.content)
        return "\n".join(texts)

    def extract_full_prompt(self) -> str:
        """Extract entire reconstructed prompt."""
        return "\n".join(f"{m.role}: {m.content}" for m in self.messages if m.content)


class LLMResponse(BaseModel):
    """Provider-agnostic representation of an inbound LLM completion or tool request."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    content: str = Field(default="")
    tool_calls: List[ToolCall] = Field(default_factory=list)
    model: Optional[str] = Field(default=None)
    usage: Dict[str, int] = Field(default_factory=dict)  # {"prompt_tokens": ..., "completion_tokens": ...}
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RuntimeSecurityState(str, Enum):
    """Cumulative security health state of an active agent runtime session."""
    CLEAN = "clean"
    WARNING = "warning"
    BLOCKED = "blocked"
    TERMINATED = "terminated"
    ERROR = "error"


class RuntimeDecision(BaseModel):
    """Deterministic security decision rendered at any execution boundary."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    boundary: RuntimeBoundary
    action: Action
    reason: str
    risk_score: Optional[float] = Field(default=0.0)
    severity: Severity = Field(default=Severity.INFO)
    findings: List[Finding] = Field(default_factory=list)
    policy_id: Optional[str] = Field(default=None)
    triggered_rules: List[str] = Field(default_factory=list)
    sanitized_text: Optional[str] = Field(default=None)
    runtime_id: Optional[str] = Field(default=None)
    trace_id: Optional[str] = Field(default=None)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def is_blocked(self) -> bool:
        return self.action == Action.BLOCK

    @property
    def is_allowed(self) -> bool:
        return self.action in (Action.ALLOW, Action.WARN, Action.REDACT)

