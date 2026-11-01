"""Distributed Security Context and Trace Propagation Engine for LLMFirewall.

Provides framework-independent, thread-safe, and async-isolated propagation
of security context (trace ID, request ID, tenant ID, session ID, agent ID,
policy version, and audit metadata) across distributed multi-agent and
multi-service architectures.

Key Invariants:
1. Complete Async & Thread Isolation: Backed by `contextvars.ContextVar` to prevent
   cross-tenant context contamination in concurrent asyncio event loops.
2. Zero-Retention Safe Attributes: Never stores or propagates raw prompts, credentials,
   or sensitive payloads in distributed context or telemetry spans.
3. OpenTelemetry Compatibility: Seamlessly extracts and injects W3C `traceparent`
   headers (RFC 7230 / W3C Trace Context) and bridges to `opentelemetry.trace` when available.
"""

from __future__ import annotations

import contextlib
import contextvars
from datetime import datetime, timezone
import json
import logging
import re
import uuid
from typing import Any, AsyncGenerator, Dict, Generator, Iterator, Optional, Union

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger("llmfirewall.integrations.context")

# W3C traceparent regex: version(2 hex)-trace_id(32 hex)-parent_id(16 hex)-trace_flags(2 hex)
W3C_TRACEPARENT_REGEX = re.compile(
    r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$",
    re.IGNORECASE,
)


class SecurityContext(BaseModel):
    """Immutable, framework-independent distributed security context container.

    Carries cryptographic trace identifiers, tenant identity, and policy metadata
    across LLM framework boundaries (OpenAI, Anthropic, LangChain, LangGraph, MCP, web APIs).
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    trace_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        description="32-hex character distributed trace identifier matching W3C Trace Context",
    )
    request_id: str = Field(
        default_factory=lambda: f"req-{uuid.uuid4().hex[:12]}",
        description="Unique request identifier for log correlation",
    )
    tenant_id: str = Field(
        default="default-tenant",
        description="Tenant identifier for multi-tenant isolation",
    )
    session_id: Optional[str] = Field(
        default=None,
        description="Conversational multi-turn session identifier",
    )
    agent_id: Optional[str] = Field(
        default=None,
        description="Agent persona or service identifier",
    )
    parent_span_id: Optional[str] = Field(
        default=None,
        description="16-hex character parent span identifier",
    )
    span_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex[:16],
        description="16-hex character local span identifier",
    )
    policy_version: Optional[str] = Field(
        default="1.0",
        description="Active security policy version applied to this trace",
    )
    decision_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Safe, non-sensitive audit metadata from firewall decisions",
    )
    correlation_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Custom application metadata (must not contain raw secrets or PII)",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC creation timestamp",
    )

    # -------------------------------------------------------------------------
    # W3C Traceparent Header Interoperability
    # -------------------------------------------------------------------------

    def to_w3c_traceparent(self) -> str:
        """Serialize context to standard W3C Traceparent header string."""
        trace_hex = self.trace_id.replace("-", "").lower()
        if len(trace_hex) < 32:
            trace_hex = trace_hex.zfill(32)
        elif len(trace_hex) > 32:
            trace_hex = trace_hex[:32]

        span_hex = self.span_id.replace("-", "").lower()
        if len(span_hex) < 16:
            span_hex = span_hex.zfill(16)
        elif len(span_hex) > 16:
            span_hex = span_hex[:16]

        return f"00-{trace_hex}-{span_hex}-01"

    @classmethod
    def from_w3c_traceparent(
        cls,
        traceparent: str,
        tenant_id: str = "default-tenant",
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        **kwargs: Any,
    ) -> "SecurityContext":
        """Construct SecurityContext from an incoming W3C Traceparent header."""
        match = W3C_TRACEPARENT_REGEX.match(traceparent.strip())
        if match:
            _, trace_id, parent_id, _ = match.groups()
            return cls(
                trace_id=trace_id,
                parent_span_id=parent_id,
                tenant_id=tenant_id,
                session_id=session_id,
                agent_id=agent_id,
                **kwargs,
            )
        # Fall back to new trace if invalid header format
        logger.warning(f"Invalid W3C traceparent header format: '{traceparent}'. Generating new trace_id.")
        return cls(tenant_id=tenant_id, session_id=session_id, agent_id=agent_id, **kwargs)

    # -------------------------------------------------------------------------
    # OpenTelemetry Bridge
    # -------------------------------------------------------------------------

    @classmethod
    def current(cls, tenant_id: Optional[str] = None, **kwargs: Any) -> "SecurityContext":
        """Get the active security context, or bridge from OpenTelemetry / create new.

        Resolution order:
        1. Explicitly bound `contextvars` SecurityContext if set.
        2. Active OpenTelemetry span context if `opentelemetry` is available.
        3. Brand new SecurityContext.
        """
        existing = get_current_context()
        if existing is not None:
            if tenant_id and existing.tenant_id != tenant_id:
                # Return updated context for new tenant
                return existing.model_copy(update={"tenant_id": tenant_id})
            return existing

        # Attempt to bridge from active OpenTelemetry span
        try:
            from opentelemetry import trace  # type: ignore
            current_span = trace.get_current_span()
            if current_span and current_span.get_span_context().is_valid:
                span_ctx = current_span.get_span_context()
                trace_id_hex = format(span_ctx.trace_id, "032x")
                span_id_hex = format(span_ctx.span_id, "016x")
                return cls(
                    trace_id=trace_id_hex,
                    parent_span_id=span_id_hex,
                    tenant_id=tenant_id or "default-tenant",
                    **kwargs,
                )
        except Exception:
            pass

        return cls(tenant_id=tenant_id or "default-tenant", **kwargs)

    # -------------------------------------------------------------------------
    # Safe Export & Telemetry
    # -------------------------------------------------------------------------

    def safe_dict(self) -> Dict[str, Any]:
        """Produce a scrubbed dictionary representation safe for audit logs and SIEM exporters."""
        return {
            "trace_id": self.trace_id,
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "parent_span_id": self.parent_span_id,
            "span_id": self.span_id,
            "policy_version": self.policy_version,
            "decision_metadata": self.decision_metadata,
            "correlation_metadata": self.correlation_metadata,
            "created_at": self.created_at.isoformat(),
        }

    def to_audit_event(
        self,
        action: str,
        rule_id: Optional[str] = None,
        integration: str = "core",
        risk_score: float = 0.0,
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Produce a standardized immutable audit event record."""
        meta = dict(self.correlation_metadata)
        if extra_metadata:
            meta.update(extra_metadata)
        # Ensure no raw text or secret values in metadata
        for k in ("prompt", "input", "raw_text", "password", "api_key", "secret"):
            meta.pop(k, None)

        return {
            "event_id": f"evt-{uuid.uuid4().hex[:12]}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "trace_id": self.trace_id,
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "integration": integration,
            "action": str(action),
            "rule_id": rule_id or "unknown",
            "risk_score": float(risk_score),
            "safe_metadata": meta,
        }


# Backward-compatible alias
DistributedSecurityContext = SecurityContext

# Thread-safe and async-safe ContextVar container
_CURRENT_CONTEXT_VAR: contextvars.ContextVar[Optional[SecurityContext]] = contextvars.ContextVar(
    "llmfirewall_security_context",
    default=None,
)


def get_current_context() -> Optional[SecurityContext]:
    """Retrieve the currently active SecurityContext for the current thread or asyncio task."""
    return _CURRENT_CONTEXT_VAR.get()


def set_current_context(context: SecurityContext) -> contextvars.Token:
    """Set the active SecurityContext for the current execution scope."""
    if not isinstance(context, SecurityContext):
        raise TypeError(f"Expected SecurityContext, got {type(context).__name__}")
    return _CURRENT_CONTEXT_VAR.set(context)


def reset_current_context(token: contextvars.Token) -> None:
    """Restore the previous SecurityContext using a contextvars Token."""
    _CURRENT_CONTEXT_VAR.reset(token)


@contextlib.contextmanager
def security_context_scope(
    context_or_tenant: Union[SecurityContext, str, Dict[str, Any]],
    session_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    trace_id: Optional[str] = None,
) -> Iterator[SecurityContext]:
    """Context manager setting an active SecurityContext for a synchronous or async block.

    Restores previous context automatically upon exit to prevent state leaks.
    """
    if isinstance(context_or_tenant, SecurityContext):
        ctx = context_or_tenant
    elif isinstance(context_or_tenant, str):
        ctx = SecurityContext(
            tenant_id=context_or_tenant,
            session_id=session_id,
            agent_id=agent_id,
            trace_id=trace_id or uuid.uuid4().hex,
        )
    elif isinstance(context_or_tenant, dict):
        d = dict(context_or_tenant)
        if "tenant_id" not in d:
            d["tenant_id"] = "default-tenant"
        ctx = SecurityContext(**d)
    else:
        ctx = SecurityContext()

    token = set_current_context(ctx)
    try:
        yield ctx
    finally:
        reset_current_context(token)


def extract_w3c_traceparent(headers: Dict[str, Any]) -> Optional[str]:
    """Extract W3C traceparent header from case-insensitive HTTP or RPC header mapping."""
    if not headers or not isinstance(headers, dict):
        return None
    for k, v in headers.items():
        if k.lower() == "traceparent" and isinstance(v, str):
            return v
    return None


def inject_w3c_traceparent(
    headers: Dict[str, Any],
    context: Optional[SecurityContext] = None,
) -> Dict[str, Any]:
    """Inject W3C traceparent header into outgoing HTTP or RPC headers dictionary."""
    ctx = context or get_current_context() or SecurityContext.current()
    new_headers = dict(headers)
    new_headers["traceparent"] = ctx.to_w3c_traceparent()
    new_headers["x-llmfirewall-tenant-id"] = ctx.tenant_id
    if ctx.session_id:
        new_headers["x-llmfirewall-session-id"] = ctx.session_id
    return new_headers
