"""LLMFirewall Context-Aware Security Decisions (Phase 5).

Provides verified context extraction, anti-spoofing guarantees,
explicit decision contracts, and taint propagation across LLM and agent workflows.
"""

from llmfirewall.context.models import (
    ContextTrustBoundary,
    ContextTrustLevel,
    DocumentTrustStatus,
    TrustLevel,
    VerifiedSecurityContext,
)
from llmfirewall.context.contract import (
    RESTRICTED_TOOLS_ON_TAINT,
    ContextDecisionContract,
)
from llmfirewall.context.engine import (
    ContextAwareDecisionEngine,
    ContextDecisionEnrichment,
)

__all__ = [
    "ContextTrustBoundary",
    "ContextTrustLevel",
    "DocumentTrustStatus",
    "TrustLevel",
    "VerifiedSecurityContext",
    "RESTRICTED_TOOLS_ON_TAINT",
    "ContextDecisionContract",
    "ContextAwareDecisionEngine",
    "ContextDecisionEnrichment",
]
