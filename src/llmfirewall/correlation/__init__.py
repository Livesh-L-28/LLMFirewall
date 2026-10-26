"""LLMFirewall Unified Security Event Correlation (Phase 4).

Provides unified, privacy-safe event correlation, causal DAG ordering,
and incident timeline generation across single requests, multi-step workflows,
RAG context retrieval, and agent tool execution.
"""

from llmfirewall.correlation.models import (
    CorrelatedIncidentTimeline,
    UnifiedSecurityEvent,
)
from llmfirewall.correlation.engine import EventCorrelationEngine
from llmfirewall.correlation.sanitizer import (
    REDACTED_CREDENTIAL_TOKEN,
    REDACTED_TEXT_TOKEN,
    sanitize_metadata,
    sanitize_string,
    sanitize_value,
)
from llmfirewall.correlation.exporters import (
    export_timeline_cef,
    export_timeline_json,
    export_timeline_markdown,
    export_timeline_opentelemetry,
    export_timeline_syslog_rfc5424,
)

__all__ = [
    "CorrelatedIncidentTimeline",
    "UnifiedSecurityEvent",
    "EventCorrelationEngine",
    "REDACTED_CREDENTIAL_TOKEN",
    "REDACTED_TEXT_TOKEN",
    "sanitize_metadata",
    "sanitize_string",
    "sanitize_value",
    "export_timeline_cef",
    "export_timeline_json",
    "export_timeline_markdown",
    "export_timeline_opentelemetry",
    "export_timeline_syslog_rfc5424",
]
