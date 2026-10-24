"""Production Observability & Security Intelligence module for LLMFirewall.

Public symbols:
- Models: SecurityEvent, SecurityEventType, EventSeverity, DecisionTrace, AnomalyEvent
- Stores: EventStore, InMemoryEventStore, JSONLEventStore, SQLiteEventStore, EventFilter
- Intelligence: SecurityIntelligenceEngine
- Exporters: export_prometheus_metrics, export_events_json, export_events_jsonl, export_events_csv
"""

from llmfirewall.observability.dashboard import (
    DashboardSummary,
    PaginatedEventsResponse,
    SanitizedDashboardEvent,
    SecurityDashboardAPI,
    TimeseriesBucket,
)
from llmfirewall.observability.exporters import (
    export_events_cef,
    export_events_csv,
    export_events_json,
    export_events_jsonl,
    export_events_opentelemetry,
    export_events_syslog_rfc5424,
    export_prometheus_metrics,
)
from llmfirewall.observability.webhook import (
    WebhookAlertConfig,
    WebhookAlertSink,
)
from llmfirewall.observability.intelligence import SecurityIntelligenceEngine
from llmfirewall.observability.models import (
    AnomalyEvent,
    DecisionTrace,
    DecisionTraceStep,
    EventSeverity,
    SecurityEvent,
    SecurityEventType,
    hash_content,
)
from llmfirewall.observability.store import (
    EventFilter,
    EventStore,
    InMemoryEventStore,
    JSONLEventStore,
    SQLiteEventStore,
)

__all__ = [
    # Models & Traces
    "SecurityEvent",
    "SecurityEventType",
    "EventSeverity",
    "DecisionTrace",
    "DecisionTraceStep",
    "AnomalyEvent",
    "hash_content",
    # Storage
    "EventStore",
    "InMemoryEventStore",
    "JSONLEventStore",
    "SQLiteEventStore",
    "EventFilter",
    # Intelligence & Analytics
    "SecurityIntelligenceEngine",
    # Dashboard API (Phase 54)
    "SecurityDashboardAPI",
    "DashboardSummary",
    "TimeseriesBucket",
    "SanitizedDashboardEvent",
    "PaginatedEventsResponse",
    # Exporters
    "export_prometheus_metrics",
    "export_events_cef",
    "export_events_json",
    "export_events_jsonl",
    "export_events_csv",
    "export_events_opentelemetry",
    "export_events_syslog_rfc5424",
    # SIEM / SOC Integration (Phase 65)
    "WebhookAlertConfig",
    "WebhookAlertSink",
]
