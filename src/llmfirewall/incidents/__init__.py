"""Incident Response and Investigation module exports for Phase 38."""

from llmfirewall.incidents.models import (
    EvidenceItem,
    IncidentAction,
    IncidentActionRecord,
    IncidentSeverity,
    IncidentStatus,
    SecurityEvent,
    SecurityEventType,
    SecurityIncident,
    TimelineEntry,
    compute_evidence_hash,
)
from llmfirewall.incidents.rules import (
    AbnormalAgentBehaviorRule,
    IncidentCandidate,
    IncidentDetectionRule,
    PolicyBypassRule,
    PromptInjectionFollowedByPrivilegedToolRule,
    RepeatedUnauthorizedToolCallsRule,
    SecretExposureRule,
    get_default_incident_rules,
)
from llmfirewall.incidents.manager import IncidentError, IncidentManager
from llmfirewall.incidents.reporting import (
    format_incident_detail_human,
    format_incident_timeline_human,
    format_incidents_table_human,
    generate_post_incident_report,
)

__all__ = [
    # Models
    "SecurityEvent",
    "SecurityEventType",
    "SecurityIncident",
    "IncidentSeverity",
    "IncidentStatus",
    "IncidentAction",
    "IncidentActionRecord",
    "EvidenceItem",
    "TimelineEntry",
    "compute_evidence_hash",
    # Rules
    "IncidentDetectionRule",
    "IncidentCandidate",
    "RepeatedUnauthorizedToolCallsRule",
    "PromptInjectionFollowedByPrivilegedToolRule",
    "SecretExposureRule",
    "PolicyBypassRule",
    "AbnormalAgentBehaviorRule",
    "get_default_incident_rules",
    # Manager
    "IncidentManager",
    "IncidentError",
    # Reporting
    "format_incidents_table_human",
    "format_incident_detail_human",
    "format_incident_timeline_human",
    "generate_post_incident_report",
]
