"""SIEM / SOC Exporters for Correlated Incident Timelines.

Phase 4: Unified Security Event Correlation.
Extends existing SIEM/SOC interfaces to provide:
- Structured JSON and JSONL exports.
- Human-readable markdown diagnostic reports.
- ArcSight Common Event Format (CEF) multi-event export.
- RFC 5424 Syslog structured data export.
- OpenTelemetry (OTLP) LogRecords export with trace linking.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from llmfirewall.correlation.models import CorrelatedIncidentTimeline, UnifiedSecurityEvent


def export_timeline_json(timeline: CorrelatedIncidentTimeline, indent: Optional[int] = 2) -> str:
    """Export the correlated incident timeline as a formatted JSON document."""
    return json.dumps(timeline.safe_dict(), indent=indent)


def export_timeline_markdown(timeline: CorrelatedIncidentTimeline) -> str:
    """Export the correlated incident timeline as a human-readable diagnostic Markdown report."""
    return timeline.to_markdown()


def export_timeline_cef(timeline: CorrelatedIncidentTimeline) -> str:
    """Export all events in the incident timeline formatted as ArcSight Common Event Format (CEF)."""
    cef_lines: List[str] = []
    sev_map = {"critical": 10, "high": 7, "warning": 5, "info": 2, "debug": 0}

    for ev in timeline.events:
        sev_int = sev_map.get(ev.severity.value.lower(), 5)
        name = f"Incident Correlation: {ev.event_type.value}"
        act = ev.action.value if ev.action else "none"
        det = ev.detector_name or "none"
        score = f"{ev.risk_score:.3f}" if ev.risk_score is not None else "0.000"

        ext_parts = [
            f"act={act}",
            f"dvc={ev.environment}",
            f"cs1={det}",
            "cs1Label=DetectorName",
            f"cs2={ev.policy_id or 'none'}",
            "cs2Label=PolicyID",
            f"cfp1={score}",
            "cfp1Label=RiskScore",
            f"externalId={ev.event_id}",
            f"rt={int(ev.timestamp.timestamp() * 1000)}",
            f"cn1={ev.sequence_number}",
            "cn1Label=SequenceNumber",
            f"cs3={timeline.correlation_id}",
            "cs3Label=CorrelationID",
        ]

        if ev.parent_event_id:
            ext_parts.append(f"cs4={ev.parent_event_id} cs4Label=ParentEventID")
        if ev.workflow_id:
            ext_parts.append(f"cs5={ev.workflow_id} cs5Label=WorkflowID")
        if ev.tenant_id:
            ext_parts.append(f"cs6={ev.tenant_id} cs6Label=TenantID")

        extension = " ".join(ext_parts)
        cef_lines.append(f"CEF:0|LLMFirewall|LLMFirewallCore|2.0|{ev.event_type.value}|{name}|{sev_int}|{extension}")

    return "\n".join(cef_lines) + ("\n" if cef_lines else "")


def export_timeline_syslog_rfc5424(
    timeline: CorrelatedIncidentTimeline,
    app_name: str = "llmfirewall",
    hostname: str = "localhost",
    facility: int = 10,  # 10 = security/authorization messages
) -> str:
    """Export timeline events formatted according to RFC 5424 (The Syslog Protocol)."""
    lines: List[str] = []
    sev_codes = {
        "critical": 2,
        "high": 3,
        "warning": 4,
        "info": 6,
        "debug": 7,
    }

    for ev in timeline.events:
        sev_code = sev_codes.get(ev.severity.value.lower(), 5)
        pri = facility * 8 + sev_code
        ts = ev.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        procid = "-"
        msgid = ev.event_type.value
        act = ev.action.value if ev.action else "none"
        det = ev.detector_name or "none"
        score = f"{ev.risk_score:.3f}" if ev.risk_score is not None else "0.000"

        sd = (
            f'[llmfirewall@41123 eventId="{ev.event_id}" '
            f'correlationId="{timeline.correlation_id}" '
            f'sequence="{ev.sequence_number}" '
            f'action="{act}" '
            f'detector="{det}" '
            f'riskScore="{score}"]'
        )
        msg = f"Security event {ev.event_type.value} seq={ev.sequence_number} outcome={ev.outcome}"
        lines.append(f"<{pri}>1 {ts} {hostname} {app_name} {procid} {msgid} {sd} {msg}")

    return "\n".join(lines) + ("\n" if lines else "")


def export_timeline_opentelemetry(timeline: CorrelatedIncidentTimeline) -> Dict[str, Any]:
    """Export timeline events formatted according to OpenTelemetry (OTLP) LogRecords schema."""
    otel_sev_numbers = {
        "debug": 5,
        "info": 9,
        "warning": 13,
        "high": 17,
        "critical": 21,
    }

    log_records = []
    for ev in timeline.events:
        sev_str = ev.severity.value.lower()
        sev_num = otel_sev_numbers.get(sev_str, 9)
        time_nano = int(ev.timestamp.timestamp() * 1_000_000_000)

        attrs = [
            {"key": "gen_ai.system", "value": {"stringValue": "llmfirewall"}},
            {"key": "security.event_id", "value": {"stringValue": ev.event_id}},
            {"key": "security.event_type", "value": {"stringValue": ev.event_type.value}},
            {"key": "security.correlation_id", "value": {"stringValue": timeline.correlation_id}},
            {"key": "security.sequence_number", "value": {"intValue": ev.sequence_number}},
            {"key": "security.action", "value": {"stringValue": ev.action.value if ev.action else "none"}},
            {"key": "security.outcome", "value": {"stringValue": ev.outcome}},
            {"key": "security.environment", "value": {"stringValue": ev.environment}},
        ]

        if ev.workflow_id:
            attrs.append({"key": "security.workflow_id", "value": {"stringValue": ev.workflow_id}})
        if ev.tenant_id:
            attrs.append({"key": "security.tenant_id", "value": {"stringValue": ev.tenant_id}})
        if ev.parent_event_id:
            attrs.append({"key": "security.parent_event_id", "value": {"stringValue": ev.parent_event_id}})
        if ev.detector_name:
            attrs.append({"key": "security.detector_name", "value": {"stringValue": ev.detector_name}})
        if ev.risk_score is not None:
            attrs.append({"key": "security.risk_score", "value": {"doubleValue": float(ev.risk_score)}})
        if ev.tool_name:
            attrs.append({"key": "security.tool_name", "value": {"stringValue": ev.tool_name}})
        if ev.payload_hash:
            attrs.append({"key": "security.payload_hash", "value": {"stringValue": ev.payload_hash}})

        log_records.append({
            "timeUnixNano": time_nano,
            "severityNumber": sev_num,
            "severityText": ev.severity.value.upper(),
            "body": {"stringValue": f"LLMFirewall timeline event: {ev.event_type.value} -> {ev.outcome}"},
            "attributes": attrs,
            "traceId": ev.trace_id or timeline.correlation_id,
        })

    from llmfirewall._version import __version__

    return {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "llmfirewall"}},
                        {"key": "service.version", "value": {"stringValue": __version__}},
                        {"key": "correlation.id", "value": {"stringValue": timeline.correlation_id}},
                    ]
                },
                "scopeLogs": [
                    {
                        "scope": {"name": "llmfirewall.correlation", "version": "2.0"},
                        "logRecords": log_records,
                    }
                ],
            }
        ]
    }
