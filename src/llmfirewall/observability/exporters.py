"""Security Observability Exporters.

Provides clean, sanitized serialization and export utilities:
- Prometheus text format exporter (bounded labels, no sensitive data)
- JSON / JSONL exporter with privacy guarantees
- CSV exporter for compliance and reporting
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Dict, List, Optional

from llmfirewall.observability.models import SecurityEvent
from llmfirewall.observability.store import EventStore


def export_prometheus_metrics(summary: Dict[str, Any]) -> str:
    """Export summary metrics in standard Prometheus exposition format.
    
    Cardinality Invariant:
    - Zero user prompts, tokens, URLs, or high-cardinality IDs in metric labels.
    - Standard prefixed counter and gauge metrics.
    """
    lines: List[str] = [
        "# HELP llmfirewall_requests_total Total number of processed firewall inspection requests.",
        "# TYPE llmfirewall_requests_total counter",
        f"llmfirewall_requests_total {summary.get('total_requests', 0)}",
        "",
        "# HELP llmfirewall_decisions_total Number of requests grouped by enforced security action.",
        "# TYPE llmfirewall_decisions_total counter",
        f'llmfirewall_decisions_total{{action="allow"}} {summary.get("allows", 0)}',
        f'llmfirewall_decisions_total{{action="warn"}} {summary.get("warns", 0)}',
        f'llmfirewall_decisions_total{{action="redact"}} {summary.get("redactions", 0)}',
        f'llmfirewall_decisions_total{{action="block"}} {summary.get("blocks", 0)}',
        "",
        "# HELP llmfirewall_block_rate_percent Percentage of total requests blocked.",
        "# TYPE llmfirewall_block_rate_percent gauge",
        f"llmfirewall_block_rate_percent {summary.get('block_rate_percent', 0.0)}",
        "",
        "# HELP llmfirewall_latency_milliseconds Execution latency summary in milliseconds.",
        "# TYPE llmfirewall_latency_milliseconds gauge",
    ]

    lat = summary.get("latency", {})
    lines.append(f'llmfirewall_latency_milliseconds{{quantile="0.50"}} {lat.get("p50_ms", 0.0)}')
    lines.append(f'llmfirewall_latency_milliseconds{{quantile="0.95"}} {lat.get("p95_ms", 0.0)}')
    lines.append(f'llmfirewall_latency_milliseconds{{quantile="0.99"}} {lat.get("p99_ms", 0.0)}')
    lines.append(f'llmfirewall_latency_milliseconds{{quantile="avg"}} {lat.get("average_ms", 0.0)}')
    lines.append("")

    # Top detector triggers
    top_dets = summary.get("top_detectors", {})
    if top_dets:
        lines.append("# HELP llmfirewall_detector_triggers_total Total triggers recorded by detector.")
        lines.append("# TYPE llmfirewall_detector_triggers_total counter")
        for det_name, count in top_dets.items():
            safe_name = det_name.replace('"', '\\"')
            lines.append(f'llmfirewall_detector_triggers_total{{detector="{safe_name}"}} {count}')
        lines.append("")

    # Cache Operational Metrics (Phase 52)
    cache = summary.get("cache") or {}
    if cache:
        lines.append("# HELP llmfirewall_cache_hits_total Total in-memory scan cache hits.")
        lines.append("# TYPE llmfirewall_cache_hits_total counter")
        lines.append(f"llmfirewall_cache_hits_total {cache.get('hits', 0)}")
        lines.append("")
        lines.append("# HELP llmfirewall_cache_misses_total Total in-memory scan cache misses.")
        lines.append("# TYPE llmfirewall_cache_misses_total counter")
        lines.append(f"llmfirewall_cache_misses_total {cache.get('misses', 0)}")
        lines.append("")
        lines.append("# HELP llmfirewall_cache_hit_ratio Normalized cache hit ratio [0.0, 1.0].")
        lines.append("# TYPE llmfirewall_cache_hit_ratio gauge")
        lines.append(f"llmfirewall_cache_hit_ratio {cache.get('hit_ratio', 0.0)}")
        lines.append("")

    return "\n".join(lines) + "\n"


def export_events_cef(events: List[SecurityEvent]) -> str:
    """Export security events in standard ArcSight Common Event Format (CEF) for SIEM ingestion."""
    cef_lines: List[str] = []
    sev_map = {"critical": 10, "high": 7, "medium": 5, "low": 2, "info": 0}

    for e in events:
        sev_int = sev_map.get(e.severity.value.lower(), 5)
        name = f"Security Violation: {e.detector_name}" if e.detector_name else f"Firewall Event: {e.event_type.value}"
        act = e.action.value if e.action else "unknown"
        ext_parts = [
            f"act={act}",
            f"dvc={e.environment}",
            f"cs1={e.detector_name or 'none'}",
            "cs1Label=DetectorName",
            f"cs2={e.policy_id or 'none'}",
            "cs2Label=PolicyID",
            f"cfp1={e.risk_score or 0.0}",
            "cfp1Label=RiskScore",
            f"externalId={e.event_id}",
            f"rt={int(e.timestamp.timestamp() * 1000)}",
        ]
        if e.tool_name:
            ext_parts.append(f"cs3={e.tool_name} cs3Label=ToolName")
        if e.payload_hash:
            ext_parts.append(f"cs4={e.payload_hash} cs4Label=PayloadHash")

        extension = " ".join(ext_parts)
        cef_lines.append(f"CEF:0|LLMFirewall|LLMFirewallCore|1.1.0|{e.event_type.value}|{name}|{sev_int}|{extension}")

    return "\n".join(cef_lines) + "\n"


def export_events_json(events: List[SecurityEvent], indent: Optional[int] = None) -> str:
    """Export security events as a JSON array."""
    data = [e.model_dump(mode="json") for e in events]
    return json.dumps(data, indent=indent)


def export_events_jsonl(events: List[SecurityEvent]) -> str:
    """Export security events as JSON Lines (JSONL)."""
    return "\n".join(json.dumps(e.model_dump(mode="json")) for e in events) + "\n"


def export_events_csv(events: List[SecurityEvent]) -> str:
    """Export security events as tabular CSV format for audits/reporting."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "event_id",
        "timestamp",
        "event_type",
        "severity",
        "trace_id",
        "request_id",
        "component",
        "action",
        "risk_level",
        "risk_score",
        "detector_name",
        "policy_id",
        "tool_name",
        "duration_ms",
        "payload_length",
        "payload_hash",
        "environment",
    ])

    for e in events:
        writer.writerow([
            e.event_id,
            e.timestamp.isoformat(),
            e.event_type.value,
            e.severity.value,
            e.trace_id,
            e.request_id,
            e.component,
            e.action.value if e.action else "",
            e.risk_level.value if e.risk_level else "",
            e.risk_score if e.risk_score is not None else "",
            e.detector_name or "",
            e.policy_id or "",
            e.tool_name or "",
            round(e.duration_ms, 3),
            e.payload_length,
            e.payload_hash or "",
            e.environment,
        ])

    return output.getvalue()


def export_events_syslog_rfc5424(
    events: List[SecurityEvent],
    app_name: str = "llmfirewall",
    hostname: str = "localhost",
    facility: int = 10,  # 10 = security/authorization messages
) -> str:
    """Export security events formatted according to RFC 5424 (The Syslog Protocol).
    
    Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    """
    lines: List[str] = []
    # RFC 5424 severity codes: 2=Critical, 3=Error, 4=Warning, 5=Notice, 6=Informational
    sev_codes = {
        "critical": 2,
        "high": 3,
        "medium": 4,
        "low": 5,
        "info": 6,
    }

    for e in events:
        sev_code = sev_codes.get(e.severity.value.lower(), 5)
        pri = facility * 8 + sev_code
        ts = e.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        procid = "-"
        msgid = e.event_type.value
        act = e.action.value if e.action else "none"
        det = e.detector_name or "none"
        score = f"{e.risk_score:.3f}" if e.risk_score is not None else "0.000"

        sd = (
            f'[llmfirewall@41123 eventId="{e.event_id}" '
            f'traceId="{e.trace_id}" '
            f'action="{act}" '
            f'detector="{det}" '
            f'riskScore="{score}"]'
        )
        msg = f"Security event {e.event_type.value} action={act} detector={det}"
        lines.append(f"<{pri}>1 {ts} {hostname} {app_name} {procid} {msgid} {sd} {msg}")

    return "\n".join(lines) + ("\n" if lines else "")


def export_events_opentelemetry(events: List[SecurityEvent]) -> Dict[str, Any]:
    """Export security events conforming to OpenTelemetry (OTLP) LogRecords schema."""
    # Mapping to OTel severity numbers (1..24)
    otel_sev_numbers = {
        "info": 9,      # INFO
        "low": 10,     # INFO2
        "medium": 13,  # WARN
        "high": 17,    # ERROR
        "critical": 21 # FATAL
    }

    log_records = []
    for e in events:
        sev_str = e.severity.value.lower()
        sev_num = otel_sev_numbers.get(sev_str, 9)
        time_nano = int(e.timestamp.timestamp() * 1_000_000_000)

        attrs = [
            {"key": "gen_ai.system", "value": {"stringValue": "llmfirewall"}},
            {"key": "security.event_id", "value": {"stringValue": e.event_id}},
            {"key": "security.event_type", "value": {"stringValue": e.event_type.value}},
            {"key": "security.action", "value": {"stringValue": e.action.value if e.action else "none"}},
            {"key": "security.environment", "value": {"stringValue": e.environment}},
        ]
        if e.detector_name:
            attrs.append({"key": "security.detector_name", "value": {"stringValue": e.detector_name}})
        if e.risk_score is not None:
            attrs.append({"key": "security.risk_score", "value": {"doubleValue": float(e.risk_score)}})
        if e.tool_name:
            attrs.append({"key": "security.tool_name", "value": {"stringValue": e.tool_name}})
        if e.payload_hash:
            attrs.append({"key": "security.payload_hash", "value": {"stringValue": e.payload_hash}})

        log_records.append({
            "timeUnixNano": time_nano,
            "severityNumber": sev_num,
            "severityText": e.severity.value.upper(),
            "body": {"stringValue": f"LLMFirewall event: {e.event_type.value} -> {e.action.value if e.action else 'none'}"},
            "attributes": attrs,
            "traceId": e.trace_id,
        })

    return {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "llmfirewall"}},
                        {"key": "service.version", "value": {"stringValue": "1.2.0"}},
                    ]
                },
                "scopeLogs": [
                    {
                        "scope": {"name": "llmfirewall.observability", "version": "1.2.0"},
                        "logRecords": log_records,
                    }
                ],
            }
        ]
    }

