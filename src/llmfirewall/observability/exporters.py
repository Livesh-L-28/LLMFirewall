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

    return "\n".join(lines) + "\n"


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
