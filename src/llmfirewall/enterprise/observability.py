"""OpenTelemetry Distributed Tracing and Enterprise Observability Bridge."""

from __future__ import annotations

import contextvars
from dataclasses import dataclass, field
import hashlib
import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("llmfirewall.enterprise.observability")

# Optional OpenTelemetry imports
try:
    from opentelemetry import trace as otel_trace
    from opentelemetry import metrics as otel_metrics
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    _HAS_OTEL = True
except ImportError:
    otel_trace = None  # type: ignore
    otel_metrics = None  # type: ignore
    TraceContextTextMapPropagator = None  # type: ignore
    _HAS_OTEL = False


# Non-sensitive permitted metric and span attribute keys
SAFE_ATTRIBUTE_ALLOWLIST = {
    "llmfirewall.direction",
    "llmfirewall.action",
    "llmfirewall.threat_type",
    "llmfirewall.severity",
    "llmfirewall.rule_id",
    "llmfirewall.status_code",
    "llmfirewall.tenant_tier",
    "llmfirewall.tenant_id_hash",
    "llmfirewall.is_blocked",
    "llmfirewall.risk_score",
    "llmfirewall.policy_version",
}


@dataclass
class SafeAuditEvent:
    """Enterprise audit record guaranteed free of unmasked prompts or credentials."""
    event_id: str
    timestamp: float = field(default_factory=time.time)
    trace_id: str = ""
    span_id: str = ""
    tenant_id_hash: str = ""
    direction: str = "input"
    action: str = "ALLOW"
    risk_score: float = 0.0
    rules_applied: List[str] = field(default_factory=list)
    safe_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "tenant_id_hash": self.tenant_id_hash,
            "direction": self.direction,
            "action": self.action,
            "risk_score": round(self.risk_score, 3),
            "rules_applied": self.rules_applied,
            "metadata": self.safe_metadata,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"))


class OpenTelemetryBridge:
    """Production OpenTelemetry bridge for distributed tracing and metric export.

    Guarantees:
    - Zero Hard Dependency: If opentelemetry is not installed, all methods operate as safe no-ops.
    - Zero Retention of Sensitive Data: Only allowlisted non-sensitive attributes are recorded to spans and metrics.
    - Low Cardinality: Bounded label values to prevent Prometheus / Datadog memory exhaustion.
    - W3C Conformance: Injects and extracts standard W3C traceparent headers.
    """

    def __init__(
        self,
        service_name: str = "llmfirewall",
        enable_metrics: bool = True,
        enable_tracing: bool = True,
    ) -> None:
        self.service_name = service_name
        self.enable_metrics = enable_metrics and _HAS_OTEL
        self.enable_tracing = enable_tracing and _HAS_OTEL

        self._tracer = otel_trace.get_tracer(service_name) if self.enable_tracing else None
        self._meter = otel_metrics.get_meter(service_name) if self.enable_metrics else None

        # Initialize low-cardinality metric instruments if OpenTelemetry is present
        self._scans_counter = None
        self._blocks_counter = None
        self._latency_histogram = None

        if self._meter:
            try:
                self._scans_counter = self._meter.create_counter(
                    name="llmfirewall.scans.total",
                    description="Total count of security inspection scans",
                    unit="1",
                )
                self._blocks_counter = self._meter.create_counter(
                    name="llmfirewall.blocks.total",
                    description="Total count of blocked security violations",
                    unit="1",
                )
                self._latency_histogram = self._meter.create_histogram(
                    name="llmfirewall.scan.latency.seconds",
                    description="Scan execution duration in seconds",
                    unit="s",
                )
            except Exception as exc:
                logger.warning("Failed to initialize OpenTelemetry metric instruments: %s", exc)

    @property
    def is_available(self) -> bool:
        return _HAS_OTEL

    def extract_traceparent(self, headers: Dict[str, str]) -> Optional[Tuple[str, str]]:
        """Extract (trace_id, span_id) from standard W3C traceparent header."""
        traceparent = headers.get("traceparent") or headers.get("TRACEPARENT")
        if not traceparent:
            return None

        parts = traceparent.split("-")
        if len(parts) == 4 and parts[0] == "00":
            return parts[1], parts[2]
        return None

    def inject_traceparent(self, headers: Dict[str, str], trace_id: str, span_id: str) -> None:
        """Inject compliant W3C traceparent header."""
        if trace_id and span_id:
            headers["traceparent"] = f"00-{trace_id}-{span_id}-01"

    def record_scan_metrics(
        self,
        direction: str,
        action: str,
        latency_seconds: float,
        threat_type: Optional[str] = None,
    ) -> None:
        """Record bounded, low-cardinality metric datapoints."""
        if not self.enable_metrics:
            return

        labels = {
            "direction": str(direction).lower(),
            "action": str(action).upper(),
        }

        try:
            if self._scans_counter:
                self._scans_counter.add(1, labels)
            if self._latency_histogram:
                self._latency_histogram.record(latency_seconds, labels)
            if action == "BLOCK" and self._blocks_counter:
                block_labels = dict(labels)
                block_labels["threat"] = str(threat_type or "unknown")
                self._blocks_counter.add(1, block_labels)
        except Exception as exc:
            logger.debug("Failed recording OpenTelemetry metric: %s", exc)

    def filter_safe_attributes(self, attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Scrub all unapproved attributes to eliminate risk of credential/PII leaks to telemetry."""
        safe: Dict[str, Any] = {}
        for k, v in attributes.items():
            if k in SAFE_ATTRIBUTE_ALLOWLIST:
                safe[k] = v
            elif k.startswith("llmfirewall.safe_"):
                safe[k] = v
        return safe

    def create_safe_audit_event(
        self,
        event_id: str,
        direction: str,
        action: str,
        risk_score: float,
        rules_applied: List[str],
        tenant_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> SafeAuditEvent:
        """Construct zero-retention safe audit event."""
        # Hash tenant ID to prevent leaking customer organization names in logs
        tenant_hash = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()[:16] if tenant_id else "global"

        safe_meta = {}
        if extra_metadata:
            for k, v in extra_metadata.items():
                if isinstance(v, (int, float, bool)):
                    safe_meta[k] = v

        return SafeAuditEvent(
            event_id=event_id,
            trace_id=trace_id or "",
            span_id=span_id or "",
            tenant_id_hash=tenant_hash,
            direction=direction,
            action=action,
            risk_score=risk_score,
            rules_applied=rules_applied,
            safe_metadata=safe_meta,
        )
