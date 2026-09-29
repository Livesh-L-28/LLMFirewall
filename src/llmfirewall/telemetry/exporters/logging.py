"""Standard in-memory and logging-backed TelemetrySink implementations."""

import logging
from typing import List, Optional

from llmfirewall.core.models import ScanRequest, ScanResult
from llmfirewall.telemetry.events import TelemetryEvent
from llmfirewall.telemetry.metrics import MetricsCollector, MetricSummary
from llmfirewall.telemetry.sink import TelemetrySink


class InMemoryTelemetrySink(TelemetrySink):
    """Production-ready in-memory telemetry collector and optional logger exporter.
    
    Guarantees:
    - Thread-safe metric collection.
    - Strict privacy invariants (never stores raw prompts, secrets, or PII).
    - Failure isolation: sinks log internal errors without raising exceptions into firewall checks.
    """

    def __init__(
        self,
        enable_events: bool = True,
        enable_metrics: bool = True,
        max_buffered_events: int = 1000,
        logger_name: Optional[str] = None,
        log_level: int = logging.INFO,
    ) -> None:
        self.enable_events = enable_events
        self.enable_metrics = enable_metrics
        self.max_buffered_events = max_buffered_events
        self._metrics = MetricsCollector()
        self._events: List[TelemetryEvent] = []
        self._logger = logging.getLogger(logger_name) if logger_name else None
        if self._logger:
            self._logger.setLevel(log_level)

    def record_scan(self, request: ScanRequest, result: ScanResult) -> None:
        try:
            # 1. Update Metrics
            if self.enable_metrics:
                self._metrics.increment_scan(result.decision.action.value)
                self._metrics.record_duration(result.execution_time_ms)
                for f in result.findings:
                    cat = f.metadata.get("pii_category") or f.metadata.get("rule_id") or f.category
                    self._metrics.record_finding(cat)

            # 2. Record Structured Event
            if self.enable_events:
                event = TelemetryEvent.from_scan(request=request, result=result)
                if len(self._events) >= self.max_buffered_events:
                    # Bounded circular eviction
                    self._events.pop(0)
                self._events.append(event)

                if self._logger:
                    self._logger.info(
                        "Firewall Telemetry: action=%s risk_score=%.2f threats=%s latency=%.2fms req_id=%s",
                        event.action.value,
                        event.risk_score,
                        event.threat_types,
                        event.latency_ms,
                        event.request_id,
                    )
        except Exception as exc:
            # Failure Isolation: Telemetry failure must never bubble up into scan decisions
            if self._logger:
                self._logger.error("TelemetrySink encountered error during record_scan: %s", exc)

    def record_error(self, request_id: str, error_message: str) -> None:
        try:
            if self.enable_metrics:
                self._metrics.increment_error()

            if self.enable_events:
                event = TelemetryEvent.from_error(request_id=request_id, error_message=error_message)
                if len(self._events) >= self.max_buffered_events:
                    self._events.pop(0)
                self._events.append(event)

                if self._logger:
                    self._logger.error(
                        "Firewall Telemetry Error: req_id=%s error=%s",
                        request_id,
                        error_message,
                    )
        except Exception:
            pass

    def get_metrics_summary(self) -> MetricSummary:
        return self._metrics.snapshot()

    def get_events(self) -> List[TelemetryEvent]:
        return list(self._events)

    def clear(self) -> None:
        self._metrics.reset()
        self._events.clear()
