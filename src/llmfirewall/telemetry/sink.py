"""Abstract TelemetrySink interface and NoOpTelemetry implementation."""

from abc import ABC, abstractmethod
from typing import List

from llmfirewall.core.models import ScanRequest, ScanResult
from llmfirewall.telemetry.events import TelemetryEvent
from llmfirewall.telemetry.metrics import MetricSummary


class TelemetrySink(ABC):
    """Abstract interface for security telemetry and observability backends."""

    @abstractmethod
    def record_scan(self, request: ScanRequest, result: ScanResult) -> None:
        """Record a completed firewall scan outcome, updating events, metrics, and timings."""

    @abstractmethod
    def record_error(self, request_id: str, error_message: str) -> None:
        """Record an unhandled exception or critical firewall error."""

    @abstractmethod
    def get_metrics_summary(self) -> MetricSummary:
        """Return the current aggregated metrics snapshot."""

    @abstractmethod
    def get_events(self) -> List[TelemetryEvent]:
        """Return a copy of captured structured events."""

    @abstractmethod
    def clear(self) -> None:
        """Reset captured metrics and events."""


class NoOpTelemetry(TelemetrySink):
    """Zero-overhead default telemetry sink performing no I/O, storage, or aggregation."""

    def record_scan(self, request: ScanRequest, result: ScanResult) -> None:
        pass

    def record_error(self, request_id: str, error_message: str) -> None:
        pass

    def get_metrics_summary(self) -> MetricSummary:
        return MetricSummary()

    def get_events(self) -> List[TelemetryEvent]:
        return []

    def clear(self) -> None:
        pass
