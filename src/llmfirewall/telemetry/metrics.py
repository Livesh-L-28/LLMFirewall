"""Provider-neutral metrics representation and in-memory aggregation collector."""

import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class MetricSummary:
    """Summary snapshot of aggregated metrics."""
    scans_total: int = 0
    allowed_total: int = 0
    warned_total: int = 0
    blocked_total: int = 0
    redacted_total: int = 0
    errors_total: int = 0
    detector_findings_total: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    total_duration_ms: float = 0.0
    scan_count_with_duration: int = 0

    @property
    def average_latency_ms(self) -> float:
        if self.scan_count_with_duration == 0:
            return 0.0
        return round(self.total_duration_ms / self.scan_count_with_duration, 3)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "llmfirewall_scans_total": self.scans_total,
            "llmfirewall_allowed_total": self.allowed_total,
            "llmfirewall_warned_total": self.warned_total,
            "llmfirewall_blocked_total": self.blocked_total,
            "llmfirewall_redacted_total": self.redacted_total,
            "llmfirewall_errors_total": self.errors_total,
            "llmfirewall_average_latency_ms": self.average_latency_ms,
            "llmfirewall_detector_findings_total": dict(self.detector_findings_total),
        }


class MetricsCollector:
    """Thread-safe, bounded, provider-neutral metrics registry.
    
    Cardinals:
    - Fixed low-cardinality label keys only (action, detector_category).
    - Never uses prompts, tokens, or user IDs as metric labels.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._scans_total = 0
        self._action_counts: Dict[str, int] = defaultdict(int)
        self._errors_total = 0
        self._findings_by_category: Dict[str, int] = defaultdict(int)
        self._total_duration_ms = 0.0
        self._duration_samples = 0

    def increment_scan(self, action: str) -> None:
        """Increment scan count and action counter."""
        with self._lock:
            self._scans_total += 1
            self._action_counts[action.lower()] += 1

    def increment_error(self) -> None:
        """Increment error counter."""
        with self._lock:
            self._errors_total += 1

    def record_finding(self, category: str, count: int = 1) -> None:
        """Increment findings counter for a specific threat category."""
        with self._lock:
            self._findings_by_category[category] += count

    def record_duration(self, duration_ms: float) -> None:
        """Record scan duration in milliseconds."""
        with self._lock:
            self._total_duration_ms += duration_ms
            self._duration_samples += 1

    def snapshot(self) -> MetricSummary:
        """Return an atomic snapshot of current metric values."""
        with self._lock:
            return MetricSummary(
                scans_total=self._scans_total,
                allowed_total=self._action_counts.get("allow", 0),
                warned_total=self._action_counts.get("warn", 0),
                blocked_total=self._action_counts.get("block", 0),
                redacted_total=self._action_counts.get("redact", 0),
                errors_total=self._errors_total,
                detector_findings_total=dict(self._findings_by_category),
                total_duration_ms=self._total_duration_ms,
                scan_count_with_duration=self._duration_samples,
            )

    def reset(self) -> None:
        """Reset all counters to zero."""
        with self._lock:
            self._scans_total = 0
            self._action_counts.clear()
            self._errors_total = 0
            self._findings_by_category.clear()
            self._total_duration_ms = 0.0
            self._duration_samples = 0
