"""Security Dashboard Read API for LLMFirewall v1.1.0 (Phase 54).

Provides aggregated metrics, timeseries buckets, and sanitized event streams
for security portals, SOC consoles, and executive dashboards without sensitive text exposure.
"""

from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.cache.scan_cache import ScanCacheMetrics
from llmfirewall.core.models import Action, Severity
from llmfirewall.observability.models import EventSeverity, SecurityEvent, SecurityEventType
from llmfirewall.observability.store import EventFilter, EventStore


class DashboardSummary(BaseModel):
    """High-level security posture summary for SOC and executive dashboards."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    total_requests: int = Field(default=0)
    total_blocked: int = Field(default=0)
    total_redacted: int = Field(default=0)
    total_warned: int = Field(default=0)
    total_allowed: int = Field(default=0)
    block_rate_percent: float = Field(default=0.0)
    p50_latency_ms: float = Field(default=0.0)
    p95_latency_ms: float = Field(default=0.0)
    p99_latency_ms: float = Field(default=0.0)
    average_latency_ms: float = Field(default=0.0)
    threat_breakdown: Dict[str, int] = Field(default_factory=dict)
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    cache_metrics: Optional[ScanCacheMetrics] = None


class TimeseriesBucket(BaseModel):
    """Time-window aggregated metrics bucket."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    timestamp_start: str
    total_requests: int = Field(default=0)
    blocked: int = Field(default=0)
    redacted: int = Field(default=0)
    threats_detected: int = Field(default=0)


class SanitizedDashboardEvent(BaseModel):
    """Sanitized security event guaranteed free of raw sensitive prompts and secret keys."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    timestamp: str
    event_type: str
    severity: str
    action: Optional[str]
    risk_level: Optional[str]
    risk_score: Optional[float]
    detector_name: Optional[str]
    tool_name: Optional[str]
    duration_ms: float
    payload_hash: Optional[str]
    environment: str


class PaginatedEventsResponse(BaseModel):
    """Paginated security events response."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    events: List[SanitizedDashboardEvent]
    total_count: int
    offset: int
    limit: int


class SecurityDashboardAPI:
    """Read-only dashboard query and analytics interface."""

    def __init__(self, store: EventStore, cache_metrics_provider: Optional[Any] = None) -> None:
        self.store = store
        self.cache_metrics_provider = cache_metrics_provider

    def get_summary(self, time_window_seconds: Optional[int] = None) -> DashboardSummary:
        """Compute aggregated posture metrics across all recorded security events."""
        now = datetime.now(timezone.utc)
        start_time = None
        if time_window_seconds:
            start_time = datetime.fromtimestamp(now.timestamp() - time_window_seconds, tz=timezone.utc)

        flt = EventFilter(since=start_time, until=now, limit=1000000)
        events = self.store.query(flt)

        total_reqs = len(events)
        blocks = sum(1 for e in events if e.action == Action.BLOCK)
        redacts = sum(1 for e in events if e.action == Action.REDACT)
        warns = sum(1 for e in events if e.action == Action.WARN)
        allows = sum(1 for e in events if e.action == Action.ALLOW)
        block_rate = round((blocks / total_reqs * 100.0) if total_reqs > 0 else 0.0, 2)

        durations = sorted([e.duration_ms for e in events])
        p50 = 0.0
        p95 = 0.0
        p99 = 0.0
        avg_lat = 0.0
        if durations:
            avg_lat = round(sum(durations) / len(durations), 3)
            p50 = round(durations[int(len(durations) * 0.50)], 3)
            p95 = round(durations[int(len(durations) * 0.95)], 3)
            p99 = round(durations[min(len(durations) - 1, int(len(durations) * 0.99))], 3)

        threat_breakdown: Dict[str, int] = {}
        severity_breakdown: Dict[str, int] = {}

        for e in events:
            sev_key = e.severity.value.lower()
            severity_breakdown[sev_key] = severity_breakdown.get(sev_key, 0) + 1

            if e.detector_name:
                threat_breakdown[e.detector_name] = threat_breakdown.get(e.detector_name, 0) + 1

        cache_metrics = None
        if self.cache_metrics_provider and hasattr(self.cache_metrics_provider, "get_metrics"):
            cache_metrics = self.cache_metrics_provider.get_metrics()

        return DashboardSummary(
            total_requests=total_reqs,
            total_blocked=blocks,
            total_redacted=redacts,
            total_warned=warns,
            total_allowed=allows,
            block_rate_percent=block_rate,
            p50_latency_ms=p50,
            p95_latency_ms=p95,
            p99_latency_ms=p99,
            average_latency_ms=avg_lat,
            threat_breakdown=threat_breakdown,
            severity_breakdown=severity_breakdown,
            cache_metrics=cache_metrics,
        )

    def get_events(
        self,
        offset: int = 0,
        limit: int = 50,
        severity: Optional[str] = None,
        action: Optional[str] = None,
    ) -> PaginatedEventsResponse:
        """Retrieve paginated, sanitized security events with zero payload leakage."""
        sev_enum = None
        if severity:
            sev_upper = severity.upper()
            try:
                sev_enum = EventSeverity(sev_upper)
            except ValueError:
                sev_enum = getattr(EventSeverity, sev_upper, None)

        act_enum = None
        if action:
            act_lower = action.lower()
            try:
                act_enum = Action(act_lower)
            except ValueError:
                act_enum = getattr(Action, act_lower.upper(), None)

        count_filter = EventFilter(
            severities=[sev_enum] if sev_enum else None,
            actions=[act_enum] if act_enum else None,
            limit=1000000,
        )
        total_count = self.store.count(count_filter)

        ev_filter = EventFilter(
            severities=[sev_enum] if sev_enum else None,
            actions=[act_enum] if act_enum else None,
            limit=limit,
            offset=offset,
        )
        paged = self.store.query(ev_filter)
        sanitized: List[SanitizedDashboardEvent] = []

        for e in paged:
            sanitized.append(
                SanitizedDashboardEvent(
                    event_id=e.event_id,
                    timestamp=e.timestamp.isoformat(),
                    event_type=e.event_type.value,
                    severity=e.severity.value.lower(),
                    action=e.action.value if e.action else None,
                    risk_level=e.risk_level.value if e.risk_level else None,
                    risk_score=e.risk_score,
                    detector_name=e.detector_name,
                    tool_name=e.tool_name,
                    duration_ms=round(e.duration_ms, 3),
                    payload_hash=e.payload_hash,
                    environment=e.environment,
                )
            )

        return PaginatedEventsResponse(
            events=sanitized,
            total_count=total_count,
            offset=offset,
            limit=limit,
        )

    def get_timeseries(
        self,
        window_seconds: int = 3600,
        bucket_count: int = 6,
    ) -> List[TimeseriesBucket]:
        """Aggregate events into chronological time buckets."""
        now = time.time()
        bucket_size = window_seconds / max(1, bucket_count)
        buckets: List[TimeseriesBucket] = []

        for i in range(bucket_count):
            t_start = now - window_seconds + (i * bucket_size)
            t_end = t_start + bucket_size
            dt_start = datetime.fromtimestamp(t_start, tz=timezone.utc)
            dt_end = datetime.fromtimestamp(t_end, tz=timezone.utc)

            events = self.store.query(EventFilter(since=dt_start, until=dt_end, limit=1000000))
            reqs = len(events)
            blks = sum(1 for e in events if e.action == Action.BLOCK)
            reds = sum(1 for e in events if e.action == Action.REDACT)
            threats = sum(1 for e in events if e.severity in (EventSeverity.HIGH, EventSeverity.CRITICAL))

            buckets.append(
                TimeseriesBucket(
                    timestamp_start=dt_start.isoformat(),
                    total_requests=reqs,
                    blocked=blks,
                    redacted=reds,
                    threats_detected=threats,
                )
            )

        return buckets
