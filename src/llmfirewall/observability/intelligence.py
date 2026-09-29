"""Security Intelligence, Aggregation, Trend Analysis, and Anomaly Detection Engine.

Provides deep operational and security analytics over stored events:
- Total requests, blocks, warnings, redactions
- Breakdown by detector, policy, tool, risk level
- Period-over-period trend analysis
- Conservative anomaly indicators (statistical baseline deviation)
- Performance & latency percentile analysis (P50, P95, P99)
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from llmfirewall.core.models import Action, Severity
from llmfirewall.observability.models import AnomalyEvent, EventSeverity, SecurityEvent, SecurityEventType
from llmfirewall.observability.store import EventFilter, EventStore


class SecurityIntelligenceEngine:
    """Analytical and intelligence query processor over an EventStore."""

    def __init__(self, store: EventStore) -> None:
        self._store = store

    @property
    def store(self) -> EventStore:
        return self._store

    def summary(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        application_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Compute comprehensive security intelligence summary."""
        events = self._get_events_in_window(since, until)
        if application_id:
            events = [e for e in events if e.application_id == application_id]

        total_requests = len(events)
        action_counts: Dict[str, int] = defaultdict(int)
        severity_counts: Dict[str, int] = defaultdict(int)
        detector_counts: Dict[str, int] = defaultdict(int)
        policy_counts: Dict[str, int] = defaultdict(int)
        tool_counts: Dict[str, int] = defaultdict(int)
        durations: List[float] = []

        for e in events:
            if e.action:
                action_counts[e.action.value] += 1
            if e.risk_level:
                severity_counts[e.risk_level.value] += 1
            if e.detector_name:
                detector_counts[e.detector_name] += 1
            if e.policy_id:
                policy_counts[e.policy_id] += 1
            if e.tool_name:
                tool_counts[e.tool_name] += 1
            if e.duration_ms > 0:
                durations.append(e.duration_ms)

        # Percentile latency calculation
        latencies = self._calculate_percentiles(durations)

        # Risk distribution percentages
        risk_dist = {}
        for sev in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            count = severity_counts.get(sev, 0) + severity_counts.get(sev.lower(), 0)
            pct = (count / total_requests * 100.0) if total_requests > 0 else 0.0
            risk_dist[sev] = round(pct, 2)

        blocks = action_counts.get(Action.BLOCK.value, 0)
        block_rate = round((blocks / total_requests * 100.0), 2) if total_requests > 0 else 0.0

        return {
            "total_requests": total_requests,
            "blocks": blocks,
            "block_rate_percent": block_rate,
            "warns": action_counts.get(Action.WARN.value, 0),
            "redactions": action_counts.get(Action.REDACT.value, 0),
            "allows": action_counts.get(Action.ALLOW.value, 0),
            "risk_distribution_percent": risk_dist,
            "top_detectors": dict(sorted(detector_counts.items(), key=lambda x: x[1], reverse=True)[:5]),
            "top_policies": dict(sorted(policy_counts.items(), key=lambda x: x[1], reverse=True)[:5]),
            "top_tools": dict(sorted(tool_counts.items(), key=lambda x: x[1], reverse=True)[:5]),
            "latency": latencies,
        }

    def detector_analytics(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Detailed breakdown per detector: triggers, blocks, warnings, average latency."""
        events = self._get_events_in_window(since, until)
        breakdown: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"triggers": 0, "blocks": 0, "warns": 0, "latencies": []}
        )

        for e in events:
            if not e.detector_name:
                continue
            entry = breakdown[e.detector_name]
            entry["triggers"] += 1
            if e.action == Action.BLOCK:
                entry["blocks"] += 1
            elif e.action == Action.WARN:
                entry["warns"] += 1
            if e.duration_ms > 0:
                entry["latencies"].append(e.duration_ms)

        results = []
        for det, stats in sorted(breakdown.items(), key=lambda x: x[1]["triggers"], reverse=True):
            avg_lat = round(sum(stats["latencies"]) / len(stats["latencies"]), 3) if stats["latencies"] else 0.0
            results.append({
                "detector": det,
                "triggers": stats["triggers"],
                "blocks": stats["blocks"],
                "warns": stats["warns"],
                "average_latency_ms": avg_lat,
            })
        return results

    def policy_analytics(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Detailed breakdown per policy and version: evaluations, blocks, allows, warns."""
        events = self._get_events_in_window(since, until)
        breakdown: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"evaluations": 0, "allows": 0, "warns": 0, "blocks": 0, "redacts": 0, "versions": set()}
        )

        for e in events:
            pid = e.policy_id or "default"
            entry = breakdown[pid]
            entry["evaluations"] += 1
            if e.policy_version:
                entry["versions"].add(e.policy_version)
            if e.action == Action.ALLOW:
                entry["allows"] += 1
            elif e.action == Action.WARN:
                entry["warns"] += 1
            elif e.action == Action.BLOCK:
                entry["blocks"] += 1
            elif e.action == Action.REDACT:
                entry["redacts"] += 1

        results = []
        for pid, stats in sorted(breakdown.items(), key=lambda x: x[1]["evaluations"], reverse=True):
            results.append({
                "policy_id": pid,
                "versions": sorted(list(stats["versions"])),
                "evaluations": stats["evaluations"],
                "allows": stats["allows"],
                "warns": stats["warns"],
                "blocks": stats["blocks"],
                "redacts": stats["redacts"],
            })
        return results

    def tool_security_analytics(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Detailed breakdown per tool: invocations, allows, blocks, violations."""
        events = self._get_events_in_window(since, until)
        tool_events = [e for e in events if e.tool_name is not None]

        breakdown: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"calls": 0, "allowed": 0, "blocked": 0, "warned": 0, "threat_counts": defaultdict(int)}
        )

        for e in tool_events:
            tname = e.tool_name or "unknown"
            entry = breakdown[tname]
            entry["calls"] += 1
            if e.action == Action.BLOCK:
                entry["blocked"] += 1
            elif e.action == Action.WARN:
                entry["warned"] += 1
            else:
                entry["allowed"] += 1

            for threat in e.threat_types:
                entry["threat_counts"][threat] += 1

        results = []
        for tname, stats in sorted(breakdown.items(), key=lambda x: x[1]["calls"], reverse=True):
            results.append({
                "tool_name": tname,
                "calls": stats["calls"],
                "allowed": stats["allowed"],
                "blocked": stats["blocked"],
                "warned": stats["warned"],
                "threat_breakdown": dict(stats["threat_counts"]),
            })
        return results

    def trend_analysis(self, window_hours: int = 24) -> Dict[str, Any]:
        """Compute period-over-period percentage change between two adjacent time windows.
        
        Example: Compare the last 24h against the preceding 24h.
        Invariant:
        - Labels changes as 'observed increase' or 'observed decrease', avoiding unsubstantiated causality claims.
        """
        now = datetime.now(timezone.utc)
        current_start = now - timedelta(hours=window_hours)
        previous_start = current_start - timedelta(hours=window_hours)

        current_events = self._get_events_in_window(since=current_start, until=now)
        prev_events = self._get_events_in_window(since=previous_start, until=current_start)

        def _calc_metrics(ev_list: List[SecurityEvent]) -> Dict[str, Any]:
            blocks = sum(1 for e in ev_list if e.action == Action.BLOCK)
            warns = sum(1 for e in ev_list if e.action == Action.WARN)
            tool_blocks = sum(1 for e in ev_list if e.action == Action.BLOCK and e.tool_name)
            return {
                "total": len(ev_list),
                "blocks": blocks,
                "warns": warns,
                "tool_blocks": tool_blocks,
            }

        curr_stats = _calc_metrics(current_events)
        prev_stats = _calc_metrics(prev_events)

        def _delta_pct(curr: int, prev: int) -> float:
            if prev == 0:
                return 100.0 if curr > 0 else 0.0
            return round(((curr - prev) / prev) * 100.0, 2)

        return {
            "window_hours": window_hours,
            "current_period": {
                "start": current_start.isoformat(),
                "end": now.isoformat(),
                **curr_stats,
            },
            "previous_period": {
                "start": previous_start.isoformat(),
                "end": current_start.isoformat(),
                **prev_stats,
            },
            "deltas_percent": {
                "total_requests": _delta_pct(curr_stats["total"], prev_stats["total"]),
                "blocks": _delta_pct(curr_stats["blocks"], prev_stats["blocks"]),
                "warns": _delta_pct(curr_stats["warns"], prev_stats["warns"]),
                "tool_blocks": _delta_pct(curr_stats["tool_blocks"], prev_stats["tool_blocks"]),
            },
        }

    def detect_anomalies(
        self,
        window_minutes: int = 60,
        baseline_windows: int = 5,
        threshold_multiplier: float = 2.0,
    ) -> List[AnomalyEvent]:
        """Statistical baseline anomaly detection over recent time windows.
        
        Calculates mean and standard deviation across historical baseline windows.
        Emits AnomalyEvent when current window metric exceeds baseline + (multiplier * stddev).
        """
        now = datetime.now(timezone.utc)
        curr_start = now - timedelta(minutes=window_minutes)
        curr_events = self._get_events_in_window(since=curr_start, until=now)

        curr_blocks = sum(1 for e in curr_events if e.action == Action.BLOCK)
        curr_tool_blocks = sum(1 for e in curr_events if e.action == Action.BLOCK and e.tool_name)

        # Collect historical baseline windows
        hist_blocks: List[int] = []
        hist_tool_blocks: List[int] = []

        for i in range(1, baseline_windows + 1):
            w_end = curr_start - timedelta(minutes=(i - 1) * window_minutes)
            w_start = curr_start - timedelta(minutes=i * window_minutes)
            w_events = self._get_events_in_window(since=w_start, until=w_end)
            hist_blocks.append(sum(1 for e in w_events if e.action == Action.BLOCK))
            hist_tool_blocks.append(sum(1 for e in w_events if e.action == Action.BLOCK and e.tool_name))

        anomalies: List[AnomalyEvent] = []

        # Analyze blocks
        anom_block = self._check_metric_anomaly(
            metric_name="requests_blocked",
            observed=float(curr_blocks),
            history=hist_blocks,
            window_minutes=window_minutes,
            multiplier=threshold_multiplier,
        )
        if anom_block:
            anomalies.append(anom_block)

        # Analyze tool blocks
        anom_tool = self._check_metric_anomaly(
            metric_name="tool_blocks",
            observed=float(curr_tool_blocks),
            history=hist_tool_blocks,
            window_minutes=window_minutes,
            multiplier=threshold_multiplier,
        )
        if anom_tool:
            anomalies.append(anom_tool)

        return anomalies

    def _check_metric_anomaly(
        self,
        metric_name: str,
        observed: float,
        history: List[int],
        window_minutes: int,
        multiplier: float,
    ) -> Optional[AnomalyEvent]:
        if not history or sum(history) == 0:
            if observed >= 5:  # Significant activity from dead zero
                return AnomalyEvent(
                    metric_name=metric_name,
                    observed_value=observed,
                    baseline_value=0.0,
                    deviation_percent=100.0,
                    window_minutes=window_minutes,
                    severity=EventSeverity.WARNING,
                    description=f"Unusual activity observed in '{metric_name}' (observed {int(observed)}, baseline 0).",
                )
            return None

        mean = sum(history) / len(history)
        variance = sum((x - mean) ** 2 for x in history) / len(history)
        stddev = math.sqrt(variance)

        threshold = mean + (multiplier * max(stddev, 1.0))
        if observed > threshold and observed >= 3:
            deviation_pct = round(((observed - mean) / mean) * 100.0, 2)
            sev = EventSeverity.HIGH if observed > (mean + 3.0 * max(stddev, 1.0)) else EventSeverity.WARNING
            return AnomalyEvent(
                metric_name=metric_name,
                observed_value=observed,
                baseline_value=round(mean, 2),
                deviation_percent=deviation_pct,
                window_minutes=window_minutes,
                severity=sev,
                description=f"Unusual increase observed in '{metric_name}' (+{deviation_pct}% vs baseline of {round(mean, 1)}).",
            )
        return None

    def _get_events_in_window(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> List[SecurityEvent]:
        flt = EventFilter(since=since, until=until, limit=100000)
        return self._store.query(flt)

    def _calculate_percentiles(self, values: List[float]) -> Dict[str, float]:
        if not values:
            return {"average_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0}

        sorted_vals = sorted(values)
        n = len(sorted_vals)

        def _p(pct: float) -> float:
            idx = int(math.ceil((pct / 100.0) * n)) - 1
            return round(sorted_vals[max(0, min(idx, n - 1))], 3)

        avg = round(sum(sorted_vals) / n, 3)
        return {
            "average_ms": avg,
            "p50_ms": _p(50),
            "p95_ms": _p(95),
            "p99_ms": _p(99),
        }
