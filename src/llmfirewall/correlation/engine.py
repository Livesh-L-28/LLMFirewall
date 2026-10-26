"""Unified Security Event Correlation Engine.

Phase 4: Unified Security Event Correlation.
Handles:
- Deterministic correlation across requests, multi-step agent workflows, RAG, and tools.
- Idempotent deduplication: Repeated event ingestion does not duplicate entries.
- Causal and chronological ordering: Resolves timestamps, sequence numbers, and parent_event_id DAGs.
- Incomplete trace detection: Flags sequence gaps and dangling causal references.
- Multi-tenant isolation: Strictly enforces tenant boundaries on all correlations and queries.
- Bounded memory LRU & TTL expiration: Automatically prunes stale correlation sessions.
- Fail-safe isolation: Ingestion and storage errors are caught safely and never compromise security gating.
"""

from __future__ import annotations

import collections
from datetime import datetime, timezone
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Set, Union

from llmfirewall.core.models import Action
from llmfirewall.correlation.models import CorrelatedIncidentTimeline, UnifiedSecurityEvent
from llmfirewall.correlation.sanitizer import sanitize_metadata, sanitize_string
from llmfirewall.observability.models import EventSeverity, SecurityEvent, SecurityEventType
from llmfirewall.workflow.models import CrossTenantViolationError

logger = logging.getLogger("llmfirewall.correlation.engine")


class EventCorrelationEngine:
    """Coordinates event ingestion, causal correlation, deduplication, and timeline construction."""

    def __init__(
        self,
        max_active_sessions: int = 1000,
        session_ttl_seconds: float = 3600.0,
    ) -> None:
        self.max_active_sessions = max_active_sessions
        self.session_ttl_seconds = session_ttl_seconds
        self._lock = threading.RLock()

        # In-memory session store: correlation_id -> List[UnifiedSecurityEvent]
        self._sessions: collections.OrderedDict[str, List[UnifiedSecurityEvent]] = collections.OrderedDict()
        # Session tenant bindings: correlation_id -> tenant_id
        self._session_tenants: Dict[str, Optional[str]] = {}
        # Session last active timestamps: correlation_id -> float
        self._session_timestamps: Dict[str, float] = {}
        # Seen event IDs for deduplication: event_id -> correlation_id
        self._seen_events: Set[str] = set()

    # -------------------------------------------------------------------------
    # Ingestion & Recording
    # -------------------------------------------------------------------------

    def record_event(
        self,
        event_or_dict: Union[UnifiedSecurityEvent, SecurityEvent, Dict[str, Any]],
        correlation_id: Optional[str] = None,
        sequence_number: Optional[int] = None,
        tenant_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
    ) -> UnifiedSecurityEvent:
        """Ingest and correlate a single security event safely."""
        try:
            return self._ingest_internal(
                event_or_dict=event_or_dict,
                correlation_id=correlation_id,
                sequence_number=sequence_number,
                tenant_id=tenant_id,
                workflow_id=workflow_id,
                parent_event_id=parent_event_id,
            )
        except CrossTenantViolationError:
            # Re-raise tenant violations explicitly
            raise
        except Exception as exc:
            logger.error(f"Failed to ingest event into correlation engine: {exc}")
            # Return a fallback event so telemetry failure never breaks calling execution
            if isinstance(event_or_dict, UnifiedSecurityEvent):
                return event_or_dict
            return UnifiedSecurityEvent(
                event_type=SecurityEventType.SECURITY_DECISION,
                correlation_id=correlation_id or "unknown",
                request_id="fallback",
                safe_explanation=f"Telemetry fallback: {exc}",
            )

    def _ingest_internal(
        self,
        event_or_dict: Union[UnifiedSecurityEvent, SecurityEvent, Dict[str, Any]],
        correlation_id: Optional[str] = None,
        sequence_number: Optional[int] = None,
        tenant_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
    ) -> UnifiedSecurityEvent:
        """Internal thread-safe event ingestion."""
        # Normalize into UnifiedSecurityEvent
        if isinstance(event_or_dict, UnifiedSecurityEvent):
            event = event_or_dict
        elif isinstance(event_or_dict, SecurityEvent):
            event = UnifiedSecurityEvent.from_security_event(
                event=event_or_dict,
                correlation_id=correlation_id,
                sequence_number=sequence_number or 0,
                workflow_id=workflow_id,
                tenant_id=tenant_id,
                parent_event_id=parent_event_id,
            )
        elif isinstance(event_or_dict, dict):
            # Parse dict representation
            d = dict(event_or_dict)
            corr = correlation_id or d.get("correlation_id") or d.get("workflow_id") or d.get("request_id") or "unspecified"
            d["correlation_id"] = corr
            if "request_id" not in d:
                d["request_id"] = corr
            if "event_type" not in d:
                d["event_type"] = SecurityEventType.SECURITY_DECISION
            event = UnifiedSecurityEvent(**d)
        else:
            raise ValueError(f"Unsupported event type: {type(event_or_dict)}")

        corr_id = event.correlation_id or correlation_id or event.workflow_id or event.request_id

        with self._lock:
            # 1. Prune expired sessions
            self._prune_expired_sessions()

            # 2. Strict Tenant Isolation Invariant
            bound_tenant = self._session_tenants.get(corr_id)
            if bound_tenant is not None and event.tenant_id is not None and event.tenant_id != bound_tenant:
                raise CrossTenantViolationError(
                    f"Cross-tenant event correlation rejected: event specified tenant '{event.tenant_id}', "
                    f"but correlation session '{corr_id}' is immutably bound to tenant '{bound_tenant}'.",
                    workflow_id=event.workflow_id,
                    tenant_id=bound_tenant,
                )

            # Bind tenant if first time seeing this correlation session
            if corr_id not in self._session_tenants:
                self._session_tenants[corr_id] = event.tenant_id

            # 3. Deduplication Check
            if event.event_id in self._seen_events:
                logger.debug(f"Duplicate event '{event.event_id}' ignored in correlation session '{corr_id}'.")
                return event

            self._seen_events.add(event.event_id)

            # 4. Enforce in-memory LRU bounds
            if corr_id not in self._sessions and len(self._sessions) >= self.max_active_sessions:
                evicted_key, _ = self._sessions.popitem(last=False)
                self._session_tenants.pop(evicted_key, None)
                self._session_timestamps.pop(evicted_key, None)

            if corr_id not in self._sessions:
                self._sessions[corr_id] = []

            # 5. Assign monotonic sequence number if not set or zero
            if event.sequence_number == 0 and len(self._sessions[corr_id]) > 0:
                highest_seq = max(e.sequence_number for e in self._sessions[corr_id])
                # We can't mutate frozen model directly, so reconstruct with updated sequence
                event_data = event.model_dump()
                event_data["sequence_number"] = highest_seq + 1
                event = UnifiedSecurityEvent(**event_data)

            self._sessions[corr_id].append(event)
            self._session_timestamps[corr_id] = time.time()
            self._sessions.move_to_end(corr_id)

            return event

    # -------------------------------------------------------------------------
    # Correlation & Timeline Construction
    # -------------------------------------------------------------------------

    def get_timeline(
        self,
        correlation_id: str,
        tenant_id: Optional[str] = None,
    ) -> Optional[CorrelatedIncidentTimeline]:
        """Construct and return the correlated incident timeline for a session."""
        with self._lock:
            self._prune_expired_sessions()
            events = self._sessions.get(correlation_id)
            if not events:
                return None

            bound_tenant = self._session_tenants.get(correlation_id)
            if bound_tenant is not None and tenant_id is not None and tenant_id != bound_tenant:
                raise CrossTenantViolationError(
                    f"Cross-tenant access violation: requested tenant '{tenant_id}', "
                    f"but correlation session '{correlation_id}' belongs to tenant '{bound_tenant}'.",
                    tenant_id=bound_tenant,
                )

            return self.correlate_events(
                events=list(events),
                correlation_id=correlation_id,
                tenant_id=bound_tenant,
            )

    def correlate_events(
        self,
        events: List[UnifiedSecurityEvent],
        correlation_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> CorrelatedIncidentTimeline:
        """Deterministically correlate an arbitrary list of security events into a timeline."""
        if not events:
            corr = correlation_id or "empty"
            return CorrelatedIncidentTimeline(
                correlation_id=corr,
                tenant_id=tenant_id,
                diagnostic_summary="No events recorded in this correlation session.",
            )

        # 1. Enforce Tenant Isolation within event set
        tenants = {e.tenant_id for e in events if e.tenant_id is not None}
        if len(tenants) > 1:
            raise CrossTenantViolationError(
                f"Cannot correlate events across multiple tenant boundaries: found tenants {tenants}."
            )
        effective_tenant = tenant_id or (next(iter(tenants)) if tenants else None)

        # Deduplicate events by event_id preserving order
        unique_events: List[UnifiedSecurityEvent] = []
        seen: Set[str] = set()
        for ev in events:
            if ev.event_id not in seen:
                seen.add(ev.event_id)
                unique_events.append(ev)

        # 2. Causal and Chronological DAG Sorting
        sorted_events = self._causal_sort(unique_events)

        # 3. Detect Incomplete Traces & Missing Sequence Gaps
        missing_warnings: List[str] = []
        is_incomplete = False

        known_ids = {e.event_id for e in sorted_events}
        for ev in sorted_events:
            if ev.parent_event_id and ev.parent_event_id not in known_ids:
                missing_warnings.append(
                    f"Event '{ev.event_id}' ({ev.event_type.value}) references missing causal parent '{ev.parent_event_id}'."
                )
                is_incomplete = True

        # Check sequence gaps if sequence numbers were explicitly assigned
        seq_nums = [e.sequence_number for e in sorted_events if e.sequence_number > 0]
        if seq_nums and len(seq_nums) > 1:
            for i in range(len(seq_nums) - 1):
                if seq_nums[i + 1] > seq_nums[i] + 1:
                    missing_warnings.append(
                        f"Sequence gap detected: sequence jumped from {seq_nums[i]} to {seq_nums[i + 1]}."
                    )
                    is_incomplete = True

        # 4. Compute Metrics & Aggregations
        corr_id = correlation_id or sorted_events[0].correlation_id
        wf_id = sorted_events[0].workflow_id
        req_id = sorted_events[0].request_id

        start_time = min(e.timestamp for e in sorted_events)
        end_time = max(e.timestamp for e in sorted_events)
        total_duration = max(0.0, (end_time.timestamp() - start_time.timestamp()) * 1000.0)

        # Severity resolution
        sev_rank = {
            EventSeverity.DEBUG: 0,
            EventSeverity.INFO: 1,
            EventSeverity.WARNING: 2,
            EventSeverity.HIGH: 3,
            EventSeverity.CRITICAL: 4,
        }
        max_sev = max((e.severity for e in sorted_events), key=lambda s: sev_rank.get(s, 0))

        # Final action
        final_action = None
        for e in reversed(sorted_events):
            if e.action is not None:
                final_action = e.action
                break

        # Root cause event identification
        root_cause: Optional[UnifiedSecurityEvent] = None
        for e in sorted_events:
            if e.action in (Action.BLOCK, Action.REDACT) or sev_rank.get(e.severity, 0) >= 3:
                root_cause = e
                break

        # Reconstruct causal chains
        causal_chains = self._build_causal_chains(sorted_events)

        # Construct Diagnostic Summary
        summary = self._generate_diagnostic_summary(
            sorted_events=sorted_events,
            max_severity=max_sev,
            final_action=final_action,
            root_cause=root_cause,
            is_incomplete=is_incomplete,
        )

        return CorrelatedIncidentTimeline(
            correlation_id=corr_id,
            tenant_id=effective_tenant,
            workflow_id=wf_id,
            request_id=req_id,
            created_at=start_time,
            updated_at=end_time,
            start_time=start_time,
            end_time=end_time,
            total_duration_ms=round(total_duration, 2),
            events=sorted_events,
            total_events=len(sorted_events),
            max_severity=max_sev,
            final_action=final_action,
            root_cause_event=root_cause,
            causal_chains=causal_chains,
            missing_events=missing_warnings,
            is_incomplete=is_incomplete,
            diagnostic_summary=summary,
        )

    # -------------------------------------------------------------------------
    # Helper Methods
    # -------------------------------------------------------------------------

    def _causal_sort(self, events: List[UnifiedSecurityEvent]) -> List[UnifiedSecurityEvent]:
        """Sort events by sequence_number, timestamp, and topological parent dependencies."""
        # Initial stable sort by (sequence_number, timestamp)
        events_by_id = {e.event_id: e for e in events}

        # Build dependency adjacency
        parents = {e.event_id: e.parent_event_id for e in events if e.parent_event_id in events_by_id}

        # Topological sort with tie-breaking on (sequence_number, timestamp)
        visited: Set[str] = set()
        visiting: Set[str] = set()
        ordered: List[UnifiedSecurityEvent] = []

        # Sort seeds by sequence number and timestamp
        seeds = sorted(events, key=lambda e: (e.sequence_number, e.timestamp))

        def visit(ev: UnifiedSecurityEvent) -> None:
            if ev.event_id in visiting:
                # Cycle detected: break cycle safely
                return
            if ev.event_id not in visited:
                visiting.add(ev.event_id)
                parent_id = parents.get(ev.event_id)
                if parent_id and parent_id in events_by_id:
                    visit(events_by_id[parent_id])
                visiting.remove(ev.event_id)
                visited.add(ev.event_id)
                ordered.append(ev)

        for s in seeds:
            visit(s)

        return ordered

    def _build_causal_chains(self, events: List[UnifiedSecurityEvent]) -> List[List[str]]:
        """Extract explicit causal chains linking parent events to terminal outcomes."""
        events_by_id = {e.event_id: e for e in events}
        children: Dict[str, List[str]] = collections.defaultdict(list)
        roots: List[str] = []

        for e in events:
            if e.parent_event_id and e.parent_event_id in events_by_id:
                children[e.parent_event_id].append(e.event_id)
            else:
                roots.append(e.event_id)

        chains: List[List[str]] = []

        def dfs(current_id: str, current_path: List[str]) -> None:
            path = current_path + [current_id]
            child_ids = children.get(current_id, [])
            if not child_ids:
                if len(path) > 1:
                    chains.append(path)
            else:
                for cid in child_ids:
                    dfs(cid, path)

        for root_id in roots:
            dfs(root_id, [])

        return chains

    def _generate_diagnostic_summary(
        self,
        sorted_events: List[UnifiedSecurityEvent],
        max_severity: EventSeverity,
        final_action: Optional[Action],
        root_cause: Optional[UnifiedSecurityEvent],
        is_incomplete: bool,
    ) -> str:
        """Construct deterministic, privacy-safe plain-English diagnostic summary."""
        parts = [f"Correlated {len(sorted_events)} security event(s)."]
        parts.append(f"Peak operational severity: {max_severity.value}.")

        if final_action:
            parts.append(f"Final enforcement action: {final_action.value.upper()}.")

        if root_cause:
            threat_str = ", ".join(root_cause.threat_types) if root_cause.threat_types else root_cause.event_type.value
            parts.append(
                f"Root cause originated at step {root_cause.sequence_number} ({root_cause.component}): "
                f"{root_cause.safe_explanation or threat_str}."
            )
        else:
            parts.append("All inspected interactions conformed to verified security policies.")

        if is_incomplete:
            parts.append("Warning: trace timeline is incomplete due to missing events or sequence gaps.")

        return " ".join(parts)

    def _prune_expired_sessions(self) -> None:
        """Prune inactive correlation sessions exceeding TTL."""
        now = time.time()
        for corr_id, last_active in list(self._session_timestamps.items()):
            if now - last_active > self.session_ttl_seconds:
                self._sessions.pop(corr_id, None)
                self._session_tenants.pop(corr_id, None)
                self._session_timestamps.pop(corr_id, None)

    def clear(self) -> None:
        """Clear all in-memory correlation sessions (for testing)."""
        with self._lock:
            self._sessions.clear()
            self._session_tenants.clear()
            self._session_timestamps.clear()
            self._seen_events.clear()
