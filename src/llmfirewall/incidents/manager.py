"""Incident Manager for Phase 38: AI Security Incident Response & Investigation.

Handles:
- Event ingestion and correlation
- Rule evaluation and incident creation
- Attack graph correlation (Phase 33 integration)
- Chronological timeline generation with evidence hashes
- Incident lifecycle transitions and action audit logging
- Containment hooks (with strict dry-run safeguard)
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import logging
from typing import Any, Callable, Dict, List, Optional, Set
import uuid

from llmfirewall.core.exceptions import LLMFirewallError
from llmfirewall.incidents.models import (
    EvidenceItem,
    IncidentAction,
    IncidentActionRecord,
    IncidentSeverity,
    IncidentStatus,
    SecurityEvent,
    SecurityIncident,
    TimelineEntry,
    compute_evidence_hash,
)
from llmfirewall.incidents.rules import (
    IncidentCandidate,
    IncidentDetectionRule,
    get_default_incident_rules,
)

logger = logging.getLogger("llmfirewall.incidents")


class IncidentError(LLMFirewallError):
    """Exception raised for invalid incident operations or transitions."""
    pass


class IncidentManager:
    """Central engine for AI Security Incident Response & Investigation."""

    def __init__(
        self,
        rules: Optional[List[IncidentDetectionRule]] = None,
        attack_graph_engine: Optional[Any] = None,
        containment_handlers: Optional[Dict[str, Callable[..., Any]]] = None,
    ) -> None:
        self.rules: List[IncidentDetectionRule] = rules if rules is not None else get_default_incident_rules()
        self.attack_graph_engine = attack_graph_engine
        self.containment_handlers = containment_handlers or {}
        
        # In-memory storage for events and incidents
        self._events: Dict[str, SecurityEvent] = {}
        self._incidents: Dict[str, SecurityIncident] = {}
        self._evidence_store: Dict[str, EvidenceItem] = {}

    # -------------------------------------------------------------------------
    # Event Ingestion & Correlation
    # -------------------------------------------------------------------------

    def record_event(
        self,
        event_type: str,
        source: str = "llmfirewall.runtime",
        asset_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        tool_id: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        severity: IncidentSeverity = IncidentSeverity.MEDIUM,
        metadata: Optional[Dict[str, Any]] = None,
        evidence: Optional[List[Dict[str, Any]]] = None,
    ) -> SecurityEvent:
        """Convenience method to construct, store, and ingest a single security event."""
        event = SecurityEvent(
            event_type=event_type,
            source=source,
            asset_id=asset_id,
            agent_id=agent_id,
            tool_id=tool_id,
            request_id=request_id,
            session_id=session_id,
            severity=severity,
            metadata=metadata or {},
            evidence=evidence or [],
        )
        self.ingest_event(event)
        return event

    def ingest_event(self, event: SecurityEvent) -> Optional[SecurityIncident]:
        """Ingests a single SecurityEvent, indexes it, and evaluates detection rules."""
        self._events[event.id] = event

        # Preserve evidence item
        ev_item = EvidenceItem(
            event_id=event.id,
            timestamp=event.timestamp,
            asset_id=event.asset_id or (f"agent:{event.agent_id}" if event.agent_id else None),
            source=event.source,
            evidence_hash=compute_evidence_hash(event.metadata),
            collection_time=datetime.now(timezone.utc),
            details={"event_type": event.event_type, "severity": event.severity.value},
        )
        self._evidence_store[ev_item.id] = ev_item

        # Correlate and evaluate
        candidates = self._evaluate_rules()
        created_incidents = self._process_candidates(candidates)
        return created_incidents[0] if created_incidents else None

    def ingest_events(self, events: List[SecurityEvent]) -> List[SecurityIncident]:
        """Ingests a batch of SecurityEvents and processes detections."""
        for event in events:
            self._events[event.id] = event
            ev_item = EvidenceItem(
                event_id=event.id,
                timestamp=event.timestamp,
                asset_id=event.asset_id or (f"agent:{event.agent_id}" if event.agent_id else None),
                source=event.source,
                evidence_hash=compute_evidence_hash(event.metadata),
                collection_time=datetime.now(timezone.utc),
                details={"event_type": event.event_type, "severity": event.severity.value},
            )
            self._evidence_store[ev_item.id] = ev_item

        candidates = self._evaluate_rules()
        return self._process_candidates(candidates)

    def _evaluate_rules(self) -> List[IncidentCandidate]:
        """Runs all enabled detection rules across stored events."""
        events_list = list(self._events.values())
        candidates: List[IncidentCandidate] = []
        for rule in self.rules:
            if rule.enabled:
                candidates.extend(rule.evaluate(events_list))
        return candidates

    def _process_candidates(self, candidates: List[IncidentCandidate]) -> List[SecurityIncident]:
        """Deduplicates and creates new incidents or links to existing ones."""
        new_incidents: List[SecurityIncident] = []

        for cand in candidates:
            # Check if an existing open incident already contains all these event IDs
            existing = None
            for inc in self._incidents.values():
                if inc.status not in (IncidentStatus.CLOSED, IncidentStatus.RESOLVED):
                    if set(cand.event_ids).issubset(set(inc.events)):
                        existing = inc
                        break

            if existing:
                # Already tracked
                continue

            # Create new incident
            inc_id = f"INC-{len(self._incidents) + 1:03d}"
            incident = SecurityIncident(
                id=inc_id,
                title=cand.title,
                description=cand.description,
                status=IncidentStatus.DETECTED,
                severity=cand.severity,
                created_at=datetime.now(timezone.utc),
                detected_at=datetime.now(timezone.utc),
                assets=cand.assets,
                events=cand.event_ids,
                evidence=cand.evidence,
            )

            # Correlate attack paths (Phase 33 integration)
            self.correlate_attack_paths(incident)

            # Record creation action
            incident.record_action(
                action=IncidentAction.ACKNOWLEDGE,
                actor="detection_engine",
                notes=f"Triggered by rule '{cand.rule_name}'. {cand.root_cause_indicator}",
                details={"rule": cand.rule_name},
            )

            self._incidents[incident.id] = incident
            new_incidents.append(incident)

        return new_incidents

    # -------------------------------------------------------------------------
    # Attack Path Correlation (Phase 33)
    # -------------------------------------------------------------------------

    def correlate_attack_paths(self, incident: SecurityIncident) -> List[str]:
        """Correlates an incident's assets and tools with Phase 33 Attack Paths."""
        correlated_paths: List[str] = []
        if not self.attack_graph_engine:
            return correlated_paths

        try:
            # If the engine has find_attack_paths or paths in memory
            paths = getattr(self.attack_graph_engine, "paths", [])
            for path in paths:
                path_id = getattr(path, "id", None) or getattr(path, "path_id", str(path))
                # Check if any incident asset or event tool appears in the attack path
                steps = getattr(path, "steps", [])
                step_str = " ".join([str(s) for s in steps])
                matched = False
                for asset in incident.assets:
                    clean_asset = asset.replace("agent:", "").replace("tool:", "")
                    if clean_asset and clean_asset in step_str:
                        matched = True
                        break
                if matched and path_id not in incident.attack_paths:
                    incident.attack_paths.append(path_id)
                    correlated_paths.append(path_id)
        except Exception as e:
            logger.debug(f"Attack path correlation failed: {e}")

        return correlated_paths

    # -------------------------------------------------------------------------
    # Investigation Timeline
    # -------------------------------------------------------------------------

    def get_timeline(self, incident_id: str) -> List[TimelineEntry]:
        """Generates a strictly chronological timeline of all events and actions linked to an incident."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise IncidentError(f"Incident '{incident_id}' not found.")

        timeline: List[TimelineEntry] = []

        # 1. Timeline entries from events
        for ev_id in incident.events:
            ev = self._events.get(ev_id)
            if ev:
                timeline.append(
                    TimelineEntry(
                        timestamp=ev.timestamp,
                        stage="RUNTIME_EVENT",
                        title=f"Event: {ev.event_type}",
                        description=f"Source: {ev.source}, Request: {ev.request_id or 'none'}, Tool: {ev.tool_id or 'none'}",
                        event_id=ev.id,
                        asset_id=ev.asset_id or (f"agent:{ev.agent_id}" if ev.agent_id else None),
                        evidence_hash=compute_evidence_hash(ev.metadata),
                        observed=True,
                    )
                )

        # 2. Timeline entries from actions
        for act in incident.actions:
            timeline.append(
                TimelineEntry(
                    timestamp=act.timestamp,
                    stage="INCIDENT_ACTION",
                    title=f"Action: {act.action.value}",
                    description=f"Actor: {act.actor}. Notes: {act.notes}",
                    event_id=None,
                    asset_id=None,
                    evidence_hash=compute_evidence_hash(act.details),
                    observed=True,
                )
            )

        # Sort chronologically
        timeline.sort(key=lambda t: t.timestamp)
        return timeline

    # -------------------------------------------------------------------------
    # Incident Lifecycle Actions
    # -------------------------------------------------------------------------

    def get_incident(self, incident_id: str) -> Optional[SecurityIncident]:
        """Retrieves an incident by ID."""
        return self._incidents.get(incident_id)

    def list_incidents(
        self,
        status: Optional[IncidentStatus] = None,
        severity: Optional[IncidentSeverity] = None,
        asset_id: Optional[str] = None,
    ) -> List[SecurityIncident]:
        """Filters and lists incidents."""
        results = list(self._incidents.values())
        if status:
            results = [inc for inc in results if inc.status == status]
        if severity:
            results = [inc for inc in results if inc.severity == severity]
        if asset_id:
            results = [inc for inc in results if asset_id in inc.assets]
        return sorted(results, key=lambda x: x.created_at, reverse=True)

    def transition_status(
        self,
        incident_id: str,
        new_status: IncidentStatus,
        actor: str = "security_analyst",
        notes: str = "",
    ) -> SecurityIncident:
        """Enforces state machine transitions on an incident."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise IncidentError(f"Incident '{incident_id}' not found.")

        if not incident.can_transition_to(new_status):
            raise IncidentError(
                f"Invalid status transition from {incident.status.value} to {new_status.value}."
            )

        prev_status = incident.status
        incident.status = new_status
        if new_status == IncidentStatus.RESOLVED and not incident.resolved_at:
            incident.resolved_at = datetime.now(timezone.utc)
        elif new_status == IncidentStatus.REOPENED:
            incident.resolved_at = None

        incident.record_action(
            action=IncidentAction.RESOLVE if new_status == IncidentStatus.RESOLVED else IncidentAction.ACKNOWLEDGE,
            actor=actor,
            notes=f"Status transitioned from {prev_status.value} to {new_status.value}. {notes}",
            details={"from": prev_status.value, "to": new_status.value},
        )
        return incident

    def acknowledge(self, incident_id: str, actor: str = "security_analyst", notes: str = "") -> SecurityIncident:
        """Acknowledges an incident and moves to TRIAGED."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise IncidentError(f"Incident '{incident_id}' not found.")
        incident.record_action(IncidentAction.ACKNOWLEDGE, actor=actor, notes=notes)
        if incident.status == IncidentStatus.DETECTED:
            incident.status = IncidentStatus.TRIAGED
        return incident

    def assign(self, incident_id: str, owner: str, actor: str = "security_analyst", notes: str = "") -> SecurityIncident:
        """Assigns an owner to an incident and moves to INVESTIGATING if currently DETECTED/TRIAGED."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise IncidentError(f"Incident '{incident_id}' not found.")
        incident.owner = owner
        incident.record_action(
            IncidentAction.ASSIGN,
            actor=actor,
            notes=f"Assigned owner to {owner}. {notes}",
            details={"owner": owner},
        )
        if incident.status in (IncidentStatus.DETECTED, IncidentStatus.TRIAGED):
            incident.status = IncidentStatus.INVESTIGATING
        return incident

    def contain(
        self,
        incident_id: str,
        actor: str = "security_analyst",
        containment_action: str = "quarantine",
        notes: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> SecurityIncident:
        """Marks an incident as contained and records the containment step."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise IncidentError(f"Incident '{incident_id}' not found.")
        
        incident.record_action(
            IncidentAction.CONTAIN,
            actor=actor,
            notes=f"Containment applied: {containment_action}. {notes}",
            details={"containment_action": containment_action, **(details or {})},
        )
        incident.status = IncidentStatus.CONTAINED
        return incident

    def escalate(
        self,
        incident_id: str,
        new_severity: IncidentSeverity,
        actor: str = "security_analyst",
        notes: str = "",
    ) -> SecurityIncident:
        """Escalates incident severity."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise IncidentError(f"Incident '{incident_id}' not found.")
        
        old_sev = incident.severity
        incident.severity = new_severity
        incident.record_action(
            IncidentAction.ESCALATE,
            actor=actor,
            notes=f"Escalated severity from {old_sev.value} to {new_severity.value}. {notes}",
            details={"old_severity": old_sev.value, "new_severity": new_severity.value},
        )
        return incident

    def resolve(self, incident_id: str, actor: str = "security_analyst", notes: str = "") -> SecurityIncident:
        """Resolves an incident."""
        return self.transition_status(incident_id, IncidentStatus.RESOLVED, actor=actor, notes=notes)

    def close(self, incident_id: str, actor: str = "security_analyst", notes: str = "") -> SecurityIncident:
        """Closes an incident."""
        return self.transition_status(incident_id, IncidentStatus.CLOSED, actor=actor, notes=notes)

    def reopen(self, incident_id: str, actor: str = "security_analyst", reason: str = "", new_events: Optional[List[str]] = None) -> SecurityIncident:
        """Reopens an incident upon new evidence."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise IncidentError(f"Incident '{incident_id}' not found.")
        
        if new_events:
            for ev_id in new_events:
                if ev_id not in incident.events:
                    incident.events.append(ev_id)

        incident.record_action(
            IncidentAction.REOPEN,
            actor=actor,
            notes=f"Reopened incident: {reason}",
            details={"new_events": new_events or []},
        )
        incident.status = IncidentStatus.REOPENED
        return incident

    def export_report(self, incident_id: str, format_type: str = "markdown", format: Optional[str] = None) -> str:
        """Generates a post-incident investigation report with chronological timeline."""
        fmt = format if format is not None else format_type
        incident = self.get_incident(incident_id)
        if not incident:
            raise IncidentError(f"Incident '{incident_id}' not found.")
        timeline = self.get_timeline(incident_id)
        from llmfirewall.incidents.reporting import generate_post_incident_report
        return generate_post_incident_report(incident, timeline=timeline, format_type=fmt)

    # -------------------------------------------------------------------------
    # Containment Hooks (with dry-run safeguard)
    # -------------------------------------------------------------------------

    def execute_containment_action(
        self,
        action_name: str,
        target_id: str,
        dry_run: bool = True,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Executes a containment hook.
        
        CRITICAL SAFEGUARD:
        Defaults to dry_run=True. Production systems are NEVER modified unless dry_run=False
        is explicitly provided by the caller.
        """
        handler = self.containment_handlers.get(action_name)
        result: Dict[str, Any] = {
            "action": action_name,
            "target_id": target_id,
            "dry_run": dry_run,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if dry_run:
            result["status"] = "SIMULATED"
            result["message"] = f"[DRY-RUN] Would execute containment action '{action_name}' on target '{target_id}'."
            return result

        if handler:
            try:
                exec_res = handler(target_id, **kwargs)
                result["status"] = "SUCCESS"
                result["details"] = exec_res
            except Exception as e:
                result["status"] = "FAILED"
                result["error"] = str(e)
        else:
            result["status"] = "EXECUTED_DEFAULT"
            result["message"] = f"Containment action '{action_name}' recorded for target '{target_id}'."

        return result

    def disable_agent(self, agent_id: str, dry_run: bool = True) -> Dict[str, Any]:
        """Containment hook: disables an agent from further runtime dispatch."""
        return self.execute_containment_action("disable_agent", agent_id, dry_run=dry_run)

    def disable_tool(self, tool_id: str, dry_run: bool = True) -> Dict[str, Any]:
        """Containment hook: disables a tool capability across agent environments."""
        return self.execute_containment_action("disable_tool", tool_id, dry_run=dry_run)

    def change_policy(self, policy_id: str, new_mode: str, dry_run: bool = True) -> Dict[str, Any]:
        """Containment hook: changes policy enforcement mode (e.g. shadow -> enforce)."""
        return self.execute_containment_action("change_policy", policy_id, dry_run=dry_run, new_mode=new_mode)

    def block_request(self, request_id: str, dry_run: bool = True) -> Dict[str, Any]:
        """Containment hook: terminates or drops an active in-flight request."""
        return self.execute_containment_action("block_request", request_id, dry_run=dry_run)

    def revoke_session(self, session_id: str, dry_run: bool = True) -> Dict[str, Any]:
        """Containment hook: revokes an active session token and clears runtime state."""
        return self.execute_containment_action("revoke_session", session_id, dry_run=dry_run)
