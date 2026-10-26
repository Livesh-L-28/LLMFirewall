"""Incident Correlation & Timeline Generation Pipeline Example.

Phase 4: Unified Security Event Correlation.
Demonstrates:
1. Multi-stage attack detection:
   - Stage 1: User prompt with adversarial intent.
   - Stage 2: RAG context ingestion with poisoned prompt injection.
   - Stage 3: Attempted unauthorized tool execution (privilege escalation).
2. Deterministic causal event linking:
   - Emits versioned UnifiedSecurityEvent instances with explicit causal references.
3. Automated timeline correlation:
   - Resolves causal DAG, detects root causes, and identifies any missing sequence gaps.
4. Privacy-safe SIEM/SOC exports:
   - JSON, Markdown diagnostic report, ArcSight CEF, RFC 5424 Syslog, OpenTelemetry OTLP.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from llmfirewall import (
    Action,
    CorrelatedIncidentTimeline,
    EventCorrelationEngine,
    Firewall,
    Severity,
    UnifiedSecurityEvent,
    export_timeline_cef,
    export_timeline_json,
    export_timeline_markdown,
    export_timeline_opentelemetry,
    export_timeline_syslog_rfc5424,
)
from llmfirewall.observability.models import (
    EventSeverity,
    SecurityEventType,
)


class IncidentCorrelationPipeline:
    """Enterprise security pipeline with unified event correlation across prompt, RAG, and tools."""

    def __init__(self, firewall: Optional[Firewall] = None) -> None:
        self.fw = firewall or Firewall()
        self.correlation_engine = EventCorrelationEngine()

    def process_incident_flow(
        self,
        correlation_id: str,
        tenant_id: str,
        user_prompt: str,
        rag_documents: List[str],
        attempted_tool: str,
        tool_args: Dict[str, Any],
    ) -> CorrelatedIncidentTimeline:
        """Execute a full multi-stage flow and generate a correlated incident timeline."""
        # ---------------------------------------------------------------------
        # Step 1: Ingest and scan user prompt
        # ---------------------------------------------------------------------
        trace = self.fw.trace_decision(
            text_or_request=user_prompt,
            correlation_id=correlation_id,
            tenant_id=tenant_id,
            direction="input",
        )

        ev1 = self.correlation_engine.record_event(
            UnifiedSecurityEvent(
                event_id=f"evt-{uuid.uuid4().hex[:8]}",
                sequence_number=1,
                event_type=SecurityEventType.SCAN_REQUEST,
                severity=EventSeverity.INFO if trace.final_action == Action.ALLOW else EventSeverity.HIGH,
                correlation_id=correlation_id,
                request_id=trace.request_id,
                tenant_id=tenant_id,
                component="prompt_scanner",
                action=trace.final_action,
                outcome="ALLOWED" if trace.final_action == Action.ALLOW else "BLOCKED",
                safe_explanation=trace.explanation,
                duration_ms=trace.total_duration_ms,
            )
        )

        # ---------------------------------------------------------------------
        # Step 2: Ingest and scan retrieved RAG context documents
        # ---------------------------------------------------------------------
        quarantined_docs = []
        for idx, doc_text in enumerate(rag_documents):
            rag_scan = self.fw.scan(doc_text, direction="input")
            if rag_scan.is_blocked:
                quarantined_docs.append(idx)

        rag_action = Action.BLOCK if quarantined_docs else Action.ALLOW
        rag_outcome = "QUARANTINED" if quarantined_docs else "ALLOWED"
        rag_sev = EventSeverity.HIGH if quarantined_docs else EventSeverity.INFO
        rag_expl = (
            f"RAG context scanned: {len(quarantined_docs)} document(s) quarantined due to injection patterns."
            if quarantined_docs
            else "All retrieved RAG documents verified safe."
        )

        ev2 = self.correlation_engine.record_event(
            UnifiedSecurityEvent(
                event_id=f"evt-{uuid.uuid4().hex[:8]}",
                sequence_number=2,
                event_type=SecurityEventType.THREAT_DETECTED if quarantined_docs else SecurityEventType.SECURITY_DECISION,
                severity=rag_sev,
                correlation_id=correlation_id,
                request_id=trace.request_id,
                tenant_id=tenant_id,
                component="rag_orchestrator",
                action=rag_action,
                outcome=rag_outcome,
                threat_types=["RAG_POISONING", "INDIRECT_INJECTION"] if quarantined_docs else [],
                detector_name="rag_scanner" if quarantined_docs else None,
                parent_event_id=ev1.event_id,
                safe_explanation=rag_expl,
            )
        )

        # ---------------------------------------------------------------------
        # Step 3: Tool Execution Authorization & Inspection
        # ---------------------------------------------------------------------
        # If RAG was poisoned or tool is dangerous, block tool execution
        tool_action = Action.BLOCK if quarantined_docs or attempted_tool in ("export_db", "admin_shell") else Action.ALLOW
        tool_outcome = "BLOCKED" if tool_action == Action.BLOCK else "ALLOWED"
        tool_sev = EventSeverity.CRITICAL if tool_action == Action.BLOCK else EventSeverity.INFO
        tool_expl = (
            f"Unauthorized tool execution '{attempted_tool}' blocked: workflow context is tainted by prior injection."
            if quarantined_docs
            else f"Tool execution '{attempted_tool}' verified and authorized."
        )

        ev3 = self.correlation_engine.record_event(
            UnifiedSecurityEvent(
                event_id=f"evt-{uuid.uuid4().hex[:8]}",
                sequence_number=3,
                event_type=SecurityEventType.TOOL_BLOCKED if tool_action == Action.BLOCK else SecurityEventType.TOOL_ALLOWED,
                severity=tool_sev,
                correlation_id=correlation_id,
                request_id=trace.request_id,
                tenant_id=tenant_id,
                component="tool_enforcer",
                action=tool_action,
                outcome=tool_outcome,
                tool_name=attempted_tool,
                threat_types=["PRIVILEGE_ESCALATION", "TAINTED_EXECUTION"] if tool_action == Action.BLOCK else [],
                parent_event_id=ev2.event_id,
                safe_explanation=tool_expl,
                metadata={"tool_args_keys": list(tool_args.keys())},
            )
        )

        # ---------------------------------------------------------------------
        # Step 4: Construct and return the correlated incident timeline
        # ---------------------------------------------------------------------
        timeline = self.correlation_engine.get_timeline(
            correlation_id=correlation_id,
            tenant_id=tenant_id,
        )
        if timeline is None:
            raise RuntimeError("Failed to build correlated incident timeline.")
        return timeline


def export_all_formats(timeline: CorrelatedIncidentTimeline) -> Dict[str, Any]:
    """Convenience exporter compiling all 5 supported SIEM/SOC formats."""
    return {
        "json": export_timeline_json(timeline),
        "markdown": export_timeline_markdown(timeline),
        "cef": export_timeline_cef(timeline),
        "syslog_rfc5424": export_timeline_syslog_rfc5424(timeline),
        "opentelemetry": export_timeline_opentelemetry(timeline),
    }
