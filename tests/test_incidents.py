"""Test suite for Phase 38: AI Security Incident Response & Investigation."""

from datetime import datetime, timezone
import pytest

from llmfirewall.incidents import (
    IncidentAction,
    IncidentError,
    IncidentManager,
    IncidentSeverity,
    IncidentStatus,
    SecurityEvent,
    SecurityEventType,
    SecurityIncident,
    compute_evidence_hash,
    generate_post_incident_report,
)
from llmfirewall.incidents.rules import (
    PromptInjectionFollowedByPrivilegedToolRule,
    RepeatedUnauthorizedToolCallsRule,
    SecretExposureRule,
)


class TestIncidentResponse:
    """Tests for event ingestion, detection rules, multi-entity correlation, and containment."""

    def test_event_ingestion_and_secret_sanitization(self):
        mgr = IncidentManager()
        ev = mgr.record_event(
            event_type="UNAUTHORIZED_TOOL_CALL",
            agent_id="support_bot",
            tool_id="db_dump",
            metadata={"secret_token": "sk-1234567890abcdefghij", "user": "alice"},
        )
        assert ev.id.startswith("evt_")
        # Ensure secret was sanitized from metadata
        assert ev.metadata.get("secret_token") != "sk-1234567890abcdefghij"
        assert "[REDACTED" in str(ev.metadata.get("secret_token"))

    def test_repeated_unauthorized_tool_calls_detection(self):
        mgr = IncidentManager()
        # Ingest 2 unauthorized calls
        mgr.record_event(
            event_type=SecurityEventType.UNAUTHORIZED_TOOL_CALL.value,
            agent_id="support",
            tool_id="terminal_exec",
            session_id="session-101",
        )
        mgr.record_event(
            event_type=SecurityEventType.UNAUTHORIZED_TOOL_CALL.value,
            agent_id="support",
            tool_id="terminal_exec",
            session_id="session-101",
        )

        incidents = mgr.list_incidents()
        assert len(incidents) >= 1
        inc = incidents[0]
        assert inc.severity in (IncidentSeverity.HIGH, IncidentSeverity.MEDIUM)
        assert "Unauthorized Tool" in inc.title
        assert len(inc.events) == 2

    def test_prompt_injection_followed_by_tool_call_correlation(self):
        """Tests multi-event correlation across request_id."""
        mgr = IncidentManager()
        # Event 1: Injection
        mgr.record_event(
            event_type=SecurityEventType.PROMPT_INJECTION_DETECTED.value,
            request_id="req-corr-01",
            agent_id="billing",
            metadata={"pattern": "system override"},
        )
        # Event 2: Privileged tool invocation in same request
        mgr.record_event(
            event_type=SecurityEventType.PRIVILEGED_TOOL_CALL.value,
            request_id="req-corr-01",
            agent_id="billing",
            tool_id="refund_tool",
            metadata={"amount": 5000},
        )

        incidents = mgr.list_incidents()
        assert len(incidents) == 1
        inc = incidents[0]
        assert inc.severity == IncidentSeverity.CRITICAL
        assert "Prompt Injection Preceding Tool Call" in inc.title
        assert len(inc.events) == 2

    def test_incident_lifecycle_state_machine(self):
        mgr = IncidentManager()
        mgr.record_event(
            event_type=SecurityEventType.SECRET_EXPOSURE.value,
            agent_id="chat",
            metadata={"secret_exposed": True},
        )
        inc = mgr.list_incidents()[0]
        assert inc.status == IncidentStatus.DETECTED

        # Acknowledge -> TRIAGED
        mgr.acknowledge(inc.id, actor="analyst_1", notes="Reviewing event sequence")
        assert inc.status == IncidentStatus.TRIAGED

        # Assign -> INVESTIGATING
        mgr.assign(inc.id, owner="secops_lead", actor="analyst_1")
        assert inc.status == IncidentStatus.INVESTIGATING
        assert inc.owner == "secops_lead"

        # Contain -> CONTAINED
        mgr.contain(inc.id, actor="secops_lead", containment_action="quarantine_agent")
        assert inc.status == IncidentStatus.CONTAINED

        # Resolve -> RESOLVED
        mgr.resolve(inc.id, actor="secops_lead", notes="Agent credentials revoked and rotated")
        assert inc.status == IncidentStatus.RESOLVED
        assert inc.resolved_at is not None

        # Close -> CLOSED
        mgr.close(inc.id, actor="secops_lead", notes="Verified no further leaks")
        assert inc.status == IncidentStatus.CLOSED

        # Reopen with new evidence -> REOPENED
        mgr.reopen(inc.id, actor="analyst_2", reason="New leak detected in log stream")
        assert inc.status == IncidentStatus.REOPENED

    def test_invalid_status_transition_raises_error(self):
        mgr = IncidentManager()
        mgr.record_event(event_type=SecurityEventType.SECRET_EXPOSURE.value, metadata={"secret_exposed": True})
        inc = mgr.list_incidents()[0]

        # DETECTED cannot transition straight to REOPENED
        with pytest.raises(IncidentError):
            mgr.transition_status(inc.id, IncidentStatus.REOPENED)

    def test_chronological_timeline_and_evidence_integrity(self):
        mgr = IncidentManager()
        mgr.record_event(
            event_type=SecurityEventType.PROMPT_INJECTION_DETECTED.value,
            request_id="req-tl-01",
            agent_id="support",
            metadata={"test": "1"},
        )
        mgr.record_event(
            event_type=SecurityEventType.PRIVILEGED_TOOL_CALL.value,
            request_id="req-tl-01",
            agent_id="support",
            tool_id="db_tool",
            metadata={"test": "2"},
        )

        inc = mgr.list_incidents()[0]
        timeline = mgr.get_timeline(inc.id)
        assert len(timeline) >= 3  # 2 events + 1 creation action

        # Verify timeline is strictly chronological
        for i in range(len(timeline) - 1):
            assert timeline[i].timestamp <= timeline[i + 1].timestamp

        # Verify evidence hashes are valid SHA-256 strings
        for entry in timeline:
            if entry.evidence_hash:
                assert len(entry.evidence_hash) == 64

    def test_containment_hook_dry_run_safeguard(self):
        """CRITICAL: Containment hooks must NEVER modify systems by default (dry_run=True)."""
        executed = []

        def custom_disable_agent(target_id: str, **kwargs):
            executed.append(target_id)
            return {"disabled": True}

        mgr = IncidentManager(containment_handlers={"disable_agent": custom_disable_agent})

        # By default dry_run=True
        res = mgr.disable_agent("agent:support")
        assert res["status"] == "SIMULATED"
        assert res["dry_run"] is True
        assert len(executed) == 0  # Did not modify system

        # Explicitly configure dry_run=False
        res_live = mgr.disable_agent("agent:support", dry_run=False)
        assert res_live["status"] == "SUCCESS"
        assert len(executed) == 1

    def test_post_incident_report_generation(self):
        mgr = IncidentManager()
        mgr.record_event(
            event_type=SecurityEventType.PROMPT_INJECTION_DETECTED.value,
            request_id="req-rep-01",
            agent_id="finance_bot",
            metadata={"token": "test"},
        )
        mgr.record_event(
            event_type=SecurityEventType.PRIVILEGED_TOOL_CALL.value,
            request_id="req-rep-01",
            agent_id="finance_bot",
            tool_id="wire_transfer",
            metadata={"token": "test"},
        )

        inc = mgr.list_incidents()[0]
        timeline = mgr.get_timeline(inc.id)

        # Markdown report
        md_report = generate_post_incident_report(inc, timeline=timeline, format_type="markdown")
        assert f"# POST-INCIDENT SECURITY REPORT: {inc.id}" in md_report
        assert "OBSERVED" in md_report
        assert "Lessons Learned" in md_report

        # JSON report
        json_report = generate_post_incident_report(inc, timeline=timeline, format_type="json")
        assert inc.id in json_report
