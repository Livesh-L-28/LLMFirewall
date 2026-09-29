"""Runnable example demonstrating AI Security Incident Response & Investigation (Phase 38)."""

import json
from datetime import datetime, timezone
from llmfirewall import (
    Firewall,
    SecurityEvent,
    SecurityEventType,
    IncidentSeverity,
    IncidentStatus,
)

def main() -> None:
    print("=" * 80)
    print("      LLMFirewall Phase 38: AI Security Incident Response & Investigation     ")
    print("=" * 80)

    # 1. Initialize Firewall orchestrator
    fw = Firewall()

    print("\n[Step 1] Ingesting security event sequence (Prompt Injection + Privileged Tool Call)...")

    # Event 1: Prompt injection attempt
    ev1 = fw.incidents.record_event(
        event_type=SecurityEventType.PROMPT_INJECTION_DETECTED.value,
        severity=IncidentSeverity.HIGH,
        asset_id="agent:financial_copilot",
        session_id="sess-88991",
        metadata={
            "description": "Prompt injection attempt detected targeting financial records.",
            "pattern": "ignore previous instructions",
            "confidence": 0.98,
        },
    )
    print(f"  Recorded Event 1 (Injection ID: {ev1.id})")

    # Event 2: Immediate follow-up privileged tool call in the same session
    ev2 = fw.incidents.record_event(
        event_type=SecurityEventType.PRIVILEGED_TOOL_CALL.value,
        severity=IncidentSeverity.CRITICAL,
        asset_id="agent:financial_copilot",
        tool_id="execute_wire_transfer",
        session_id="sess-88991",
        metadata={
            "description": "Execution of privileged tool 'execute_wire_transfer' attempted.",
            "tool_name": "execute_wire_transfer",
            "recipient": "external_account_99",
        },
    )
    print(f"  Recorded Event 2 (Privileged Tool ID: {ev2.id})")

    # 2. Inspect generated incident
    all_incidents = fw.incidents.list_incidents()
    print(f"\n[Step 2] Total Correlated Incidents: {len(all_incidents)}")
    if not all_incidents:
        print("No incidents recorded.")
        return

    inc = all_incidents[0]
    print(f"\n[INCIDENT DETAILS: {inc.id}]")
    print(f"  Title:        {inc.title}")
    print(f"  Severity:     {inc.severity.value}")
    print(f"  Status:       {inc.status.value}")
    print(f"  Assets:       {', '.join(inc.assets) if inc.assets else 'None'}")
    print(f"  Description:  {inc.description}")
    print(f"  Correlated:   {len(inc.events)} security event(s)")

    # 3. View chronological timeline
    print("\n[Step 3] Chronological Timeline & Evidence Traceability:")
    timeline = fw.incidents.get_timeline(inc.id)
    for entry in timeline:
        ev_hash_preview = entry.evidence_hash[:12] if entry.evidence_hash else "none"
        obs_label = "OBSERVED" if entry.observed else "INFERRED"
        print(f"  [{entry.timestamp.strftime('%H:%M:%S')}] [{obs_label}] ({entry.stage}) {entry.title}: {entry.description} [hash: {ev_hash_preview}...]")

    # 4. Dry-run containment action
    print("\n[Step 4] Executing Dry-Run Containment Action (Safety Invariant: dry_run=True default)...")
    dry_run_res = fw.incidents.disable_agent(
        agent_id="agent:financial_copilot",
        dry_run=True,
    )
    print(f"  Dry-run containment status: {dry_run_res['status']}")
    print(f"  Message: {dry_run_res['message']}")

    # 5. Lifecycle state machine transition
    print("\n[Step 5] Transitioning incident lifecycle state to CONTAINED...")
    fw.incidents.transition_status(
        incident_id=inc.id,
        new_status=IncidentStatus.CONTAINED,
        notes="Agent financial_copilot session halted and placed in sandbox.",
    )
    updated_inc = fw.incidents.get_incident(inc.id)
    print(f"  Updated status: {updated_inc.status.value}")

    # 6. Generate post-incident investigation report
    print("\n[Step 6] Generating Post-Incident Report (Distinguishing Observed vs Hypothesis)...")
    md_report = fw.incidents.export_report(inc.id, format="markdown")
    print("\n--- BEGIN POST-INCIDENT REPORT (MARKDOWN PREVIEW) ---")
    print("\n".join(md_report.splitlines()[:25]))
    print("... [truncated for display] ...")
    print("--- END POST-INCIDENT REPORT ---\n")

if __name__ == "__main__":
    main()
