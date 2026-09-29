# AI Security Incident Response & Investigation Example (Phase 38)

This example demonstrates the AI Security Incident Response engine in `LLMFirewall`.

## What This Demonstrates

1. **Multi-Event Security Correlation**: Ingesting high-severity prompt injection events followed by unauthorized tool calls within a shared session.
2. **Rule-Based Detection**: Triggering `PromptInjectionFollowedByPrivilegedToolRule` to automatically assemble a high/critical security incident.
3. **Chronological Timelines**: Constructing verifiable, SHA256-hashed event timelines ensuring evidence integrity.
4. **Dry-Run Containment**: Safeguarding production systems by enforcing `dry_run=True` containment by default (`ISOLATE_AGENT`, `REVOKE_CREDENTIALS`, `BLOCK_IP`).
5. **Incident Lifecycle State Machine**: Tracking states from `NEW` -> `TRIAGED` -> `CONTAINED` -> `RESOLVED`.
6. **Post-Incident Reporting**: Generating comprehensive post-incident investigation reports that strictly separate observed factual evidence from investigative hypotheses.

## Running the Example

Run the application directly:

```bash
python examples/incident_response/application.py
```

Or explore incidents via the CLI:

```bash
# List all active incidents
llmfirewall incidents list

# Show incident timeline
llmfirewall incidents timeline INC-001

# Export incident report
llmfirewall incidents export INC-001 --format markdown --output incident_report.md
```
