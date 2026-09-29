# AI Security Incident Response & Investigation (Phase 38)

The Incident Response & Investigation engine provides automated detection, timeline reconstruction, containment, and post-incident investigation reporting for AI systems.

---

## 1. Architectural Pipeline

```text
Security Events (Runtime sensors, Scan failures, Anomalies)
           │
           ↓
   Incident Correlation Engine
           │
     ┌─────┴────────────────┐
     ↓                      ↓
Detection Rules        Attack Graph Linkage
(Injection + Tools,    (Phase 33 Traversal)
 Repeated Denial)
     │                      │
     └─────────┬────────────┘
               ↓
        Security Incident
               │
   ┌───────────┼───────────┐
   ↓           ↓           ↓
Timeline    Containment  Post-Incident
Tracing      Hooks       Reporting
(Evidence  (dry_run=True (Observed vs
 Hashes)    Safe Default) Hypothesis)
```

### 1.1 Detection Rules

- **`PromptInjectionFollowedByPrivilegedToolRule`**: Flags prompt injection attempts immediately followed by sensitive tool calls in the same request or session.
- **`RepeatedUnauthorizedToolCallsRule`**: Detects adversarial tool enumeration or permission bypass attempts exceeding thresholds.
- **`SecretExposureRule`**: Flags leaks of raw API keys, bearer tokens, or passwords in outputs or logs.
- **`PolicyBypassRule`**: Flags anomalous bypasses of policy controls.
- **`AbnormalAgentBehaviorRule`**: Flags deviations from expected capability profiles.

### 1.2 Containment Hooks & Safety Invariant

LLMFirewall provides automated containment capabilities:
- `ISOLATE_AGENT`: Suspends an agent from scheduling queues.
- `DISABLE_TOOL`: Deactivates a compromised or vulnerable tool.
- `REVOKE_SESSION`: Terminates active user sessions and clears state.
- `CHANGE_POLICY`: Switches enforcement from `SHADOW` to `ENFORCE`.

> [!CAUTION]
> **Safety Invariant**: All containment actions enforce `dry_run=True` by default. Production systems are NEVER modified unless `dry_run=False` is explicitly passed.

---

## 2. Python API

```python
from llmfirewall import Firewall, SecurityEventType, IncidentSeverity, IncidentStatus

fw = Firewall()

# 1. Record security events
fw.incidents.record_event(
    event_type=SecurityEventType.PROMPT_INJECTION_DETECTED.value,
    severity=IncidentSeverity.HIGH,
    asset_id="agent:support",
    session_id="sess-100",
    metadata={"pattern": "system override"},
)

# 2. Correlate and inspect incidents
incidents = fw.incidents.list_incidents()
for inc in incidents:
    print(f"Incident {inc.id}: {inc.title} ({inc.severity.value})")

# 3. View chronological timeline
timeline = fw.incidents.get_timeline(inc.id)
for entry in timeline:
    print(f"[{entry.timestamp}] {entry.title} (hash: {entry.evidence_hash[:10]}...)")

# 4. Dry-run containment
fw.incidents.disable_agent("agent:support", dry_run=True)

# 5. Transition status
fw.incidents.transition_status(inc.id, IncidentStatus.CONTAINED, notes="Agent quarantined.")

# 6. Export report
report_md = fw.incidents.export_report(inc.id, format="markdown")
```

---

## 3. CLI Commands

```bash
# List all active incidents
llmfirewall incidents list

# Show detailed incident info
llmfirewall incidents show INC-001

# Inspect chronological timeline
llmfirewall incidents timeline INC-001

# Export post-incident report
llmfirewall incidents export INC-001 --format markdown --output incident_report.md
```
