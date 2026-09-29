# Evidence Model & Provenance

In LLMFirewall Phase 36, compliance controls are evaluated strictly against **verifiable, traceable evidence artifacts** rather than self-reported assertions.

---

## 1. Evidence Model Specification

Every evidence item is modeled by `ComplianceEvidence`:

| Field | Type | Description |
|---|---|---|
| `id` | `str` | Unique, stable evidence ID (e.g. `EVID-A1B2C3D4`). |
| `type` | `EvidenceType` | Classification taxonomy of the evidence. |
| `source` | `str` | Subsystem or origin generating the evidence (e.g. `llmfirewall.spm`). |
| `asset_id` | `str` | Target asset identifier (e.g. `agent:customer-support`). |
| `control_id` | `str` | Associated compliance control (e.g. `ai-baseline:AC-01`). |
| `collected_at` | `float` | Epoch timestamp of initial collection. |
| `expires_at` | `Optional[float]` | Expiration epoch timestamp if time-bounded. |
| `last_verified` | `float` | Epoch timestamp of most recent verification. |
| `content_reference` | `str` | Safe non-secret cryptographic digest, test run ID, or policy ID. |
| `status` | `EvidenceValidity` | Current validity state (`VALID`, `STALE`, `REVOKED`, `CONFLICTING`, `UNKNOWN`). |
| `attestation` | `Optional[Dict]` | Human attestation record (if type is `MANUAL_ATTESTATION`). |
| `metadata` | `Dict[str, Any]` | Safe metadata with automatic credential scrubbing. |

---

## 2. 11 Supported Evidence Types

```text
CONFIGURATION        - Direct runtime or framework configuration settings
POLICY               - Security policies defined in Phase 31 Governance
SECURITY_TEST        - Empirical automated attack test results from Phase 30
FINDING              - Security findings and audit observations
AUDIT_EVENT          - Verifiable audit trail event log
POSTURE              - Phase 35 AI-SPM validated security posture record
ATTACK_GRAPH         - Phase 33 Attack path analysis or mitigation verification
ASSET_INVENTORY      - Phase 34 authoritative discovery record
RUNTIME_EVENT        - Live runtime security enforcement event
DOCUMENT             - Architecture specifications, threat models, or design docs
MANUAL_ATTESTATION   - Explicit human compliance signoff
```

---

## 3. Evidence Freshness & Staleness Invariant

Evidence can degrade over time:
1. **Time-Based Expiration**: If `time.time() > evidence.expires_at`, evidence automatically becomes `STALE` or expired.
2. **Asset Modification Invalidation**: If the target asset is modified (`asset.last_seen > evidence.last_verified + 1.0`), previous empirical test evidence is downgraded to `STALE`.

> [!WARNING]
> Stale evidence can **never** satisfy full control requirements. Stale evidence causes the control to evaluate to `PARTIALLY_EVIDENCED` or `IMPLEMENTED`, prompting re-testing.

---

## 4. Evidence Conflict Detection (Section 18)

If contradictory evidence artifacts are registered for the same requirement:
```text
Policy:  Tool authorization enabled
Runtime: Tool authorization bypassed / disabled
```
LLMFirewall does not arbitrarily choose one. It flags both as `CONFLICTING`, evaluates the control as `FAILED`, and generates a high-severity gap:
```text
[HIGH] Conflicting Evidence Detected for Control 'ai-baseline:AC-01'
Remediation: Investigate discrepancies between configured policies and runtime telemetry.
```

---

## 5. Explicit Human Attestation

Human attestations (`MANUAL_ATTESTATION`) must contain explicit signoff metadata:
- `attestor`: Identity or email of reviewer
- `timestamp`: Date and time of review
- `scope`: Asset or environmental scope
- `statement`: Affirmation statement
- `expiration`: Mandatory expiration date (e.g. 90 days)

Human attestation does not replace technical automated evidence, but serves as auxiliary evidence for organizational controls.
