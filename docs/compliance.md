# AI Security Compliance & Control Mapping (Phase 36)

LLMFirewall **Phase 36** introduces an **evidence-driven compliance and control-mapping engine** for AI systems, building on Phase 31 (Governance), Phase 32 (Knowledge Graph), Phase 33 (Attack Graph), Phase 34 (AI Asset Inventory), and Phase 35 (AI Security Posture Management).

---

## 1. Core Mission & Philosophy

While Phase 35 answers:
```text
HOW SECURE IS THE AI ENVIRONMENT?
```

Phase 36 answers:
```text
WHICH SECURITY REQUIREMENTS APPLY?
WHICH CONTROLS ADDRESS THEM?
WHAT EVIDENCE SUPPORTS EACH CONTROL?
WHAT IS MISSING?
WHAT IS UNKNOWN?
```

### The Evidence Mapping Principle
> [!IMPORTANT]
> **LLMFirewall provides evidence mapping and technical assessment, NOT legal certification.**
> The system does not claim *"System is ISO 27001 compliant"* merely because technical guardrails exist. Instead, it reports:
> ```text
> Control: Access Control (AC-01)
> Status: PARTIALLY_EVIDENCED
> Evidence:
>   - Authorization policy exists (VALID)
>   - Tool authorization test passed (VALID)
>   - Production configuration evidence missing
> Gap: Production evidence required
> ```

---

## 2. Architecture & Data Flow

```text
Asset Inventory (Phase 34)
       ↓
Knowledge Graph (Phase 32)
       ↓
Attack Graph (Phase 33)
       ↓
AI-SPM Posture (Phase 35)
       ↓
Compliance & Control Mapping (Phase 36)
       ↓
Evidence Collection & Freshness Validation
       ↓
Control Status Assessment
       ↓
Compliance Report & Audit Trail
```

### Complete Evidence Chain (Section 63)
Every assessment conclusion is traceable end-to-end:
```text
Framework Control
       ↓
Assessment Rule
       ↓
Asset
       ↓
Security Control
       ↓
Posture
       ↓
Test / Policy / Finding
       ↓
Evidence
```

---

## 3. Standardized Control States

LLMFirewall defines nine standardized control evaluation states:

| State | Semantics |
|---|---|
| `NOT_ASSESSED` | Control is cataloged in the framework but has not yet been evaluated for the asset or environment. |
| `NOT_APPLICABLE` | Control does not apply to the asset type, environment, or scope (e.g. data center physical security for a software prompt template). |
| `NOT_IMPLEMENTED` | Applicable control is required, but zero defensive security controls or policies exist. |
| `PARTIALLY_IMPLEMENTED` | Some required defensive controls exist, but others are missing from configuration. |
| `IMPLEMENTED` | Defensive security controls and policies are configured, but empirical security test evidence has not verified efficacy. |
| `PARTIALLY_EVIDENCED` | Some required evidence exists and is valid, but other required evidence items are missing, untested, or stale. |
| `EVIDENCED` | Full required evidence exists, is fresh and valid, confirming the control is configured and effective. |
| `FAILED` | Negative evidence exists (e.g. failing security test, active exploit finding, conflicting evidence, or broken guardrail). |
| `UNKNOWN` | Incomplete observations, unobserved asset, or missing telemetry prevents assessing implementation or evidence. |

---

## 4. Factual Coverage (No Fake Scores)

Avoid misleading labels such as *"80% compliant"*. LLMFirewall reports factual breakdowns across evaluated controls:

```text
Applicable Controls:      20
Evidenced:                12
Partially Evidenced:       4
Implemented (Untested):    1
Not Implemented:           2
Failed:                    1
Unknown:                   0
```

---

## 5. Quickstart Example

```python
from llmfirewall import Firewall, FirewallConfig

fw = Firewall()

# Discover assets and evaluate compliance across all controls
fw.discover_assets()
assessments = fw.assess_compliance(asset_id="agent:customer-support")

for a in assessments:
    print(f"[{a.status.value}] {a.control_id}: {len(a.evidence)} evidence items, {len(a.gaps)} gaps")
```

Generate snapshot and diff:
```python
# Create baseline snapshot
snap1 = fw.compliance.snapshot()

# Compare against subsequent snapshot
snap2 = fw.compliance.snapshot()
diff = fw.compliance.diff(snap1, snap2)

if diff.regressions:
    print(f"Detected {len(diff.regressions)} compliance regressions!")
```
