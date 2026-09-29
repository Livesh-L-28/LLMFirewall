# Control Mapping & Cross-Framework Harmonization

Compliance controls rarely have 1-to-1 mappings with technical implementations or between different frameworks. LLMFirewall provides a flexible **many-to-many mapping model**.

---

## 1. Many-to-Many Architecture

A single defensive security control or guardrail can satisfy multiple compliance controls:
```text
Tool Authorization Guardrail
          │
          ├── AC-01 (Agent Tool Authorization)
          ├── TS-01 (Tool Security)
          └── DS-01 (Data Exfiltration Prevention)
```

Conversely, a single compliance control typically demands evidence from multiple technical subsystems:
```text
AC-01 (Tool Authorization)
          │
          ├── Configuration Policy (Governance)
          ├── Runtime Guardrail (Security Control)
          ├── Posture Validation (AI-SPM)
          └── Automated Security Test Result (Testing)
```

---

## 2. ControlMapping Model

The `ControlMapping` class establishes traceable relationships across entities:

```python
from llmfirewall.compliance import ControlMapping

mapping = ControlMapping(
    control_id="ai-baseline:AC-01",
    asset_id="agent:customer-support",
    posture_dimension="access_control",
    security_control_id="guardrail:tool_authorization",
    finding_id="F-TA-01",
    test_id="TEST-TOOL-AUTH-01",
    attack_path_id="AP-004",
    rationale="Tool authorization guardrail validates and blocks unauthorized invocations.",
)
```

---

## 3. Cross-Framework Mapping (Section 30)

Organizations often map their internal frameworks against external standards or baselines:

```text
Company Policy AC-01  ──[EXACT / PARTIAL]──>  AI Baseline AC-01
```

### Supported Mapping Types:
- `EXACT`: Direct 1-to-1 conceptual equivalence.
- `PARTIAL`: Overlapping requirements; some requirements left uncovered.
- `RELATED`: Similar objectives or complementary controls.
- `DERIVED`: Control synthesized or adapted from an existing standard.
- `ORGANIZATION_DEFINED`: Custom organization-specific alignment.

### Mapping Invariant
> [!IMPORTANT]
> Cross-framework mappings document conceptual and technical alignment. They **do not imply legal certification or statutory equivalence**. Every mapping must document:
> 1. *Why are these controls related?*
> 2. *What evidence supports the mapping?*
> 3. *What requirements are not covered?*
