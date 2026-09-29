# AI Security Risk & Prioritization Engine (Phase 37)

The AI Security Risk & Prioritization Engine converts findings, attack paths, security controls, compliance gaps, and configurations into an **evidence-driven, explainable risk assessment system**.

Rather than returning opaque or arbitrary scores, LLMFirewall provides clear, transparent rationales for *why* an asset is prioritized.

---

## 1. Core Architecture

```text
Assets (Agents, Models, Datasets, Tools)
  │
  ├── Findings
  ├── Attack Paths
  ├── Security Controls
  ├── Compliance Gaps
  ├── Configuration
  └── Test Results
          │
          ↓
   Risk Prioritization Engine
          │
    ┌─────┼─────┐
    ↓     ↓     ↓
 Impact Exposure Evidence
    │     │     │
    └─────┼─────┘
          ↓
   Prioritized Risk Assessment
```

### 1.1 Multi-Factor Risk Evaluation

Risk is determined through independent, explainable factors:
1. **Criticality / Business Impact**: Criticality score of the primary asset and connected data stores.
2. **Data Sensitivity**: Classification of data handled (`restricted`, `confidential`, `sensitive`, `public`).
3. **Attack Path Severity**: Presence of validated multi-hop attack paths reaching crown jewels.
4. **Control Effectiveness**: Compensating controls (e.g. rate limiters, input guardrails, authorization policies).
5. **Exposure Level**: Reachability of the asset (`external`, `internal`, `isolated`).
6. **Compliance Gaps**: Unresolved gaps in mandatory security baselines.
7. **Downstream Inheritance**: Risks inherited when an agent connects to sensitive internal tools or databases.

### 1.2 Epistemic Uncertainty

LLMFirewall treats missing data with explicit epistemic uncertainty:
- `LOW`: Comprehensive test coverage, verified configuration, and fresh evidence.
- `MEDIUM`: Partial configuration or older evidence.
- `HIGH`: Missing configuration or unvalidated dependencies.

> [!IMPORTANT]
> **Safety Invariant**: Missing evidence is NEVER treated as proof of safety. High uncertainty elevates the attention priority of an asset.

---

## 2. Python API

```python
from llmfirewall import Firewall, RiskLevel, RiskFactorType

fw = Firewall()

# Run discovery and register assets
fw.discover_assets()

# Prioritize risks for a specific agent
assessments = fw.risk.prioritize(asset_id="agent:support_copilot")
for r in assessments:
    print(f"[{r.level.value}] {r.asset_id}: {r.rationale}")
    print(f"Uncertainty: {r.uncertainty.value}")
    for factor in r.factors:
        print(f"  - {factor.name}: {factor.rationale}")

# Create risk baseline snapshot
snap1 = fw.risk.snapshot(environment="production")

# Compare snapshots to detect risk drift
diff = fw.risk.diff(snap1, snap2)
if diff.has_regressions:
    print(f"New high-risk assets: {diff.elevated_risks}")
```

---

## 3. CLI Commands

```bash
# Prioritize risks across all assets
llmfirewall risk

# Prioritize specific asset
llmfirewall risk agent:support_copilot --format detail

# Export risk assessments as JSON
llmfirewall risk --format json --output risk_report.json

# Snapshot risk posture
llmfirewall risk snapshot --output baseline_risk.json

# Detect risk regression diff
llmfirewall risk diff --before baseline_risk.json --after current_risk.json
```
