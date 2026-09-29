# Control Catalog & AI Security Domains

The **Control Catalog** (`ControlCatalog`) serves as the authoritative, versioned repository of compliance controls and frameworks in LLMFirewall.

---

## 1. Stable Control Identifiers

Every control in LLMFirewall uses a stable canonical identifier of the format:
```text
<framework_id>:<control_id>
```
Example:
```text
ai-baseline:AC-01
```

Avoid identifiers dependent on display titles or categories to ensure stability as frameworks evolve.

---

## 2. Standard 15 AI Security Domains

The built-in starter catalog (`ai-security-baseline` v1.0.0) covers 15 key AI security domains:

| Control ID | Domain | Title | Target Asset Types |
|---|---|---|---|
| `AM-01` | AI Asset Management | AI Asset Inventory & Continuous Discovery | Application, Agent, Model, Tool, RAG Source, Memory Store |
| `MD-01` | Model Security | Model Provenance & Change Detection | Model |
| `AG-01` | Agent Security | Autonomous Agent Execution Guardrails | Agent |
| `PS-01` | Prompt Security | Prompt Injection & Jailbreak Defense | Application, Agent |
| `TS-01` | Tool Security | Agent Tool Invocation Guardrails | Agent, Tool |
| `AC-01` | Access Control | Agent Tool Authorization & Least Privilege | Agent, Tool |
| `DS-01` | Data Security | Sensitive Data Leakage & Secret Redaction | Application, Agent, Model, Tool |
| `RS-01` | RAG Security | Retrieval-Augmented Generation Grounding & Integrity | RAG Source, Agent |
| `MS-01` | Memory Security | Persistent AI Memory Security & Poisoning Defense | Memory Store, Agent |
| `SC-01` | Supply Chain Security | AI Package & Dependency Vulnerability Screening | Package, Dependency |
| `MO-01` | Monitoring | Real-Time Telemetry & Security Anomaly Detection | Application, Agent |
| `IR-01` | Incident Response | Automated Containment & Circuit Breakers | Application, Agent |
| `ST-01` | Security Testing | Automated Adversarial Evaluation | Application, Agent, Model |
| `GV-01` | Governance | Mandatory Security Baselines & Release Gates | Application |
| `PV-01` | Privacy | PII & Privacy Protection | Application, Agent |

---

## 3. Catalog API

```python
from llmfirewall.compliance import ControlCatalog

cat = ControlCatalog()

# 1. Retrieve a control
control = cat.get_control("ai-baseline:AC-01")
print(control.title, control.evidence_requirements)

# 2. Search controls across domains
results = cat.search(query="authorization", category="access_control")

# 3. Load custom organizational framework pack
custom_fw = cat.load_pack_from_file("company_controls.yaml")

# 4. Cross-framework mapping
cat.add_cross_mapping(
    source_control_id="company-ai:AC-01",
    target_control_id="ai-baseline:AC-01",
    rationale="Both enforce mandatory agent tool authorization.",
)
```
