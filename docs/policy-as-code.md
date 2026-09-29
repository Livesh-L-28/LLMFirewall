# Policy-as-Code & Security Rules Engine (Phase 21)

LLMFirewall incorporates a declarative **Policy-as-Code** engine that allows security and engineering teams to version-control, audit, validate, and enforce AI safety rules consistently across LLM applications, RAG pipelines, and CI/CD stages.

---

## 1. Architectural Philosophy

```text
       Scan Findings + Composite RiskScore + Request Context
                                 │
                                 ▼
                     ┌───────────────────────┐
                     │   Policy-as-Code      │
                     │   (Declarative Rules) │
                     └───────────┬───────────┘
                                 │
                 Priority Sorting & Evaluation
                                 │
                                 ▼
                     ┌───────────────────────┐
                     │  Conflict Resolution  │
                     │  BLOCK > REDACT >     │
                     │  WARN  > ALLOW        │
                     └───────────┬───────────┘
                                 │
                                 ▼
                      Typed PolicyDecision
                  (Action + Explainability)
```

- **Deterministic Evaluation**: Rules are evaluated in strict priority order with deterministic tie-breaking.
- **Zero Scripting / Zero `eval()`**: Policies are strictly data-driven (JSON/YAML models). No arbitrary code execution, dynamic imports, or shell commands can be executed.
- **Explainability**: Every `PolicyDecision` includes structured rule matching details (`explanations`), indicating exactly why an action was chosen.
- **Conflict Resolution**: When multiple rules match different actions, the engine applies strict safety precedence:
  $$\text{BLOCK} > \text{REDACT} > \text{WARN} > \text{ALLOW}$$

---

## 2. Policy Schema & Rule Models

### Top-Level Document (`Policy`)

```json
{
  "name": "production-ai-guardrail",
  "version": "1.0",
  "description": "Enterprise production policy",
  "rules": [...],
  "default_action": "allow",
  "auto_redact_on_warn": true
}
```

### Rule Model (`PolicyRule`)

| Field | Type | Default | Description |
|:---|:---:|:---:|:---|
| `id` | `str` | *required* | Unique identifier for rule (e.g. `block_secrets`). |
| `name` | `Optional[str]` | `None` | Human-readable title for audit/explanations. |
| `description` | `str` | `""` | Intent and policy rationale. |
| `action` | `Action` | *required* | `allow`, `warn`, `block`, or `redact`. |
| `priority` | `int` | `100` | Integer rank in $[1, 1000]$. Higher values evaluated first. |
| `enabled` | `bool` | `True` | Toggle rule activation without deleting definition. |
| `conditions` | `List[RuleCondition]` | `[]` | Compound criteria evaluated via `operator`. |
| `operator` | `LogicalOperator` | `"and"` | `"and"` or `"or"` across compound conditions. |

### Rule Conditions (`RuleCondition`)

- `threat_type`: Target `ThreatType` (`prompt_injection`, `secret`, `pii`, `toxicity`, `malicious_url`, etc.).
- `detector`: Specific detector name (`prompt_injection_detector`, `pii_detector`, etc.).
- `category`: Fine-grained classification ID (e.g. `email`, `api_key`, `instruction_override`).
- `min_severity` / `max_severity`: `low`, `medium`, `high`, or `critical`.
- `min_risk_score` / `max_risk_score`: Score boundary in $[0.0, 1.0]$.
- `min_findings_count`: Integer threshold for number of detected findings.
- `direction`: Traffic filter (`"input"` or `"output"`).

---

## 3. Practical Policy Examples

### Example: Strict Enterprise Policy (`strict.json`)
```json
{
  "name": "strict-enterprise-policy",
  "version": "1.0",
  "description": "Zero-tolerance enterprise policy",
  "rules": [
    {
      "id": "strict-block-injection",
      "name": "Block Injections",
      "threat_type": "prompt_injection",
      "action": "block",
      "priority": 100
    },
    {
      "id": "strict-block-secrets",
      "name": "Block Credentials",
      "threat_type": "secret",
      "action": "block",
      "priority": 90
    },
    {
      "id": "strict-block-pii",
      "name": "Block Any PII",
      "threat_type": "pii",
      "action": "block",
      "priority": 85
    }
  ],
  "default_action": "allow"
}
```

---

## 4. Python API Usage

```python
from llmfirewall import Firewall, Policy

# Load policy from version-controlled file
policy = Policy.from_file("policies/strict.json")

# Instantiate firewall with policy
firewall = Firewall(policy=policy)

result = firewall.check("My secret key is 12345")

# Inspect structured explanation
decision = result.decision
print(f"Action: {decision.action}")
print(f"Policy: {decision.policy_id} v{decision.policy_version}")
print(f"Matched Rules: {decision.triggered_rules}")
for exp in decision.explanations:
    print(f" - Rule: {exp['rule_name']} (Priority: {exp['priority']})")
```

---

## 5. Command-Line Interface (CLI)

### Validate Policy Syntax & Invariants
```bash
llmfirewall policy validate policies/default.json
# Policy: default-ai-security
# Version: 1.0
# Status: VALID
# Rules: 5 (Enabled: 5, Disabled: 0)
```

### Inspect Policy Rules
```bash
llmfirewall policy show policies/default.json
```

### Run Policy Scan with Dry-Run
```bash
llmfirewall scan --policy policies/strict.json --dry-run "My email is user@example.test"
```

---

## 6. Performance Characteristics

- **Baseline Policy Evaluation (5 rules)**: ~0.0035 ms (~280,000 ops/sec).
- **Scaled Policy Evaluation (50 rules)**: ~0.113 ms (~8,500 ops/sec).
- **Execution Overhead**: Adding structured explainability adds less than 0.002 ms per request.
