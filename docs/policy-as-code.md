# Policy-as-Code & Security Rules Engine 2.0 (Phase 49)

LLMFirewall incorporates a declarative, deterministic **Policy-as-Code** engine that allows security and engineering teams to version-control, audit, validate, compose, simulate, and enforce AI safety rules across LLM applications, agentic workflows, RAG pipelines, and CI/CD stages.

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
                 Priority Sorting & Pre-Indexed Dispatch
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
                  (Action + Decision Trace)
```

- **Deterministic Evaluation**: Rules are evaluated in strict priority order with deterministic tie-breaking.
- **Pre-Indexed Dispatch**: Sub-millisecond matching across large rule sets.
- **Zero Scripting / Zero `eval()`**: Policies are strictly data-driven (JSON/YAML models). No arbitrary code execution, dynamic imports, or shell commands can be executed.
- **Fail-Closed Security**: Evaluation exceptions fail-closed to `Action.BLOCK`. Malformed policies never silently default to `ALLOW`.
- **Explainability**: Every `PolicyDecision` includes structured rule matching details (`explanations`) and complete step-by-step evaluation traces (`decision_trace`).
- **Conflict Resolution Precedence**:
  $$\text{BLOCK} > \text{REDACT} > \text{WARN} > \text{ALLOW}$$

---

## 2. Policy Schema & Models

### Policy Identity & Top-Level Schema (`Policy`)

```json
{
  "id": "urn:llmfirewall:policy:corp-strict-v1",
  "name": "production-ai-guardrail",
  "version": "1.1.0",
  "description": "Enterprise production policy",
  "rules": [...],
  "allowed_tools": ["search", "calculator"],
  "denied_tools": ["bash", "curl"],
  "default_action": "allow",
  "auto_redact_on_warn": true
}
```

| Field | Type | Default | Description |
|:---|:---:|:---:|:---|
| `id` | `Optional[str]` | `None` | Unique URN or identifier for the policy document. |
| `name` | `str` | `"custom_policy"` | Policy name for telemetry and logs. |
| `version` | `str` | `"1.0"` | Semantic version string. |
| `rules` | `List[PolicyRule]` | `[]` | Declarative security rules evaluated by priority. |
| `allowed_tools` | `Optional[List[str]]` | `None` | Tool allowlist (any unlisted tool is blocked). |
| `denied_tools` | `Optional[List[str]]` | `None` | Tool denylist (any listed tool is strictly blocked). |
| `default_action` | `Action` | `Action.ALLOW` | Fallback action when no rules trigger. |

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

### Advanced Predicates (`RuleCondition`)

- `threat_type`: Target `ThreatType` (`prompt_injection`, `secret`, `pii`, `toxicity`, `malicious_url`, etc.).
- `detector`: Specific detector name (`prompt_injection_detector`, `pii_detector`, etc.).
- `category`: Fine-grained classification ID (e.g. `email`, `api_key`, `indirect_injection`).
- `min_severity` / `max_severity`: `low`, `medium`, `high`, or `critical`.
- `min_confidence`: Minimum confidence threshold in $[0.0, 1.0]$.
- `min_risk_score` / `max_risk_score`: Score boundary in $[0.0, 1.0]$.
- `min_findings_count`: Integer threshold for number of detected findings.
- `direction`: Traffic filter (`"input"` or `"output"`).
- `source`: Match caller source (`"prompt"`, `"retrieval"`, `"tool_result"`, `"memory"`, `"system"`).
- `trust_level`: Match trust classification (`"untrusted"`, `"controlled"`, `"trusted"`).
- `user_id`: Match specific user or tenant identifier.
- `tool` / `tool_permission`: Agentic tool name and permission constraints.
- `custom_predicates`: Arbitrary context key-value matching.

---

## 3. Policy Composition

Policies can be merged programmatically using `policy.compose()`:

```python
from llmfirewall import Policy

base_policy = Policy.from_file("policies/base.json")
sec_override = Policy.from_file("policies/sec_team.json")

# Strategies: 'override', 'append', 'error_on_conflict', 'keep_existing'
merged = base_policy.compose(sec_override, strategy="override")
```

- **Rule Collisions**: Resolved via the selected strategy.
- **Tool Controls**: Denylists are unioned; allowlists are intersected.
- **Default Action**: Most restrictive action wins.
- **Metadata**: Combined and tagged with `"composed_from"`.

---

## 4. Policy Linting & Static Analysis

Detect misconfigurations, unreachable rules, and contradictions before deploying:

```python
from llmfirewall.policy import lint_policy

report = lint_policy(policy)
if not report.valid:
    for issue in report.issues:
        print(f"[{issue.severity.value.upper()}] {issue.code}: {issue.message}")
        print(f"  Recommendation: {issue.recommendation}")
```

### Static Checks
- `ERR_TOOL_CONFLICT`: Tool listed in both `allowed_tools` and `denied_tools`.
- `ERR_INVERTED_SEVERITY`: `min_severity > max_severity`.
- `ERR_INVERTED_RISK_BOUNDS`: `min_risk_score > max_risk_score`.
- `WARN_SHADOWED_RULE`: Rule unreachable due to higher priority BLOCK rule with identical criteria.
- `WARN_UNCONDITIONAL_RULE`: Rule has no criteria and will match all traffic.
- `WARN_PERMISSIVE_POLICY`: Policy has `default_action=ALLOW` and zero BLOCK rules.

---

## 5. Policy Dry-Run Simulation

Simulate policy outcomes on real findings without enforcement or redaction:

```python
from llmfirewall.policy import PolicyEngine

engine = PolicyEngine(config=policy)
sim = engine.simulate(text=prompt, findings=findings, risk_score=risk)

print(f"Simulated Action: {sim.simulated_action.value.upper()}")
print(f"Winning Rule:     {sim.winning_rule_id}")
print(f"Triggered Rules:  {sim.triggered_rules}")
print(f"Shadowed Rules:   {sim.shadowed_rules}")
```

---

## 6. Policy Explainability & Traces

Inspect the exact evaluation path for audit compliance:

```python
explanation = engine.explain(text=prompt, findings=findings, risk_score=risk)
print(f"Winning Rule: {explanation['winning_rule_id']}")
for step in explanation["decision_trace"]:
    status = "MATCH" if step["matched"] else "SKIP"
    print(f"  [{status}] {step['rule_id']} ({step['action']})")
```
