# Attack Rules & Inference Engine (Phase 33)

The **Attack Rule Engine** governs how causal attack steps and potential compromise paths are inferred across components in the AI Security Knowledge Graph.

---

## 1. Declarative Rule Schema

Rather than scattering hardcoded `if/else` checks throughout the codebase, LLMFirewall standardizes on structured, auditable `AttackRule` objects:

```yaml
attack_rules:
  - rule_id: "R-PROMPT-TO-AGENT"
    name: "Ingress Prompt Injection to Agent"
    description: "External user input or prompt payload attempts to hijack agent control logic."
    source_type: "application"
    target_type: "agent"
    technique: "T-PI-01"
    requires:
      - untrusted_input
    postconditions:
      - agent_instruction_override
    mitigations:
      - "control:prompt_injection_detector"
      - "control:input_sanitizer"
    assumptions:
      - "Agent directly processes user-controlled prompt without rigid input firewalling."
    confidence: "MEDIUM"
```

---

## 2. Standard Built-in Attack Rules

LLMFirewall ships with built-in rules modeling core AI threat vectors:

| Rule ID | Source → Target | Technique | Key Preconditions | Mitigations |
| :--- | :--- | :--- | :--- | :--- |
| `R-PROMPT-TO-AGENT` | `application` → `agent` | `T-PI-01` (Prompt Injection) | `untrusted_input` | Prompt Injection Detector, Input Sanitizer |
| `R-DOC-TO-AGENT` | `rag_source` → `agent` | `T-IPI-02` (Indirect Injection) | `unverified_document_ingestion` | RAG Scanner, Document Trust Boundary |
| `R-AGENT-TO-TOOL` | `agent` → `tool` | `T-TA-04` (Tool Abuse) | `agent_tool_access`, `missing_authorization` | Tool Validator, RBAC Authorization, Approval Gate |
| `R-TOOL-TO-DATA` | `tool` → `tool` | `T-DE-06` (Data Exfiltration) | `access_to_sensitive_data` | Secret Detector, PII Detector, SQL Sanitizer |
| `R-AGENT-TO-CAPABILITY` | `agent` → `capability` | `T-PE-05` (Privilege Escalation) | `agent_capability_access`, `missing_approval_gate` | Capability Authorizer, Approval Gate |
| `R-AGENT-TO-AGENT` | `agent` → `agent` | `T-IO-03` (Instruction Override) | `untrusted_input` | Runtime Guard, Context Isolation |
| `R-DEP-TO-APP` | `dependency` → `application` | `T-SC-12` (Supply-Chain) | `vulnerable_dependency` | Dependency Scanner, SBOM Verifier |

---

## 3. Precondition Evaluation & False Positive Prevention

Attack steps require preconditions to hold true before firing.

### Preventing False Positive Tool Abuse
A common flaw in naive threat modeling is claiming:
```text
Agent has tool -> System is vulnerable to tool abuse
```
In LLMFirewall, `R-AGENT-TO-TOOL` strictly requires:
```text
agent_tool_access AND missing_authorization
```
The `PreconditionEvaluator` inspects the Knowledge Graph for protecting security controls (`PROTECTS` / `PROTECTED_BY`). If an effective RBAC or authorization control exists and has passing test results, `missing_authorization` evaluates to `False`, preventing false alarms:

```python
# Strong passing authorization control exists
kg.add_node("control:rbac", "security_control", properties={"mode": "rbac", "authorization": True})
kg.add_relationship("control:rbac", "PROTECTS", "tool:crm")

# Result: R-AGENT-TO-TOOL does NOT fire!
```

---

## 4. Attack Rule Registry & Validation

`AttackRuleRegistry` manages rule registration with strict validation:

1. **Technique Existence**: Every rule must reference a recognized technique ID from `default_technique_registry` (e.g. `T-PI-01`).
2. **Entity Type Validation**: Source and target types must belong to known `NodeType` enums or valid architectural entities.
3. **Cycle Rejection**: Ungrounded rules that create infinite self-loops with identical preconditions and postconditions are rejected.
4. **Versioning**: Every registry carries a `rules_version` string (e.g. `"1.0"`) to guarantee reproducible audit reports and baseline diffs.

---

## 5. Programmatic Registration

```python
from llmfirewall.attack_graph import AttackRule, AttackRuleRegistry, ConfidenceLevel

registry = AttackRuleRegistry(rules_version="2.0")

custom_rule = AttackRule(
    rule_id="R-WEBHOOK-TO-AGENT",
    name="Webhook Ingress to Agent",
    description="External webhook payload forwarded to agent reasoning context.",
    source_type="application",
    target_type="agent",
    technique="T-PI-01",
    requires=["untrusted_input"],
    postconditions=["agent_instruction_override"],
    mitigations=["control:webhook_authenticator"],
    assumptions=["Webhook payload is not cryptographically signed."],
    confidence=ConfidenceLevel.MEDIUM,
)

registry.register(custom_rule)
```
