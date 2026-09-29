# Posture Rules & Declarative Evaluation

## 1. Overview

The [PostureRuleRegistry](file:///Users/livesh/LLMFirewall/src/llmfirewall/spm/rules.py) manages declarative security posture rules that analyze asset context and emit structured [SecurityGap](file:///Users/livesh/LLMFirewall/src/llmfirewall/spm/models.py) findings.

Rules are versioned (`rules_version = "1.0.0"`) and reproducible across snapshots.

---

## 2. Rule Architecture

Each rule implements the [PostureRule](file:///Users/livesh/LLMFirewall/src/llmfirewall/spm/rules.py) interface:

```python
class PostureRule:
    def __init__(
        self,
        rule_id: str,
        name: str,
        dimension: PostureDimension,
        severity: Severity,
        description: str,
        evaluator: Callable[[PostureRuleContext], Optional[SecurityGap]],
        remediation_guidance: Optional[str] = None,
        enabled: bool = True,
    )
```

The evaluator receives a [PostureRuleContext](file:///Users/livesh/LLMFirewall/src/llmfirewall/spm/rules.py) containing:
* `asset`: Target asset record (ID, type, name, environment, metadata).
* `controls`: Active defensive controls protecting the asset.
* `attack_surface`: Cataloged tools, external APIs, memory stores, RAG sources, and entry points.
* `attack_paths`: Candidate, supported, and tested attack paths reaching this asset.
* `test_coverage`: Empirical security test results and freshness status.
* `findings`: Open, resolved, and accepted governance findings.
* `policy_status`: Assigned policies, active versions, and detected policy conflicts.
* `drift`: Recorded version drift or conflict records.

---

## 3. Standard Built-In Rules

AI-SPM provides 10 standard rules covering core AI risk domains:

| Rule ID | Dimension | Severity | Condition & Evidentiary Trigger |
|---|---|---|---|
| `R-TOOL-AUTH-UNKNOWN` | `tool_security` | HIGH | Agent has callable tools, but tool authorization policy/guardrail is UNKNOWN or ABSENT. |
| `R-DATABASE-VALIDATION-MISSING` | `data_security` | HIGH | Asset is a database tool, but input/output validation guardrail is UNTESTED or FAILED. |
| `R-UNMITIGATED-ATTACK-PATH` | `attack_surface` | HIGH | Attack graph identifies a supported or tested attack path reaching the asset without active mitigation. |
| `R-UNTESTED-SECURITY-CONTROL` | `testing` | MEDIUM | Defensive control is configured (`PRESENT`) but has zero empirical security test coverage. |
| `R-STALE-TEST-COVERAGE` | `testing` | MEDIUM | Security test passed, but asset configuration was modified after the test execution. |
| `R-OPEN-CRITICAL-FINDING` | `governance` | CRITICAL | Asset is associated with an unresolved CRITICAL or HIGH governance finding. |
| `R-POLICY-CONFLICT` | `configuration_security` | HIGH | Contradictory policy rules govern this asset (e.g. Policy A allows a tool while Policy B forbids it). |
| `R-ENTRYPOINT-UNPROTECTED` | `prompt_security` | HIGH | External entry point is exposed without prompt firewall or injection detection protection. |
| `R-RAG-ACCESS-CONTROL` | `rag_security` | MEDIUM | Agent queries RAG document sources without verified tenant access controls or document boundaries. |
| `R-MEMORY-POISONING-UNTESTED` | `memory_security` | MEDIUM | Agent connects to persistent memory store without verified memory poisoning defenses. |

---

## 4. Registering Custom Rules

Organizations can declare custom rules tailored to internal compliance guidelines:

```python
from llmfirewall.spm import PostureRule, PostureDimension, SecurityGap, PostureRuleContext
from llmfirewall.core.models import Severity

def eval_custom_sandbox(ctx: PostureRuleContext):
    if ctx.asset_type == "agent":
        code_exec = any("bash" in t or "python" in t for t in ctx.attack_surface.tools)
        has_sandbox = "control:container_sandbox" in ctx.controls
        if code_exec and not has_sandbox:
            return SecurityGap(
                asset_id=ctx.asset_id,
                dimension=PostureDimension.AGENT_SECURITY.value,
                title="Code Execution Agent Lacks Sandbox Isolation",
                description="Agent has code execution tools but container sandbox is not detected.",
                severity=Severity.CRITICAL,
                remediation_guidance="Enforce container sandbox isolation around tool executor.",
            )
    return None

custom_rule = PostureRule(
    rule_id="R-CORP-SANDBOX-001",
    name="Enforce Code Execution Sandbox",
    dimension=PostureDimension.AGENT_SECURITY,
    severity=Severity.CRITICAL,
    description="Requires sandboxing for any agent capable of code execution.",
    evaluator=eval_custom_sandbox,
)

engine.rule_registry.register(custom_rule)
```
