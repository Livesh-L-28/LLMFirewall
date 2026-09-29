# LLM & Agent Runtime Protection (Phase 26)

LLMFirewall provides deterministic, multi-boundary runtime protection across the complete execution lifecycle of an LLM and agent system.

---

## 1. Runtime Architecture

Traditional firewalls only inspect requests at the edge or endpoint level. Modern agentic systems, however, execute dynamic multi-turn reasoning loops, retrieve external RAG context, and invoke external tools.

LLMFirewall introduces the **Runtime Security Engine**, which wraps and protects every stage:

```text
                 Agent Runtime
                      │
          ┌───────────┼───────────┐
          ↓           ↓           ↓
        Input        LLM         Tool
          │           │           │
          ↓           ↓           ↓
       Firewall    Firewall    Firewall
          │           │           │
          └───────────┼───────────┘
                      ↓
                Policy Engine
                      ↓
              ALLOW / WARN / BLOCK / REDACT
```

---

## 2. Execution Boundaries

The runtime establishes 8 explicit execution boundaries:

1. **USER_INPUT**: Initial prompt received from user before any prompt construction or retrieval.
2. **PROMPT**: Reconstructed prompt containing system instructions, memory, and retrieved RAG context. Untrusted sources are scanned without implicitly trusting internal retrieval stores.
3. **LLM_REQUEST**: Pre-LLM outbound payload inspection to ensure no harmful instructions are dispatched to the model.
4. **LLM_RESPONSE**: Inbound model completion inspection before parsing tool calls or downstream rendering.
5. **TOOL_REQUEST**: Agent tool authorization, schema validation, SSRF checks, and destructive command interception.
6. **TOOL_RESULT**: External tool output inspection to prevent indirect prompt injection, data poisoning, and credential leakage.
7. **AGENT_LOOP**: Loop guard safety limits enforcing maximum iterations, tool budgets, repetition detection, and execution timeouts.
8. **FINAL_RESPONSE**: Final completion output inspection, PII redaction, and telemetry trace recording.

---

## 3. Trust Classifications & Content Provenance

When synthesizing prompts, content is classified by provenance and trust levels:

* `SYSTEM`: Trusted developer or system prompts.
* `DEVELOPER`: Application instructions and guardrails.
* `USER`: Untrusted end-user text.
* `RETRIEVED`: Content from vector stores, knowledge bases, or web scraping (treated as untrusted by default).
* `TOOL`: Outputs returned from tool execution (treated as untrusted by default).
* `EXTERNAL`: 3rd-party webhooks or foreign APIs.
* `UNTRUSTED`: Explicitly untrusted data.

```python
from llmfirewall import ContentItem, TrustLevel

items = [
    ContentItem(text="You are a data assistant.", source=TrustLevel.SYSTEM),
    ContentItem(text="Retrieved document context...", source=TrustLevel.RETRIEVED),
]
session.check_prompt(items)
```

---

## 4. Lifecycle Hooks

Developers can hook into the execution lifecycle deterministically:

```python
from llmfirewall import RuntimeHook, RuntimeContext, RuntimeDecision

class CustomAuditHook(RuntimeHook):
    def before_input(self, user_input: str, context: RuntimeContext):
        return user_input.strip()

    def after_input(self, user_input: str, decision: RuntimeDecision, context: RuntimeContext):
        pass

    def before_tool(self, tool_call, context):
        return tool_call

    def after_tool(self, tool_result, decision, context):
        pass
```

### Deterministic Hook Order:
1. `before_input` → Input Security → `after_input`
2. `before_prompt` → Prompt Construction Security → `after_prompt`
3. `before_llm` → Pre-LLM Request Security
4. Model Invocation
5. `after_llm` → Post-LLM Response Security
6. `before_tool` → Tool Security Engine → Tool Execution
7. `after_tool` → Tool Result Security
8. `before_loop` → Loop Guard limits → `after_loop`
9. `before_output` → Final Output Security → `after_output`

---

## 5. Loop Guard & Operational Budgets

Agents can get trapped in infinite reasoning cycles or repeatedly invoke tools with identical arguments. `LoopGuard` enforces strict bounds:

```python
session = firewall.runtime_session(
    max_iterations=20,
    max_tool_calls=30,
    max_runtime_seconds=120.0,
    max_repeated_tool_calls=3, # Identical tool name + args detected as loop
    max_tokens=100_000,
    max_cost=1.50,
)
```

When an operational limit is exceeded, `RuntimeLimitExceeded` is raised with detailed configuration and observed telemetry.

---

## 6. Provider Independence & Adapters

LLMFirewall operates without mandatory provider SDKs. The `GenericProviderAdapter` translates OpenAI-compatible dictionaries or objects into normalized `LLMRequest` and `LLMResponse` structures:

```python
from llmfirewall import GenericProviderAdapter

adapter = GenericProviderAdapter()
req = adapter.prepare_request({"model": "gpt-4o", "messages": [...]})
resp = adapter.inspect_response(raw_completion)
```

---

## 7. Decorator & Context Manager APIs

Guarding agents can be done imperatively or declaratively:

### Context Manager:
```python
with firewall.runtime.session() as session:
    session.check_user_input(prompt)
    session.step_iteration()
    session.check_tool_call("calculator", {"x": 2})
```

### Decorator:
```python
@firewall.runtime.protect_agent(max_iterations=15)
def agent_task(prompt: str, session: RuntimeSession) -> str:
    session.step_iteration()
    # Agent logic
    return "Result"
```

---

## 8. CLI Commands

```bash
# Simulate runtime guardrails
llmfirewall runtime simulate --input "What is the capital of France?" --tool calculator --json

# Inspect a completed runtime trace
llmfirewall runtime inspect --trace-id trace-12345 --backend sqlite
```

---

## 9. Security Limitations

Phase 26 runtime protection provides multi-boundary policy enforcement and semantic inspection. It **does NOT** provide:
* Operating system kernel sandboxing or process isolation (e.g. cgroups, seccomp).
* Container sandboxing or microVM isolation (e.g. Firecracker, Docker).
* Network packet firewalls (e.g. iptables, VPC network policies).
* Secrets management / IAM identity vaults.
* Autonomous incident response or active remediation.
