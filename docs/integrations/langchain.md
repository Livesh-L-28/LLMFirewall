# LangChain & LCEL Integration Recipe

Secure LangChain workflows, chains, and agents using `FirewallRunnable` (for LCEL pipe composition) and `FirewallCallbackHandler` (for callback lifecycle hooks).

---

## 1. Overview & Capabilities

LLMFirewall provides two complementary integration patterns for LangChain:

1. **`FirewallRunnable`**: First-class LCEL (LangChain Expression Language) component supporting `|` composition (`input_guard | prompt | model | output_guard`).
2. **`FirewallCallbackHandler`**: Full callback lifecycle handler for LLM, ChatModel, Agent, and Tool execution.

### Capabilities:
- **Inbound Prompt Protection**: Intercepts prompt injections before LLM invocation.
- **PII Redaction**: Redacts sensitive personal and financial identifiers, propagating sanitized text downstream.
- **Tool Call Gating**: Validates agent tool names and arguments against SSRF and command injection before dispatch.
- **Outbound Completion Inspection**: Scrubs credentials and API keys in LLM responses.
- **Distributed Security Context**: Inherits and propagates W3C traceparent headers and multi-tenant metadata.

---

## 2. Installation

```bash
# Install core package with LangChain optional extra
python -m pip install "llmfirewall-core[langchain]"
```

---

## 3. Composable LCEL Pipelines: `FirewallRunnable`

Use `FirewallRunnable` directly in LCEL pipelines with the `|` operator:

```python
from llmfirewall import Firewall
from llmfirewall.integrations.langchain import FirewallRunnable

fw = Firewall()

# Guards for input and output boundaries
input_guard = FirewallRunnable(firewall=fw, direction="input")
output_guard = FirewallRunnable(firewall=fw, direction="output")

# Compose standard LCEL pipe: guard | prompt | model | guard
chain = input_guard | prompt_template | model | output_guard

# Synchronous execution
response = chain.invoke("Explain photosynthesis")

# Asynchronous execution
response = await chain.ainvoke("Explain photosynthesis")
```

---

## 4. Lifecycle Hooks: `FirewallCallbackHandler`

```python
from llmfirewall import Firewall
from llmfirewall.integrations.langchain import FirewallCallbackHandler

# 1. Initialize firewall and handler
fw = Firewall()
handler = FirewallCallbackHandler(firewall=fw, raise_on_block=True)

# 2. Attach to any LangChain RunnableConfig, Chain, or LLM instance
config = {"callbacks": [handler]}

# Example invocation:
# chain.invoke({"input": "Hello, world!"}, config=config)
```

---

## 5. Securing Agent Tool Execution

When using LangChain agents with tool access:

```python
from llmfirewall import Firewall
from llmfirewall.integrations.langchain import FirewallCallbackHandler

fw = Firewall()
# Ensure tool calls are inspected against SSRF and unauthorized parameters
handler = FirewallCallbackHandler(firewall=fw, inspect_tools=True)

# Pass handler to agent executor:
# agent_executor.invoke({"input": user_query}, config={"callbacks": [handler]})
```

---

## 6. Offline Testing

See [`tests/test_framework_ecosystem_week8.py`](https://github.com/Livesh-L-28/LLMFirewall/blob/main/tests/test_framework_ecosystem_week8.py) for complete test recipes using LCEL and LangChain callbacks.
