# Framework & Ecosystem Integrations Overview

Phase 25 provides integration adapters for common Python AI frameworks and web services.

---

## 1. Supported Ecosystem Matrix

| Integration | Type | Input Protection | Output Protection | Tool Guardrails | RAG Context | Streaming | Async Support | Tested Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **FastAPI** | ASGI Middleware / Dependency | ✓ | ✓ | — | — | ✓* | Native Async | Verified |
| **Flask** | Extension / Decorator | ✓ | ✓ | — | — | ✓* | Synchronous | Verified |
| **Django** | HTTP Middleware | ✓ | ✓ | — | — | ✓* | Sync / ASGI | Verified |
| **LangChain** | CallbackHandler | ✓ | ✓ | ✓ | ✓ | ✓* | Native Async & Sync | Verified |
| **LlamaIndex**| NodePostprocessor | ✓ | — | — | ✓ (Node filtering) | — | Native Async & Sync | Verified |
| **Generic Python** | `@protect` Decorator | ✓ | ✓ | — | — | — | Native Async & Sync | Verified |

*\* Streaming limitation: Real-time token streaming inspection operates either via chunk buffering or final response inspection to prevent bypassing syntactic security bounds.*

---

## 2. Generic `@protect` Decorator

Protect arbitrary Python functions without requiring web frameworks:

```python
from llmfirewall import Firewall
from llmfirewall.integrations import protect, SecurityViolation

firewall = Firewall()

@protect(firewall=firewall, input_arg_name="prompt", inspect_output=True)
def query_model(prompt: str) -> str:
    return llm.predict(prompt)

try:
    response = query_model("What is the capital of Japan?")
except SecurityViolation as exc:
    print(f"Call blocked: {exc.message} (Request ID: {exc.request_id})")
```

Supports both sync `def` and `async def` functions.

---

## 3. Web Framework Integrations

### FastAPI
```python
from fastapi import FastAPI
from llmfirewall.integrations.fastapi import FirewallMiddleware, add_security_routes

app = FastAPI()
app.add_middleware(FirewallMiddleware, paths=["/chat", "/generate"])
add_security_routes(app, prefix="/security")
```

### Flask
```python
from flask import Flask
from llmfirewall.integrations.flask import FirewallExtension

app = Flask(__name__)
FirewallExtension(app, paths=["/api/v1/chat"])
```

### Django
In `settings.py`:
```python
MIDDLEWARE = [
    ...
    "llmfirewall.integrations.django.FirewallMiddleware",
]
```

---

## 4. Agent & RAG Integrations

### LangChain
```python
from llmfirewall.integrations.langchain import FirewallCallbackHandler

handler = FirewallCallbackHandler(inspect_prompts=True, inspect_tools=True, inspect_outputs=True)
chain.invoke({"input": user_prompt}, config={"callbacks": [handler]})
```

### LlamaIndex
```python
from llmfirewall.integrations.llamaindex import FirewallNodePostprocessor

postprocessor = FirewallNodePostprocessor()
query_engine = index.as_query_engine(node_postprocessors=[postprocessor])
response = query_engine.query("Summarize financial earnings")
```

---

## 5. Security & Boundary Guarantees

1. **Thin Adapters**: Adapters only normalize and delegate to the existing deterministic `Firewall` core; they never duplicate detection logic.
2. **Fail-Closed by Default**: When an unparseable or malicious request occurs on protected paths, the adapters reject the request with HTTP 403 / `SecurityViolation`.
3. **Correlation ID Consistency**: All adapters propagate `request_id` and integrate with Phase 24 observability event stores and metrics.
