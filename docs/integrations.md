# Ecosystem Integrations

LLMFirewall seamlessly integrates across the AI and DevOps ecosystem. For in-depth architecture and guides, see [integrations/overview.md](integrations/overview.md).

---

## 1. Supported Frameworks & Integrations

- **Web Frameworks**: FastAPI, Starlette, Flask, Django (via ASGI/WSGI `LLMFirewallMiddleware`).
- **LLM Orchestrators**: LangChain, LlamaIndex, AutoGen, CrewAI, Semantic Kernel.
- **Model Providers**: OpenAI, Anthropic Claude, Google Gemini, Ollama, vLLM, HuggingFace Inference Endpoints.
- **Observability**: OpenTelemetry, Prometheus, Datadog, Splunk.
- **CI/CD & DevOps**: GitHub Actions, GitLab CI, Jenkins (SARIF 2.1.0 output for GitHub Code Scanning).

---

## 2. FastAPI Example

```python
from fastapi import FastAPI
from llmfirewall.protection import LLMFirewallMiddleware

app = FastAPI()
app.add_middleware(LLMFirewallMiddleware, agent_id="fastapi_service")

@app.post("/chat")
def chat(message: str):
    return {"reply": f"Processed: {message}"}
```

---

## 3. GitHub Actions CI/CD Integration

Export security evaluation and posture results in standard SARIF format:

```bash
llmfirewall posture summary --sarif --output posture.sarif
```

Upload directly to GitHub Security Code Scanning tab:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: posture.sarif
```
