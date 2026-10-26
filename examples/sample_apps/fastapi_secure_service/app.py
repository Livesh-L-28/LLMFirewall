"""Isolated FastAPI sample application with LLMFirewall security guardrails."""

from typing import Any, Dict, List, Optional
from fastapi import FastAPI, Request
from pydantic import BaseModel

from llmfirewall import Action, Firewall
from llmfirewall.integrations.fastapi import FirewallMiddleware, get_scan_result

app = FastAPI(title="Isolated FastAPI LLMFirewall Sample Service")
firewall = Firewall()

# Attach middleware to intercept incoming requests before reaching route handlers
app.add_middleware(
    FirewallMiddleware,
    firewall=firewall,
    paths=["/chat"],
    exclude_paths=["/health"],
    blocked_status_code=403,
    fail_closed=True,
)


class LocalModelStub:
    """Deterministic local model stub replacing paid external LLM APIs."""

    def __init__(self) -> None:
        self.invocation_log: List[Dict[str, Any]] = []

    def generate(self, safe_prompt: str) -> str:
        self.invocation_log.append({"prompt": safe_prompt})
        return f"Deterministic completion for: {safe_prompt}"


model_stub = LocalModelStub()


class ChatRequest(BaseModel):
    prompt: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/chat")
async def chat_endpoint(payload: ChatRequest, request: Request):
    # Retrieve the scan result attached to request.state by the middleware
    scan_result = get_scan_result(request)

    # CRITICAL INVARIANT: If PII/secrets were redacted, use scan_result.processed_text
    safe_prompt = scan_result.processed_text if scan_result else payload.prompt

    # Execute deterministic local model stub
    model_response = model_stub.generate(safe_prompt)

    return {
        "response": model_response,
        "action": scan_result.action.value if scan_result else "allow",
        "prompt_received_by_model": safe_prompt,
    }
