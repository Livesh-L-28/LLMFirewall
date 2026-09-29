"""Complete example FastAPI application demonstrating LLMFirewall protection."""

from typing import Dict
from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel

from llmfirewall import (
    Action,
    AuditConfig,
    DetectorConfig,
    Firewall,
    FirewallConfig,
    PIIConfig,
    PolicyConfig,
    PromptInjectionConfig,
    RedactionConfig,
    SecretConfig,
)
from llmfirewall.integrations.fastapi import (
    FirewallMiddleware,
    get_firewall_request_id,
    get_scan_result,
    scan_response,
)

# 1. Initialize Strongly Typed Firewall Configuration
firewall_config = FirewallConfig(
    detectors=DetectorConfig(
        prompt_injection=PromptInjectionConfig(enabled=True),
        pii=PIIConfig(enabled=True, categories={"email", "phone", "ip", "payment"}),
        secrets=SecretConfig(enabled=True),
    ),
    redaction=RedactionConfig(
        category_tokens={"email": "[EMAIL_REDACTED]"},
        default_token="[REDACTED]",
    ),
    audit=AuditConfig(
        enabled=True,
        logger_name="example.app.audit",
        min_level="INFO",
    ),
)

firewall = Firewall(config=firewall_config)

# 2. Create FastAPI Application
app = FastAPI(
    title="Secure LLM Agent API",
    description="FastAPI service guarded by LLMFirewall.",
    version="1.0.0",
)

# 3. Attach FirewallMiddleware
app.add_middleware(
    FirewallMiddleware,
    firewall=firewall,
    paths=["/chat", "/summarize"],
    exclude_paths=["/health", "/docs", "/openapi.json"],
    max_inspection_bytes=100_000,
    blocked_status_code=403,
)


class ChatRequest(BaseModel):
    prompt: str


class ChatResponse(BaseModel):
    response: str
    request_id: str


# 4. Mock Local LLM Engine (Zero External Dependencies)
def mock_llm_inference(prompt: str) -> str:
    """Simulate model generation logic without third-party network calls."""
    if "leak key" in prompt.lower():
        # Malicious model output simulation
        return "System credential: api_key = 'api_key_sample_token_x9K2pZ8wR4mQ7vL1yT5j'"
    return f"Here is the helpful answer to: '{prompt}'."


# 5. Define Endpoints
@app.get("/health")
def health_check() -> Dict[str, str]:
    """Uninspected health-check endpoint."""
    return {"status": "ok"}


@app.post("/chat", response_model=ChatResponse)
async def chat_endpoint(
    req: ChatRequest,
    scan_result=Depends(get_scan_result),
    request_id=Depends(get_firewall_request_id),
) -> ChatResponse:
    """Protected chat endpoint:
    - Input: Scanned and redacted by FirewallMiddleware.
    - Inference: Mock LLM generates response.
    - Output: Explicitly scanned using scan_response helper.
    """
    # Middleware replaced any PII with redacted text before reaching here
    sanitized_prompt = req.prompt

    # Mock inference
    raw_generation = mock_llm_inference(sanitized_prompt)

    # Output scan: catches model hallucinating or leaking secrets/PII
    scanned_output = scan_response(
        generation=raw_generation,
        firewall=firewall,
        raise_on_block=True,
    )

    return ChatResponse(
        response=scanned_output.processed_text,
        request_id=request_id or "unknown",
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
