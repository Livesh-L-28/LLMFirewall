"""FastAPI integration example application demonstrating LLMFirewall."""

from fastapi import Depends, FastAPI, Request
from llmfirewall import Firewall
from llmfirewall.integrations.fastapi import (
    FirewallMiddleware,
    add_security_routes,
    firewall_dependency,
    get_firewall_request_id,
    get_scan_result,
)

app = FastAPI(title="LLMFirewall Protected Service")
firewall = Firewall()

# 1. Register ASGI Firewall Middleware
app.add_middleware(
    FirewallMiddleware,
    firewall=firewall,
    paths=["/api/v1/chat"],
    exclude_paths=["/security", "/docs"],
)

# 2. Add security health and prometheus metrics endpoints
add_security_routes(app, firewall=firewall, prefix="/security")

# 3. Endpoint protected by middleware
@app.post("/api/v1/chat")
async def chat_endpoint(request: Request, req_id=Depends(get_firewall_request_id)):
    data = await request.json()
    prompt = data.get("prompt", "")
    return {
        "response": f"AI Assistant answer to: {prompt}",
        "request_id": req_id,
    }

# 4. Alternative: Lightweight dependency injection
@app.post("/api/v1/generate")
async def generate_endpoint(safe_prompt: str = Depends(firewall_dependency(firewall=firewall, field="prompt"))):
    return {"generated": f"Summary of: {safe_prompt}"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
