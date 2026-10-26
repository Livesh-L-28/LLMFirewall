"""Isolated Pure ASGI 3.0 sample application with LLMFirewall."""

import json
from typing import Any, Dict, List
from llmfirewall import Firewall
from llmfirewall.integrations import LLMFirewallASGIMiddleware


class LocalModelStub:
    """Deterministic local model stub."""

    def __init__(self) -> None:
        self.invocation_log: List[Dict[str, Any]] = []

    def generate(self, safe_prompt: str) -> str:
        self.invocation_log.append({"prompt": safe_prompt})
        return f"ASGI Stub output for: {safe_prompt}"


model_stub = LocalModelStub()


async def base_app(scope, receive, send):
    """Base ASGI application."""
    if scope["type"] == "http":
        body = b""
        more_body = True
        while more_body:
            msg = await receive()
            body += msg.get("body", b"")
            more_body = msg.get("more_body", False)

        data = json.loads(body.decode("utf-8") or "{}")
        prompt = data.get("prompt", "")

        model_output = model_stub.generate(prompt)

        response_body = json.dumps({
            "response": model_output,
            "received_prompt": prompt,
        }).encode("utf-8")

        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(response_body)).encode("utf-8")),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": response_body,
            "more_body": False,
        })


firewall = Firewall()
app = LLMFirewallASGIMiddleware(
    base_app,
    firewall=firewall,
    exclude_paths={"/health", "/metrics"},
    inspect_request=True,
    inspect_response=True,
    fail_closed=True,
)
