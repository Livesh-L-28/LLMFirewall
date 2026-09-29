"""FastAPI dependencies and response scanning helpers for LLMFirewall."""

from typing import Any, Callable, Dict, Optional
from fastapi import HTTPException, Request, Response

from llmfirewall.core.exceptions import BlockedOutputError
from llmfirewall.core.models import Action, ScanResult
from llmfirewall.firewall import Firewall


def get_scan_result(request: Request) -> Optional[ScanResult]:
    """FastAPI Dependency: Retrieve the ScanResult from request.state if available."""
    return getattr(request.state, "firewall_scan_result", None)


def get_firewall_request_id(request: Request) -> Optional[str]:
    """FastAPI Dependency: Retrieve the Firewall Request ID from request.state."""
    return getattr(request.state, "firewall_request_id", None)


def scan_response(
    generation: str,
    firewall: Optional[Firewall] = None,
    user_id: Optional[str] = None,
    session_id: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
    raise_on_block: bool = True,
) -> ScanResult:
    """Explicit helper to scan outgoing LLM output generations before returning to client.
    
    Args:
        generation: The generated text from LLM / RAG / Agent.
        firewall: Optional Firewall instance (defaults to Firewall()).
        user_id: Optional user identifier.
        session_id: Optional session identifier.
        context: Optional operational context.
        raise_on_block: If True, raises HTTPException(403) when action == BLOCK.
        
    Returns:
        ScanResult: Inspection outcome with safe processed_text.
        
    Raises:
        HTTPException: 403 Forbidden with safe message if blocked and raise_on_block=True.
    """
    fw = firewall or Firewall()
    result = fw.check_output(
        generation=generation,
        user_id=user_id,
        session_id=session_id,
        context=context,
    )
    if result.decision.action == Action.BLOCK and raise_on_block:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "output_blocked",
                "message": "Generated response rejected by security policy.",
                "request_id": result.request_id,
            },
        )
    return result


def firewall_dependency(
    firewall: Optional[Firewall] = None,
    field: Optional[str] = None,
) -> Callable[..., Any]:
    """FastAPI Dependency: Inspect an incoming prompt/field and return safe processed text.
    
    Usage:
        @app.post("/generate")
        async def generate(prompt: str = Depends(firewall_dependency(field="prompt"))):
            return {"response": prompt}
    """
    fw = firewall or Firewall()

    async def _dependency(request: Request) -> str:
        text_to_scan = ""
        try:
            body = await request.body()
            if request.headers.get("content-type", "").startswith("application/json") and body:
                import json
                data = json.loads(body.decode("utf-8"))
                if field and field in data:
                    text_to_scan = str(data[field])
                elif not field:
                    for k in ["prompt", "message", "query", "text"]:
                        if k in data:
                            text_to_scan = str(data[k])
                            break
            elif body:
                text_to_scan = body.decode("utf-8", errors="ignore")
        except Exception:
            pass

        if text_to_scan:
            res = fw.check_prompt(text_to_scan)
            if res.decision.action == Action.BLOCK:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "security_policy_violation",
                        "message": "Request rejected by security policy.",
                        "request_id": res.request_id,
                    },
                )
            return res.processed_text
        return ""

    return _dependency


def add_security_routes(
    app: Any,
    firewall: Optional[Firewall] = None,
    prefix: str = "/security",
    include_metrics: bool = True,
    include_health: bool = True,
) -> None:
    """Register optional non-sensitive security health and metrics routes on a FastAPI app."""
    fw = firewall or Firewall()
    from fastapi.responses import PlainTextResponse

    if include_health:
        @app.get(f"{prefix}/health")
        def security_health():
            return {
                "status": "healthy",
                "detectors": [d.name for d in fw.detector_engine.detectors],
                "version": "1.0",
            }

    if include_metrics:
        @app.get(f"{prefix}/metrics", response_class=PlainTextResponse)
        def security_metrics():
            from llmfirewall.observability import export_prometheus_metrics
            summ = fw.observe.summary()
            return export_prometheus_metrics(summ)

