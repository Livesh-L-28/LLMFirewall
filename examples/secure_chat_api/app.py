"""Secure LLM Chat API Example — Powered by LLMFirewall-Core and FastAPI.

Demonstrates:
- Pre-LLM prompt inspection (blocking prompt injection and jailbreaks)
- PII redaction and downstream safe propagation (The Redaction Invariant)
- Policy-as-Code presets (default vs strict vs privacy)
- Safe exception handling without leaking raw inputs
- Security audit event recording for SIEM/observability
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

from llmfirewall import Action, Firewall, Policy, ScanRequest, ScanResult
from llmfirewall.core.models import AuditEvent


class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=10000, description="User prompt to the model")
    user_id: Optional[str] = Field(default=None, description="Optional calling user ID")
    session_id: Optional[str] = Field(default=None, description="Optional conversation session ID")
    policy_preset: Optional[str] = Field(default="default", description="Security preset: 'default', 'strict', or 'privacy'")


class ChatResponse(BaseModel):
    response: str
    action_taken: str
    risk_score: float
    is_sanitized: bool
    request_id: str
    audit_id: Optional[str] = None


app = FastAPI(
    title="Secure LLM Chat API",
    description="Production-ready FastAPI application protected by LLMFirewall-Core guardrails.",
    version="1.0.0",
)

# Global Firewall orchestrator
firewall = Firewall()

# In-memory audit event store for demonstration
audit_records: List[Dict[str, Any]] = []


def mock_llm_inference(prompt: str) -> str:
    """Mock LLM provider generating responses without paid API credentials."""
    return f"Assistant response: I received your request ('{prompt}') and processed it safely."


@app.get("/health")
def health_check() -> Dict[str, str]:
    """Health check endpoint."""
    return {
        "status": "healthy",
        "firewall_version": "1.3.2",
    }


@app.post("/chat", response_model=ChatResponse)
def chat_endpoint(payload: ChatRequest) -> ChatResponse:
    """Secure conversational endpoint enforcing input guardrails before LLM generation."""
    # 1. Resolve active policy preset
    active_fw = firewall
    if payload.policy_preset and payload.policy_preset.lower() in ("strict", "privacy"):
        active_fw = Firewall(policy=payload.policy_preset.lower())

    # 2. Input Security Scan
    scan_res: ScanResult = active_fw.scan_prompt(
        payload.prompt,
        user_id=payload.user_id,
        session_id=payload.session_id,
    )

    # 3. Create Audit Record (Safe by default, raw text omitted)
    req = ScanRequest(
        text=payload.prompt,
        user_id=payload.user_id,
        session_id=payload.session_id,
    )
    audit_event = active_fw.create_audit_event(request=req, result=scan_res)
    audit_records.append(scan_res.safe_dict())

    # 4. Enforce Blocking Invariant
    if scan_res.is_blocked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "SecurityViolation",
                "message": f"Prompt blocked by security policy: {scan_res.reason}",
                "request_id": scan_res.request_id,
                "risk_score": scan_res.risk_score.score,
            },
        )

    # 5. Enforce Redaction Invariant:
    # When Action.REDACT, forward 'scan_res.processed_text', NEVER the raw prompt!
    downstream_prompt = scan_res.processed_text if scan_res.action == Action.REDACT else payload.prompt

    # 6. Call Downstream LLM
    llm_output = mock_llm_inference(downstream_prompt)

    return ChatResponse(
        response=llm_output,
        action_taken=scan_res.action.value,
        risk_score=scan_res.risk_score.score,
        is_sanitized=(scan_res.action == Action.REDACT),
        request_id=scan_res.request_id,
        audit_id=scan_res.id,
    )


@app.get("/audit/events")
def list_audit_events() -> List[Dict[str, Any]]:
    """Returns recorded security audit events."""
    return audit_records
