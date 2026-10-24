"""Phase 61 — Tool-Result Trust Analysis and Indirect Prompt Injection Defense.

Performs deep security inspection on returned ToolResult payloads, detecting indirect
prompt injection, canary token leakage, and unsafe script execution payloads before
feeding tool results back into the agent or language model context.
"""

from typing import Any, Dict, List, Optional, Set
import uuid

from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.models import Action, Finding, Severity, ThreatType
from llmfirewall.tools.models import ResultTrustLevel, ToolResult


class ToolResultSecurityAssessment(BaseModel):
    """Structured security evaluation of a ToolResult before return to LLM context."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    assessment_id: str = Field(default_factory=lambda: f"tra-{uuid.uuid4().hex[:8]}")
    tool_name: str
    is_safe: bool = Field(default=True, description="True if no security violations were detected")
    action: Action = Field(default=Action.ALLOW, description="Enforced policy action")
    effective_trust_level: ResultTrustLevel = Field(default=ResultTrustLevel.UNTRUSTED)
    findings: List[Finding] = Field(default_factory=list, description="Security findings detected in output")
    canary_leakage_detected: bool = Field(default=False, description="True if canary tokens leaked into tool output")
    indirect_injection_detected: bool = Field(default=False, description="True if prompt injection was detected in payload")
    sanitized_output: Optional[str] = Field(default=None, description="Safe sanitized text if redaction was performed")
    reason: str = Field(default="Tool result passed all security checks.")


class ToolResultTrustAnalyzer:
    """Inspects ToolResult content for indirect injection, canary leakage, and untrusted payloads."""

    def __init__(
        self,
        canary_tokens: Optional[Set[str]] = None,
        injection_detector: Optional[Any] = None,
        max_scan_length: int = 500_000,
    ) -> None:
        self.canary_tokens: Set[str] = set(canary_tokens or [])
        if injection_detector is None:
            from llmfirewall.detectors.prompt_injection import PromptInjectionDetector
            self.injection_detector = PromptInjectionDetector()
        else:
            self.injection_detector = injection_detector
        self.max_scan_length = max_scan_length

    def register_canary_token(self, token: str) -> None:
        """Register an internal canary token to track data exfiltration."""
        if token and len(token) >= 6:
            self.canary_tokens.add(token)

    def analyze_result(
        self,
        result: ToolResult,
        declared_trust: Optional[ResultTrustLevel] = None,
    ) -> ToolResultSecurityAssessment:
        """Evaluate security, trust level, and indirect injection risks in a ToolResult."""
        raw_text = str(result.output or result.data or "")
        truncated_text = raw_text[: self.max_scan_length]

        findings: List[Finding] = []
        canary_detected = False
        indirect_inj_detected = False

        # 1. Canary Token Leakage Inspection
        for canary in self.canary_tokens:
            if canary in raw_text:
                canary_detected = True
                findings.append(
                    Finding(
                        detector_name="tool_result_trust_analyzer",
                        threat_type=ThreatType.SECRET,
                        severity=Severity.CRITICAL,
                        confidence=1.0,
                        description=f"Canary token '{canary[:3]}***' detected in output of tool '{result.tool_name}'. Exfiltration attempt blocked.",
                        matched_text=canary,
                    )
                )

        # 2. Indirect Prompt Injection Inspection
        if len(truncated_text) > 10:
            inj_findings = self.injection_detector.detect(
                truncated_text,
                context={"direction": "output", "source_type": "tool_result", "tool_name": result.tool_name},
            )
            if inj_findings:
                indirect_inj_detected = True
                findings.extend(inj_findings)

        # 3. Determine Trust Level and Policy Action
        is_safe = (len(findings) == 0) and not canary_detected and not indirect_inj_detected
        effective_trust = declared_trust or result.trust_level

        if not is_safe:
            effective_trust = ResultTrustLevel.UNTRUSTED
            action = Action.BLOCK
            reason = f"Security violation detected in tool '{result.tool_name}' output: {findings[0].description}"
        else:
            action = Action.ALLOW
            reason = f"Tool '{result.tool_name}' output verified safe."

        return ToolResultSecurityAssessment(
            tool_name=result.tool_name,
            is_safe=is_safe,
            action=action,
            effective_trust_level=effective_trust,
            findings=findings,
            canary_leakage_detected=canary_detected,
            indirect_injection_detected=indirect_inj_detected,
            sanitized_output=None if is_safe else "[TOOL_RESULT_BLOCKED_BY_SECURITY_POLICY]",
            reason=reason,
        )
