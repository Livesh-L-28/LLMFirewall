"""Runtime Protection and Policy Enforcement Engine for Phase 39."""

from __future__ import annotations

from datetime import datetime, timezone
import fnmatch
import json
import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
import uuid

from llmfirewall.core.exceptions import LLMFirewallError
from llmfirewall.policy.redactor import default_redactor
from llmfirewall.protection.models import (
    FailBehavior,
    PolicyDecision,
    PolicyMode,
    ProtectionAuditEntry,
    RuntimeDecision,
    RuntimeRequest,
)
from llmfirewall.protection.policy import (
    ProtectionPolicy,
    ProtectionRule,
    get_default_production_policy,
)
from llmfirewall.protection.rate_limiter import RateLimiter

logger = logging.getLogger("llmfirewall.protection")

# Standard prompt injection & jailbreak indicator patterns
PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior)\s+instructions",
    r"disregard\s+(all\s+)?(previous\s+|prior\s+)?directions",
    r"system\s*override",
    r"you\s+are\s+now\s+(DAN|unrestricted|in\s+developer\s+mode)",
    r"\b(in\s+)?developer\s+mode\b",
    r"bypass\s+(safety|content)\s+filters",
    r"reveal\s+(all\s+)?(system\s+prompt|secrets)",
    r"dump\s+(your\s+)?(complete\s+)?system\s+prompt",
    r"ignore\s+safety\s+guidelines",
    r"drop\s+table\s+",
    r"exec\(\s*['\"]",
]

SECRET_PATTERNS = [
    r"(?i)api[_-]?key\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{16,}['\"]?",
    r"(?i)sk-[a-zA-Z0-9]{20,}",
    r"(?i)ghp_[a-zA-Z0-9]{30,}",
    r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}",
    r"(?i)password\s*[:=]\s*['\"]?[^\s'\"]{6,}['\"]?",
]

PII_PATTERNS = [
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b",  # Email
    r"\b\d{3}-\d{2}-\d{4}\b",                                    # SSN
    r"\b(?:\d{4}-){3}\d{4}\b|\b\d{16}\b",                        # Credit Card
]


class RuntimeProtectionEngine:
    """Core real-time defense and policy enforcement engine.
    
    Inspects user inputs, tool invocations, model outputs, RAG context chunks,
    and memory items against declarative policies with sub-millisecond overhead.
    """

    def __init__(
        self,
        policy: Optional[ProtectionPolicy] = None,
        mode: PolicyMode = PolicyMode.ENFORCE,
        fail_behavior: FailBehavior = FailBehavior.FAIL_CLOSED,
        incident_manager: Optional[Any] = None,
    ) -> None:
        self.policy: ProtectionPolicy = policy or get_default_production_policy()
        self.mode: PolicyMode = mode
        self.fail_behavior: FailBehavior = fail_behavior
        self.incident_manager = incident_manager
        self.rate_limiter = RateLimiter()
        
        # Audit log storage (capped in memory)
        self._audit_log: List[ProtectionAuditEntry] = []
        self._total_inspections: int = 0
        self._total_latency_ms: float = 0.0

    # -------------------------------------------------------------------------
    # Public Unified Inspect API
    # -------------------------------------------------------------------------

    def inspect(self, request: RuntimeRequest) -> RuntimeDecision:
        """Inspects an incoming RuntimeRequest and produces a deterministic RuntimeDecision."""
        start_t = time.perf_counter()
        self._total_inspections += 1

        if self.mode == PolicyMode.DISABLED:
            duration = (time.perf_counter() - start_t) * 1000.0
            self._total_latency_ms += duration
            return RuntimeDecision(
                decision=PolicyDecision.ALLOW,
                effective_decision=PolicyDecision.ALLOW,
                reason="Runtime protection is DISABLED.",
                latency_ms=duration,
                mode=self.mode,
                request_id=request.request_id,
            )

        try:
            decision, reason, matched, risk_factors, evidence, redacted_content = self._evaluate_request(request)
        except Exception as exc:
            logger.error(f"Unexpected error in runtime protection inspection: {exc}", exc_info=True)
            duration = (time.perf_counter() - start_t) * 1000.0
            return self._handle_failure(request, exc, duration)

        duration = (time.perf_counter() - start_t) * 1000.0
        self._total_latency_ms += duration

        # Apply PolicyMode
        effective = decision
        if self.mode == PolicyMode.SHADOW:
            effective = PolicyDecision.ALLOW

        rt_decision = RuntimeDecision(
            decision=decision,
            effective_decision=effective,
            reason=reason,
            matched_policies=matched,
            risk_factors=risk_factors,
            evidence=evidence,
            latency_ms=round(duration, 3),
            redacted_content=redacted_content,
            mode=self.mode,
            request_id=request.request_id,
        )

        # Audit logging (no raw sensitive payload logged)
        self._record_audit(request, rt_decision)

        # Incident pipeline dispatch if an active attack or critical violation is detected
        if decision in (PolicyDecision.BLOCK, PolicyDecision.REVIEW) and self.incident_manager:
            self._dispatch_incident_event(request, rt_decision)

        return rt_decision

    # -------------------------------------------------------------------------
    # Core Pipeline Evaluation
    # -------------------------------------------------------------------------

    def _evaluate_request(
        self,
        request: RuntimeRequest,
    ) -> Tuple[PolicyDecision, str, List[str], List[str], List[Dict[str, Any]], Optional[str]]:
        matched: List[str] = []
        risk_factors: List[str] = []
        evidence: List[Dict[str, Any]] = []
        redacted_content: Optional[str] = None

        # 1. Rate Limiting Check
        if self.policy.rate_limits:
            for rl in self.policy.rate_limits:
                if rl.enabled:
                    val = self._extract_rate_limit_key(request, rl.key_by)
                    if val:
                        allowed, count, retry_after = self.rate_limiter.check_rate_limit(
                            rl.key_by, val, rl.max_requests, rl.window_seconds
                        )
                        if not allowed:
                            risk_factors.append("RATE_LIMIT_EXCEEDED")
                            evidence.append({"rate_limit_key": rl.key_by, "limit": rl.max_requests, "count": count})
                            return (
                                PolicyDecision.RATE_LIMIT,
                                f"Rate limit exceeded for {rl.key_by}. Retry after {retry_after:.1f}s.",
                                ["rate-limiting"],
                                risk_factors,
                                evidence,
                                None,
                            )

        # 2. Input Security (Oversized, Injection, Secrets)
        if request.input and self.policy.inspect_input:
            # Oversized check
            if len(request.input) > self.policy.max_input_length:
                risk_factors.append("OVERSIZED_INPUT")
                return (
                    PolicyDecision.BLOCK,
                    f"Input length ({len(request.input)}) exceeds maximum permitted limit ({self.policy.max_input_length}).",
                    ["input-length-policy"],
                    risk_factors,
                    [{"length": len(request.input), "limit": self.policy.max_input_length}],
                    None,
                )

            # Prompt injection & jailbreak check
            for pat in PROMPT_INJECTION_PATTERNS:
                if re.search(pat, request.input, re.IGNORECASE):
                    risk_factors.append("PROMPT_INJECTION_DETECTED")
                    evidence.append({"pattern_matched": pat})
                    return (
                        PolicyDecision.BLOCK,
                        "Input contains prompt injection or adversarial jailbreak pattern.",
                        ["anti-prompt-injection"],
                        risk_factors,
                        evidence,
                        None,
                    )

            # Secret submission check
            for pat in SECRET_PATTERNS:
                if re.search(pat, request.input):
                    risk_factors.append("SECRET_SUBMISSION")
                    evidence.append({"indicator": "credential_pattern_in_input"})
                    return (
                        PolicyDecision.BLOCK,
                        "Submission of raw credentials or API keys is prohibited.",
                        ["block-secrets"],
                        risk_factors,
                        evidence,
                        None,
                    )

        # 3. Tool Protection & Authorization Check
        if request.tool and self.policy.inspect_tools:
            tool_name = request.tool.get("name") or request.tool.get("tool_name", "")
            action = request.tool.get("action", "")
            
            # Check against declarative rules
            for rule in self.policy.rules:
                if rule.enabled and rule.when.tool:
                    patterns = [rule.when.tool] if isinstance(rule.when.tool, str) else rule.when.tool
                    for pat in patterns:
                        if fnmatch.fnmatch(tool_name.lower(), pat.lower()) or (action and fnmatch.fnmatch(action.lower(), pat.lower())):
                            matched.append(rule.name)
                            risk_factors.append("PRIVILEGED_TOOL_INVOCATION")
                            evidence.append({"tool": tool_name, "rule": rule.name})
                            return (
                                rule.action,
                                rule.reason or f"Tool '{tool_name}' matched policy rule '{rule.name}'.",
                                matched,
                                risk_factors,
                                evidence,
                                None,
                            )

            # Check tool arguments for dangerous sequences (e.g. path traversal)
            args_payload = request.tool.get("arguments") or request.tool.get("args") or {}
            args_str = json.dumps(args_payload) if isinstance(args_payload, (dict, list)) else str(args_payload)
            if "../" in args_str or "..\\" in args_str:
                risk_factors.append("PATH_TRAVERSAL_ATTEMPT")
                evidence.append({"tool": tool_name, "argument_violation": "path_traversal"})
                return (
                    PolicyDecision.BLOCK,
                    f"Tool '{tool_name}' parameters contain prohibited path traversal sequence.",
                    ["path-traversal-guard"],
                    risk_factors,
                    evidence,
                    None,
                )

        # 4. RAG Protection
        if request.rag_context and self.policy.inspect_rag:
            for i, chunk in enumerate(request.rag_context):
                content = chunk if isinstance(chunk, str) else (chunk.get("content") or chunk.get("text", ""))
                source = chunk.get("source", "unspecified") if isinstance(chunk, dict) else "unspecified"
                # Check for document poisoning / malicious instructions in chunk
                for pat in PROMPT_INJECTION_PATTERNS:
                    if re.search(pat, content, re.IGNORECASE):
                        risk_factors.append("RAG_POISONING_ATTEMPT")
                        evidence.append({"chunk_index": i, "source": source, "indicator": "adversarial_instruction"})
                        return (
                            PolicyDecision.BLOCK,
                            f"Retrieved RAG document chunk from '{source}' contains malicious prompt instructions.",
                            ["rag-poisoning-protection"],
                            risk_factors,
                            evidence,
                            None,
                        )

        # 5. Memory Candidate Protection
        if request.memory_item and self.policy.inspect_memory:
            mem_content = request.memory_item if isinstance(request.memory_item, str) else (request.memory_item.get("content") or request.memory_item.get("text", ""))
            # Check memory injection
            for pat in PROMPT_INJECTION_PATTERNS:
                if re.search(pat, mem_content, re.IGNORECASE):
                    risk_factors.append("MEMORY_POISONING_ATTEMPT")
                    return (
                        PolicyDecision.BLOCK,
                        "Memory item contains adversarial prompt override attempt.",
                        ["memory-poisoning-protection"],
                        risk_factors,
                        [{"memory_key": request.memory_item.get("key", "default") if isinstance(request.memory_item, dict) else "default"}],
                        None,
                    )
            # Check memory secrets
            for pat in SECRET_PATTERNS:
                if re.search(pat, mem_content):
                    risk_factors.append("SECRET_IN_MEMORY")
                    return (
                        PolicyDecision.BLOCK,
                        "Memory storage rejected: contains raw credentials or secret patterns.",
                        ["block-secrets"],
                        risk_factors,
                        [{"memory_key": request.memory_item.get("key", "default")}],
                        None,
                    )

        # 6. Output Security (Secrets & Sensitive PII Redaction)
        if request.output and self.policy.inspect_output:
            out_text = request.output

            # Check raw secret leakage -> BLOCK
            for pat in SECRET_PATTERNS:
                if re.search(pat, out_text):
                    risk_factors.append("SECRET_LEAKAGE_IN_OUTPUT")
                    return (
                        PolicyDecision.BLOCK,
                        "Model output blocked: raw API keys or credentials detected.",
                        ["block-secrets"],
                        risk_factors,
                        [{"threat": "credential_leakage"}],
                        None,
                    )

            # Check PII for redaction
            needs_redact = False
            for pat in PII_PATTERNS:
                if re.search(pat, out_text):
                    needs_redact = True
                    out_text = re.sub(pat, "[REDACTED_PII]", out_text)

            if needs_redact:
                risk_factors.append("PII_IN_OUTPUT")
                redacted_content = out_text
                return (
                    PolicyDecision.REDACT,
                    "Sensitive PII detected and redacted from model output.",
                    ["redact-sensitive-output"],
                    risk_factors,
                    [{"action": "redact"}],
                    redacted_content,
                )

        # Passed all checks
        return PolicyDecision.ALLOW, "Request complies with all active security policies.", [], [], [], None

    def _extract_rate_limit_key(self, request: RuntimeRequest, key_by: str) -> Optional[str]:
        """Extracts the appropriate identifier for rate limiting."""
        if key_by == "user":
            return request.user_context.get("user_id") or request.user_context.get("user")
        elif key_by == "session":
            return request.session_id
        elif key_by == "agent":
            return request.agent_id
        elif key_by == "tool":
            return (request.tool or {}).get("name")
        elif key_by in ("ip", "client_ip"):
            return request.user_context.get("ip") or request.metadata.get("ip")
        elif key_by == "api_key":
            return request.user_context.get("api_key") or request.metadata.get("api_key")
        return None

    def _handle_failure(self, request: RuntimeRequest, exc: Exception, duration: float) -> RuntimeDecision:
        """Handles unexpected inspection exceptions according to the configured FailBehavior."""
        if self.fail_behavior == FailBehavior.FAIL_OPEN:
            return RuntimeDecision(
                decision=PolicyDecision.ALLOW,
                effective_decision=PolicyDecision.ALLOW,
                reason=f"Inspection failed with error; FAIL_OPEN policy applied: {exc}",
                risk_factors=["INSPECTION_FAILURE_OPEN"],
                latency_ms=round(duration, 3),
                mode=self.mode,
                request_id=request.request_id,
            )
        elif self.fail_behavior == FailBehavior.FAIL_REVIEW:
            return RuntimeDecision(
                decision=PolicyDecision.REVIEW,
                effective_decision=PolicyDecision.REVIEW,
                reason=f"Inspection failed with error; routed to review: {exc}",
                risk_factors=["INSPECTION_FAILURE_REVIEW"],
                latency_ms=round(duration, 3),
                mode=self.mode,
                request_id=request.request_id,
            )
        else:  # FAIL_CLOSED
            return RuntimeDecision(
                decision=PolicyDecision.BLOCK,
                effective_decision=PolicyDecision.BLOCK,
                reason=f"Inspection failed with error; FAIL_CLOSED policy enforced: {exc}",
                risk_factors=["INSPECTION_FAILURE_CLOSED"],
                latency_ms=round(duration, 3),
                mode=self.mode,
                request_id=request.request_id,
            )

    def _record_audit(self, request: RuntimeRequest, decision: RuntimeDecision) -> None:
        """Appends a privacy-preserving audit entry."""
        entry = ProtectionAuditEntry(
            request_id=request.request_id,
            decision=decision.decision.value,
            effective_decision=decision.effective_decision.value,
            mode=self.mode.value,
            policy=self.policy.id,
            reason=decision.reason,
            agent=request.agent_id,
            tool=(request.tool or {}).get("name"),
            latency_ms=decision.latency_ms,
        )
        self._audit_log.append(entry)
        if len(self._audit_log) > 5000:
            self._audit_log = self._audit_log[-2500:]

    def _dispatch_incident_event(self, request: RuntimeRequest, decision: RuntimeDecision) -> None:
        """Dispatches a runtime security event directly to the IncidentManager if linked."""
        if not self.incident_manager:
            return
        try:
            ev_type = "RUNTIME_POLICY_BLOCK"
            if "PROMPT_INJECTION_DETECTED" in decision.risk_factors:
                ev_type = "PROMPT_INJECTION_DETECTED"
            elif "PRIVILEGED_TOOL_INVOCATION" in decision.risk_factors:
                ev_type = "UNAUTHORIZED_TOOL_CALL"
            elif "SECRET_LEAKAGE_IN_OUTPUT" in decision.risk_factors or "SECRET_SUBMISSION" in decision.risk_factors:
                ev_type = "SECRET_EXPOSURE"
            elif "RAG_POISONING_ATTEMPT" in decision.risk_factors:
                ev_type = "RAG_POISONING_ATTEMPT"
            elif "MEMORY_POISONING_ATTEMPT" in decision.risk_factors:
                ev_type = "MEMORY_POISONING_ATTEMPT"
            elif "RATE_LIMIT_EXCEEDED" in decision.risk_factors:
                ev_type = "RATE_LIMIT_EXCEEDED"

            self.incident_manager.record_event(
                event_type=ev_type,
                source="llmfirewall.protection",
                asset_id=f"agent:{request.agent_id}" if request.agent_id else "runtime:gateway",
                agent_id=request.agent_id,
                tool_id=(request.tool or {}).get("name"),
                request_id=request.request_id,
                session_id=request.session_id,
                metadata={
                    "reason": decision.reason,
                    "matched_policies": decision.matched_policies,
                    "risk_factors": decision.risk_factors,
                },
                evidence=decision.evidence,
            )
        except Exception as e:
            logger.debug(f"Failed to dispatch incident from runtime protection: {e}")

    def get_audit_log(self) -> List[ProtectionAuditEntry]:
        """Returns recorded protection audit logs."""
        return list(self._audit_log)

    def get_performance_stats(self) -> Dict[str, Any]:
        """Returns performance metrics: inspections count, avg latency, mode, etc."""
        avg_lat = (self._total_latency_ms / self._total_inspections) if self._total_inspections > 0 else 0.0
        return {
            "total_inspections": self._total_inspections,
            "average_latency_ms": round(avg_lat, 3),
            "total_latency_ms": round(self._total_latency_ms, 3),
            "active_mode": self.mode.value,
            "fail_behavior": self.fail_behavior.value,
            "policy_id": self.policy.id,
        }
