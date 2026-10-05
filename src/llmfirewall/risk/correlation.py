"""Deterministic Finding Correlation Engine for LLMFirewall v1.1.0 (Phase 50).

Analyzes atomic findings across threat vectors, context, and tool invocations
to detect multi-stage attack chains and calculate deterministic correlation multipliers.
"""

from enum import Enum
import math
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.models import Finding, Severity, ThreatType


class AttackChainType(str, Enum):
    """Standardized multi-stage attack chain taxonomy."""
    EXFILTRATION_CHAIN = "EXFILTRATION_CHAIN"
    REMOTE_EXECUTION_CHAIN = "REMOTE_EXECUTION_CHAIN"
    INDIRECT_RAG_POISONING = "INDIRECT_RAG_POISONING"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    MULTI_VECTOR_FLOOD = "MULTI_VECTOR_FLOOD"
    ADJACENT_SPANS_COLLUSION = "ADJACENT_SPANS_COLLUSION"


class CorrelatedAttackChain(BaseModel):
    """A detected multi-stage attack pattern composed of multiple findings."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    chain_type: AttackChainType = Field(..., description="Classification of the compound attack")
    name: str = Field(..., description="Human-friendly chain title")
    description: str = Field(..., description="Detailed explanation of the attack sequence")
    severity: Severity = Field(..., description="Aggregated severity of the chain")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in the compound detection")
    involved_finding_ids: List[str] = Field(default_factory=list, description="IDs of findings forming this chain")
    multiplier: float = Field(default=1.25, ge=1.0, le=2.0, description="Risk multiplier applied due to correlation")
    mitigation: str = Field(default="", description="Recommended defense or isolation step")


class CorrelationReport(BaseModel):
    """Structured report produced by the Finding Correlation Engine."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    is_compound_attack: bool = Field(default=False, description="True if any multi-stage chains were identified")
    chains: List[CorrelatedAttackChain] = Field(default_factory=list, description="All identified attack chains")
    correlation_multiplier: float = Field(default=1.0, ge=1.0, le=2.0, description="Composite correlation multiplier")
    highest_severity: Severity = Field(default=Severity.INFO, description="Peak severity among correlated chains")
    summary: str = Field(default="No compound attack patterns detected.", description="Summary of correlation analysis")


class FindingCorrelationEngine:
    """Evaluates atomic findings and execution context to detect compound attack chains."""

    def __init__(self, base_boost: float = 0.25) -> None:
        self.base_boost = base_boost

    def correlate(
        self,
        findings: List[Finding],
        context: Optional[Dict[str, Any]] = None,
    ) -> CorrelationReport:
        """Correlate atomic findings deterministically."""
        if not findings or len(findings) == 0:
            return CorrelationReport()

        ctx = context or {}
        chains: List[CorrelatedAttackChain] = []

        threat_types: Set[ThreatType] = {f.threat_type for f in findings}
        finding_by_type: Dict[ThreatType, List[Finding]] = {}
        for f in findings:
            finding_by_type.setdefault(f.threat_type, []).append(f)

        # 1. EXFILTRATION CHAIN: Injection/Jailbreak + Secret or PII
        has_injection = (
            ThreatType.PROMPT_INJECTION in threat_types
            or ThreatType.JAILBREAK in threat_types
        )
        has_sensitive_data = (
            ThreatType.SECRET in threat_types
            or ThreatType.PII in threat_types
        )
        if has_injection and has_sensitive_data:
            inj_findings = finding_by_type.get(ThreatType.PROMPT_INJECTION, []) + finding_by_type.get(ThreatType.JAILBREAK, [])
            sens_findings = finding_by_type.get(ThreatType.SECRET, []) + finding_by_type.get(ThreatType.PII, [])
            involved = [f.id for f in (inj_findings + sens_findings)]
            conf = min(1.0, max(f.confidence for f in inj_findings) * max(f.confidence for f in sens_findings) * 1.1)

            chains.append(
                CorrelatedAttackChain(
                    chain_type=AttackChainType.EXFILTRATION_CHAIN,
                    name="Injection-Assisted Data Exfiltration",
                    description="Simultaneous occurrence of prompt injection/jailbreak alongside sensitive credentials or PII disclosure.",
                    severity=Severity.CRITICAL,
                    confidence=round(conf, 4),
                    involved_finding_ids=involved,
                    multiplier=1.35,
                    mitigation="Immediately isolate session, mask credentials, and terminate LLM agent execution.",
                )
            )

        # 2. REMOTE EXECUTION CHAIN: Injection + Tool Execution in Context
        requested_tool = str(ctx.get("tool_name", "")).lower()
        tool_args = str(ctx.get("tool_args", "")).lower()
        dangerous_keywords = {"bash", "exec", "sh", "eval", "system", "cmd", "python", "subprocess"}
        is_dangerous_tool = any(kw in requested_tool for kw in dangerous_keywords) or any(kw in tool_args for kw in dangerous_keywords)

        if has_injection and is_dangerous_tool:
            inj_findings = finding_by_type.get(ThreatType.PROMPT_INJECTION, []) + finding_by_type.get(ThreatType.JAILBREAK, [])
            chains.append(
                CorrelatedAttackChain(
                    chain_type=AttackChainType.REMOTE_EXECUTION_CHAIN,
                    name="Prompt Injection with Host Execution Tooling",
                    description=f"Prompt injection detected in concurrence with execution tool invocation '{requested_tool}'.",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    involved_finding_ids=[f.id for f in inj_findings],
                    multiplier=1.40,
                    mitigation="Enforce strict tool parameter sandboxing and deny OS-level command execution.",
                )
            )

        # 3. INDIRECT RAG POISONING: Source indicates untrusted context + Prompt Injection
        source = str(ctx.get("source", "")).lower()
        is_untrusted_rag = "rag" in source or "external" in source or "untrusted" in source or ctx.get("is_rag", False)
        if is_untrusted_rag and has_injection:
            inj_findings = finding_by_type.get(ThreatType.PROMPT_INJECTION, []) + finding_by_type.get(ThreatType.JAILBREAK, [])
            chains.append(
                CorrelatedAttackChain(
                    chain_type=AttackChainType.INDIRECT_RAG_POISONING,
                    name="Indirect RAG Document Poisoning",
                    description="Ingested retrieval context contains adversarial injection instructions aimed at overriding guardrails.",
                    severity=Severity.HIGH,
                    confidence=0.90,
                    involved_finding_ids=[f.id for f in inj_findings],
                    multiplier=1.25,
                    mitigation="Filter document chunk from retrieval context and quarantine vector index item.",
                )
            )

        # 4. PRIVILEGE ESCALATION: Role manipulation / Injection + Elevated User Role
        user_role = str(ctx.get("user_role", "")).lower()
        is_elevated_role = user_role in {"admin", "root", "system", "superuser"}
        if is_elevated_role and (has_injection or ThreatType.POLICY_VIOLATION in threat_types):
            relevant_findings = (
                finding_by_type.get(ThreatType.PROMPT_INJECTION, [])
                + finding_by_type.get(ThreatType.JAILBREAK, [])
                + finding_by_type.get(ThreatType.POLICY_VIOLATION, [])
            )
            chains.append(
                CorrelatedAttackChain(
                    chain_type=AttackChainType.PRIVILEGE_ESCALATION,
                    name="Privileged Session Exploitation",
                    description=f"Security violation attempted within high-privilege context (role: {user_role}).",
                    severity=Severity.CRITICAL,
                    confidence=0.88,
                    involved_finding_ids=[f.id for f in relevant_findings],
                    multiplier=1.30,
                    mitigation="Step down caller privilege token and enforce mandatory dual-authorization.",
                )
            )

        # 5. MULTI-VECTOR FLOOD: 3 or more distinct threat categories
        if len(threat_types) >= 3:
            all_ids = [f.id for f in findings]
            chains.append(
                CorrelatedAttackChain(
                    chain_type=AttackChainType.MULTI_VECTOR_FLOOD,
                    name="Compound Multi-Vector Attack",
                    description=f"High-density multi-vector attack spanning {len(threat_types)} distinct threat categories: {sorted([t.value for t in threat_types])}.",
                    severity=Severity.HIGH,
                    confidence=0.92,
                    involved_finding_ids=all_ids,
                    multiplier=1.20,
                    mitigation="Trigger circuit breaker and block whole request batch.",
                )
            )

        # 6. ADJACENT SPANS COLLUSION: Overlapping or proximate spans within 50 characters
        spanned_findings = [f for f in findings if f.start_pos is not None and f.end_pos is not None]
        if len(spanned_findings) >= 2:
            spanned_findings.sort(key=lambda x: x.start_pos or 0)
            colluding_ids: Set[str] = set()
            for i in range(len(spanned_findings) - 1):
                f1 = spanned_findings[i]
                f2 = spanned_findings[i + 1]
                # Distance between end of f1 and start of f2
                dist = (f2.start_pos or 0) - (f1.end_pos or 0)
                if dist <= 50 and f1.threat_type != f2.threat_type:
                    colluding_ids.add(f1.id)
                    colluding_ids.add(f2.id)

            if colluding_ids:
                chains.append(
                    CorrelatedAttackChain(
                        chain_type=AttackChainType.ADJACENT_SPANS_COLLUSION,
                        name="Co-Located Threat Collusion",
                        description="Distinct threat vectors detected in adjacent text spans (proximity <= 50 chars).",
                        severity=Severity.HIGH,
                        confidence=0.85,
                        involved_finding_ids=sorted(list(colluding_ids)),
                        multiplier=1.15,
                        mitigation="Deep scan surrounding lexical window and redact correlated segments.",
                    )
                )

        if not chains:
            return CorrelationReport()

        # Compute combined correlation multiplier (compounded with diminishing returns, capped at 1.75)
        highest_sev = max(c.severity for c in chains)
        # Sort multipliers descending
        sorted_multipliers = sorted([c.multiplier for c in chains], reverse=True)
        combined_mult = sorted_multipliers[0]
        for m in sorted_multipliers[1:]:
            combined_mult += (m - 1.0) * 0.4
        combined_mult = round(min(1.75, max(1.0, combined_mult)), 4)

        summary = (
            f"Detected {len(chains)} compound attack chain(s) across {len(findings)} findings. "
            f"Peak chain: '{chains[0].name}' ({chains[0].severity.value}). Correlation multiplier: {combined_mult}x."
        )

        return CorrelationReport(
            is_compound_attack=True,
            chains=chains,
            correlation_multiplier=combined_mult,
            highest_severity=highest_sev,
            summary=summary,
        )
