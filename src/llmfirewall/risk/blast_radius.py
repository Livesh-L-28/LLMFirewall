"""Blast Radius Estimation Engine for LLMFirewall v1.1.0 (Phase 50).

Quantifies potential downstream systemic impact, data exposure scope,
privilege escalation hazards, and containment requirements.
"""

from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.models import Finding, Severity, ThreatType


class BlastRadiusReport(BaseModel):
    """Quantified blast radius assessment explaining potential systemic impact."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    score: float = Field(default=0.0, ge=0.0, le=1.0, description="Normalized blast radius score [0.0, 1.0]")
    impact_level: Severity = Field(default=Severity.LOW, description="Categorized severity of systemic blast radius")
    reachable_systems: List[str] = Field(default_factory=list, description="Downstream services or assets reachable")
    exposed_data_types: List[str] = Field(default_factory=list, description="Data classifications at risk (e.g. 'PCI', 'PII')")
    privilege_elevation_risk: bool = Field(default=False, description="True if host/admin privilege elevation is possible")
    containment_steps: List[str] = Field(default_factory=list, description="Prescribed immediate containment actions")
    summary: str = Field(default="No elevated blast radius detected.", description="Human-readable assessment summary")


class BlastRadiusEstimator:
    """Estimates systemic blast radius based on finding vectors, tool permissions, and asset context."""

    def estimate(
        self,
        findings: List[Finding],
        context: Optional[Dict[str, Any]] = None,
    ) -> BlastRadiusReport:
        if not findings:
            return BlastRadiusReport()

        ctx = context or {}
        reachable_systems: Set[str] = set()
        exposed_data: Set[str] = set()
        privilege_risk = False
        containment: List[str] = []

        # 1. Inspect execution context
        env = str(ctx.get("environment", "production")).lower()
        user_role = str(ctx.get("user_role", "user")).lower()
        tool_name = str(ctx.get("tool_name", "")).lower()
        asset_id = str(ctx.get("asset_id", "default-llm-service"))

        reachable_systems.add(asset_id)
        if "tools" in ctx and isinstance(ctx["tools"], list):
            for t in ctx["tools"]:
                reachable_systems.add(f"tool:{t}")
        if tool_name:
            reachable_systems.add(f"tool:{tool_name}")

        # 2. Inspect findings & vectors
        has_critical = any(f.severity == Severity.CRITICAL for f in findings)
        has_secret = any(f.threat_type == ThreatType.SECRET for f in findings)
        has_pii = any(f.threat_type == ThreatType.PII for f in findings)
        has_injection = any(f.threat_type in (ThreatType.PROMPT_INJECTION, ThreatType.JAILBREAK) for f in findings)

        if has_secret:
            exposed_data.add("API_KEYS_AND_CREDENTIALS")
            containment.append("Revoke and rotate exposed credentials immediately.")
        if has_pii:
            exposed_data.add("USER_PII")
            containment.append("Mask output and audit data exposure log under privacy regulations.")

        # 3. Privilege Elevation & Systemic Danger
        if user_role in {"admin", "root", "system"} or "admin" in asset_id:
            privilege_risk = True
            reachable_systems.add("core-management-plane")
            containment.append("Isolate administrative session and enforce re-authentication.")

        dangerous_tools = {"bash", "exec", "sh", "eval", "system", "sql", "db_query"}
        if any(dt in tool_name for dt in dangerous_tools) or any(dt in s for s in reachable_systems for dt in dangerous_tools):
            privilege_risk = True
            reachable_systems.add("underlying-host-os")
            containment.append("Block host command execution and quarantine runner container.")

        # 4. Blast Radius Score Computation
        base_score = 0.20
        if has_critical:
            base_score += 0.35
        elif any(f.severity == Severity.HIGH for f in findings):
            base_score += 0.20

        if env == "production":
            base_score += 0.15
        elif env == "staging":
            base_score += 0.05

        if privilege_risk:
            base_score += 0.25

        if len(exposed_data) >= 2:
            base_score += 0.15
        elif len(exposed_data) == 1:
            base_score += 0.10

        if has_injection and len(reachable_systems) > 2:
            base_score += 0.15

        final_score = round(min(1.0, max(0.0, base_score)), 4)

        # Map to Severity level
        if final_score >= 0.80:
            level = Severity.CRITICAL
        elif final_score >= 0.60:
            level = Severity.HIGH
        elif final_score >= 0.35:
            level = Severity.MEDIUM
        else:
            level = Severity.LOW

        summary = (
            f"Estimated blast radius: {final_score:.2f} ({level.value}). "
            f"Reachable systems: {len(reachable_systems)}. Exposed data categories: {len(exposed_data)}. "
            f"Privilege escalation risk: {privilege_risk}."
        )

        return BlastRadiusReport(
            score=final_score,
            impact_level=level,
            reachable_systems=sorted(list(reachable_systems)),
            exposed_data_types=sorted(list(exposed_data)),
            privilege_elevation_risk=privilege_risk,
            containment_steps=containment,
            summary=summary,
        )
