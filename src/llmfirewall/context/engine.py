"""Context-Aware Decision Engine.

Phase 5: Context-Aware Security Decisions.
Orchestrates:
- Contract evaluation against verified application context.
- Safe risk score modulation with non-overridable bounds.
- Contextual rationale generation for DecisionTrace and safe_dict.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.models import Action, Finding, RiskScore
from llmfirewall.context.contract import ContextDecisionContract
from llmfirewall.context.models import VerifiedSecurityContext


class ContextDecisionEnrichment(BaseModel):
    """Result of contextual security evaluation augmenting a security decision."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    contextual_multiplier: float = Field(default=1.0, ge=0.0, le=3.0)
    elevated_findings: List[Finding] = Field(default_factory=list)
    forced_action: Optional[Action] = Field(default=None)
    applied_rules: List[str] = Field(default_factory=list)
    context_explanation: str = Field(default="")
    is_tainted: bool = Field(default=False)

    def safe_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class ContextAwareDecisionEngine:
    """Evaluates verified application context and applies deterministic contracts."""

    def __init__(self) -> None:
        self.contract = ContextDecisionContract()

    def evaluate(
        self,
        findings: List[Finding],
        risk_score: RiskScore,
        context: Optional[VerifiedSecurityContext] = None,
        tool_name: Optional[str] = None,
    ) -> ContextDecisionEnrichment:
        """Evaluate verified context and determine risk modulation or forced actions."""
        mult, elevated, forced, rules = self.contract.evaluate_contract(
            findings=findings,
            risk_score=risk_score,
            context=context,
            tool_name=tool_name,
        )

        is_tainted = False
        if context is not None:
            is_tainted = bool(context.has_prior_injection or (context.workflow_threat_state and context.workflow_threat_state.value in ("tainted", "critical")))

        # Construct safe diagnostic explanation
        reasons = []
        if mult > 1.0:
            reasons.append(f"Risk score adjusted by {mult:.2f}x due to context signals ({', '.join(rules)})")
        elif mult < 1.0:
            reasons.append(f"Risk score attenuated by {mult:.2f}x due to verified trusted origin ({', '.join(rules)})")
        if forced:
            reasons.append(f"Action '{forced.value.upper()}' mandated by context rule")

        explanation = "; ".join(reasons) if reasons else "Context evaluated with neutral multiplier."

        return ContextDecisionEnrichment(
            contextual_multiplier=mult,
            elevated_findings=elevated,
            forced_action=forced,
            applied_rules=rules,
            context_explanation=explanation,
            is_tainted=is_tainted,
        )
