"""Base interfaces and protocols for detectors, risk engines, and policy engines."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from llmfirewall.core.models import Finding, PolicyDecision, RiskScore


class BaseDetector(ABC):
    """Abstract base class for all detectors.
    
    Detectors adhere strictly to: 'Detectors detect.'
    They analyze content and emit a list of Findings. They do not decide actions.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this detector."""
        pass

    @abstractmethod
    def detect(self, text: str, context: Optional[Dict[str, Any]] = None) -> List[Finding]:
        """Inspect text and return a list of findings."""
        pass


class BaseRiskEngine(ABC):
    """Abstract base class for risk scoring engines.
    
    Adheres to: 'Risk engine scores.'
    Aggregates findings into a quantified RiskScore.
    """

    @abstractmethod
    def evaluate(self, findings: List[Finding], context: Optional[Dict[str, Any]] = None) -> RiskScore:
        """Aggregate findings into an overall RiskScore."""
        pass


class BasePolicyEngine(ABC):
    """Abstract base class for policy evaluation engines.
    
    Adheres to: 'Policy engine decides.'
    Evaluates findings and risk scores against configured rules to yield a PolicyDecision.
    """

    @abstractmethod
    def decide(
        self,
        text: str,
        findings: List[Finding],
        risk_score: RiskScore,
        context: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """Determine what policy action to take (ALLOW, WARN, BLOCK, REDACT)."""
        pass
