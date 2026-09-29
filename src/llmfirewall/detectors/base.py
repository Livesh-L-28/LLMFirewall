"""Base protocol and abstract class for detectors."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from pydantic import ConfigDict

from llmfirewall.core.models import Finding
from llmfirewall.detectors.metadata import DetectorMetadata


class Detector(ABC):
    """Abstract Base Class for all detectors in LLMFirewall.
    
    CRITICAL ARCHITECTURAL RULE:
    Detectors ONLY detect and return Findings.
    They MUST NOT:
    1. Decide ALLOW/BLOCK actions (Policy Engine decides).
    2. Compute overall risk scores (Risk Engine scores).
    3. Modify application behavior or raise policy errors.
    4. Log raw sensitive payload text directly to unredacted sinks.
    """

    @property
    @abstractmethod
    def metadata(self) -> DetectorMetadata:
        """Declarative metadata describing this detector."""
        pass

    @property
    def name(self) -> str:
        """Convenience property mapping to metadata.name."""
        return self.metadata.name

    @abstractmethod
    def detect(self, text: str, context: Optional[Dict[str, Any]] = None) -> List[Finding]:
        """Inspect text content and emit findings.
        
        Args:
            text: The raw prompt or generated text to inspect.
            context: Optional contextual parameters (user_id, session_id, direction, etc.).
            
        Returns:
            List[Finding]: Emitted findings, or an empty list if clean.
        """
        pass
