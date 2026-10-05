"""Structural typing protocols and cost classifications for detectors."""

from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from llmfirewall.core.models import Finding
from llmfirewall.detectors.metadata import DetectorMetadata


class DetectorCost(str, Enum):
    """Relative computational cost category for detector execution planning."""
    CHEAP = "cheap"
    NORMAL = "normal"
    EXPENSIVE = "expensive"


@runtime_checkable
class DetectorProtocol(Protocol):
    """Structural protocol defining the contract for any detector.
    
    Allows third-party libraries and users to supply detector implementations
    without explicitly subclassing `BaseDetector` or `Detector`.
    """

    @property
    def name(self) -> str:
        """Unique identifier for this detector."""
        ...

    @property
    def metadata(self) -> DetectorMetadata:
        """Declarative metadata describing this detector's identity and capabilities."""
        ...

    def detect(self, text: str, context: Optional[Dict[str, Any]] = None) -> List[Finding]:
        """Inspect text content and emit findings."""
        ...
