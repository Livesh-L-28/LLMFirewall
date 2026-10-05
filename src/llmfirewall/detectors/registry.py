"""Registry for managing and discovering detectors."""

from typing import Dict, List, Optional, Type, Union
from llmfirewall.core.exceptions import ConfigurationError
from llmfirewall.detectors.base import Detector
from llmfirewall.detectors.protocols import DetectorProtocol


class DetectorRegistry:
    """Thread-safe registry for registering and instantiating detectors."""

    def __init__(self) -> None:
        self._detectors: Dict[str, Union[Detector, DetectorProtocol]] = {}

    def register(self, detector: Union[Detector, DetectorProtocol], override: bool = False) -> None:
        """Register a detector instance.
        
        Args:
            detector: Instance conforming to Detector ABC or DetectorProtocol.
            override: If True, replace existing detector with same name.
        """
        if not isinstance(detector, (Detector, DetectorProtocol)):
            raise ConfigurationError(
                f"Expected instance of Detector or DetectorProtocol, got {type(detector).__name__}"
            )
        name = detector.name
        if not name:
            raise ConfigurationError("Detector name cannot be empty.")
        if name in self._detectors and not override:
            raise ConfigurationError(
                f"Detector '{name}' is already registered. Set override=True to overwrite."
            )
        self._detectors[name] = detector

    def unregister(self, name: str) -> None:
        """Unregister a detector by name."""
        if name in self._detectors:
            del self._detectors[name]

    def get(self, name: str) -> Optional[Detector]:
        """Retrieve a registered detector by name."""
        return self._detectors.get(name)

    def get_all(self) -> List[Detector]:
        """Return all registered detectors."""
        return list(self._detectors.values())

    def clear(self) -> None:
        """Clear all registered detectors."""
        self._detectors.clear()

    def __contains__(self, name: str) -> bool:
        return name in self._detectors

    def __len__(self) -> int:
        return len(self._detectors)


# Global default registry instance
default_detector_registry = DetectorRegistry()
