"""Abstract base class for all AI Asset Discovery providers."""

from abc import ABC, abstractmethod
from typing import List

from llmfirewall.inventory.models import Asset, AssetSource


class DiscoveryProvider(ABC):
    """Abstract interface for extensible, fault-isolated AI asset discovery providers."""

    name: str = "base_provider"
    source_type: AssetSource = AssetSource.USER_REGISTERED

    @abstractmethod
    def discover(self) -> List[Asset]:
        """Perform non-destructive discovery and return normalized Asset instances.
        
        Must not raise uncaught exceptions; errors should be handled or isolated.
        Must not execute arbitrary code or collect secret values.
        """
        pass
