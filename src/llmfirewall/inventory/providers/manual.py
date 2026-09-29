"""Manual AI Asset Discovery provider tracking explicitly registered assets."""

from typing import Dict, List

from llmfirewall.inventory.models import Asset, AssetSource
from llmfirewall.inventory.providers.base import DiscoveryProvider


class ManualDiscoveryProvider(DiscoveryProvider):
    """Tracks and returns user-registered assets."""

    name: str = "manual_registration"
    source_type: AssetSource = AssetSource.USER_REGISTERED

    def __init__(self) -> None:
        self._assets: Dict[str, Asset] = {}

    def register(self, asset: Asset) -> None:
        self._assets[asset.id] = asset

    def unregister(self, asset_id: str) -> bool:
        return self._assets.pop(asset_id, None) is not None

    def discover(self) -> List[Asset]:
        return list(self._assets.values())
