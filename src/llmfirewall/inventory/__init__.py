"""Phase 34 — AI Asset Inventory & Discovery module for LLMFirewall."""

from llmfirewall.inventory.engine import (
    AssetInventory,
    DiscoveryEngine,
    InventoryMetrics,
    normalize_asset_id,
)
from llmfirewall.inventory.models import (
    Asset,
    AssetConflict,
    AssetExposure,
    AssetProvenance,
    AssetSource,
    AssetStatus,
    AssetType,
    DiscoveryConfidence,
    DiscoveryResult,
    DiscoveryStatus,
    InventoryDiff,
    InventorySnapshot,
    sanitize_metadata_secrets,
)
from llmfirewall.inventory.providers import (
    CodeDiscoveryProvider,
    ConfigDiscoveryProvider,
    DependencyDiscoveryProvider,
    DiscoveryProvider,
    EnvironmentDiscoveryProvider,
    ImportDiscoveryProvider,
    ManualDiscoveryProvider,
    RuntimeDiscoveryProvider,
)
from llmfirewall.inventory.reporting import (
    format_asset_show_human,
    format_discovery_result_human,
    format_discovery_result_json,
    format_inventory_diff_human,
    format_inventory_json,
    format_inventory_list_human,
)

__all__ = [
    # Engine
    "AssetInventory",
    "DiscoveryEngine",
    "InventoryMetrics",
    "normalize_asset_id",
    # Models & Enums
    "Asset",
    "AssetType",
    "AssetStatus",
    "AssetSource",
    "DiscoveryConfidence",
    "DiscoveryStatus",
    "AssetProvenance",
    "AssetConflict",
    "DiscoveryResult",
    "InventorySnapshot",
    "InventoryDiff",
    "AssetExposure",
    "sanitize_metadata_secrets",
    # Providers
    "DiscoveryProvider",
    "ConfigDiscoveryProvider",
    "EnvironmentDiscoveryProvider",
    "DependencyDiscoveryProvider",
    "CodeDiscoveryProvider",
    "ImportDiscoveryProvider",
    "RuntimeDiscoveryProvider",
    "ManualDiscoveryProvider",
    # Reporting
    "format_inventory_list_human",
    "format_asset_show_human",
    "format_discovery_result_human",
    "format_inventory_diff_human",
    "format_inventory_json",
    "format_discovery_result_json",
]
