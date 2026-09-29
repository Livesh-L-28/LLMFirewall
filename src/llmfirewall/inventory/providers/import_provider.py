"""Import-driven AI Asset Discovery provider parsing structured external inventory files."""

import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional

from llmfirewall.inventory.models import (
    Asset,
    AssetProvenance,
    AssetSource,
    AssetStatus,
    AssetType,
    DiscoveryConfidence,
)
from llmfirewall.inventory.providers.base import DiscoveryProvider

MAX_IMPORT_BYTES = 10 * 1024 * 1024  # 10MB security boundary


class ImportDiscoveryProvider(DiscoveryProvider):
    """Imports assets from external inventory JSON or YAML files with strict security validation."""

    name: str = "import_discovery"
    source_type: AssetSource = AssetSource.USER_REGISTERED

    def __init__(
        self,
        file_path: Optional[str] = None,
        content: Optional[str] = None,
        format_type: str = "auto",
    ) -> None:
        self.file_path = Path(file_path) if file_path else None
        self.content = content
        self.format_type = format_type.lower()

    def discover(self) -> List[Asset]:
        raw_text = self.content
        ref_label = "in_memory_content"

        if self.file_path:
            ref_label = str(self.file_path)
            if not self.file_path.exists():
                raise FileNotFoundError(f"Inventory import file not found: {self.file_path}")

            size = self.file_path.stat().st_size
            if size > MAX_IMPORT_BYTES:
                raise ValueError(f"Inventory import file exceeds maximum size limit of {MAX_IMPORT_BYTES} bytes.")

            raw_text = self.file_path.read_text(encoding="utf-8")

        if not raw_text or not raw_text.strip():
            return []

        # Parse JSON or safe YAML
        data: Any = None
        if self.format_type == "json" or (self.format_type == "auto" and raw_text.strip().startswith("{")):
            data = json.loads(raw_text)
        else:
            try:
                import yaml
                data = yaml.safe_load(raw_text)
            except ImportError:
                data = json.loads(raw_text)

        if not isinstance(data, dict):
            raise ValueError("Imported inventory payload root must be a JSON/YAML dictionary/object.")

        raw_assets = data.get("assets", [])
        if not isinstance(raw_assets, list):
            raise ValueError("Imported inventory 'assets' field must be an array.")

        assets: List[Asset] = []
        now = time.time()

        for idx, a_raw in enumerate(raw_assets):
            if not isinstance(a_raw, dict):
                continue

            a_id = str(a_raw.get("id", "")).strip()
            a_type = str(a_raw.get("type", AssetType.CUSTOM.value)).strip().lower()
            a_name = str(a_raw.get("name", a_id)).strip()
            if not a_id:
                raise ValueError(f"Asset item at index {idx} missing required 'id' attribute.")

            prov = AssetProvenance(
                source=AssetSource.USER_REGISTERED,
                provider_name=self.name,
                reference=f"{ref_label}:assets[{idx}]",
                observed_at=now,
            )

            status_str = str(a_raw.get("status", "ACTIVE")).upper()
            try:
                status = AssetStatus(status_str)
            except ValueError:
                status = AssetStatus.ACTIVE

            asset = Asset.create(
                asset_id=a_id,
                asset_type=a_type,
                name=a_name,
                version=a_raw.get("version"),
                environment=a_raw.get("environment", "unknown"),
                source=AssetSource.USER_REGISTERED,
                status=status,
                metadata=a_raw.get("metadata", {}),
                tags=a_raw.get("tags", []),
                owner=a_raw.get("owner"),
                confidence=DiscoveryConfidence.HIGH,
                provenance=[prov],
            )
            assets.append(asset)

        return assets
