"""Dependency and Supply-Chain AI Asset Discovery provider."""

import importlib.metadata
import time
from typing import List, Optional, Set

from llmfirewall.inventory.models import (
    Asset,
    AssetProvenance,
    AssetSource,
    AssetStatus,
    AssetType,
    DiscoveryConfidence,
)
from llmfirewall.inventory.providers.base import DiscoveryProvider

# Recognized AI, ML, Data, and Security ecosystem package prefixes/names
KNOWN_AI_PACKAGES: Set[str] = {
    "openai", "anthropic", "cohere", "transformers", "torch", "tensorflow",
    "huggingface", "huggingface_hub", "langchain", "langchain_core",
    "langchain_community", "llama_index", "chromadb", "qdrant_client",
    "pinecone_client", "weaviate_client", "tiktoken", "fastapi", "uvicorn",
    "pydantic", "pydantic_core", "numpy", "pandas", "scipy", "scikit_learn",
    "llmfirewall", "vllm", "guidance", "guardrails_ai", "instructor",
}


class DependencyDiscoveryProvider(DiscoveryProvider):
    """Safely discovers installed AI packages and dependencies using offline importlib.metadata."""

    name: str = "dependency_discovery"
    source_type: AssetSource = AssetSource.DEPENDENCY_MANIFEST

    def __init__(
        self,
        ai_only: bool = True,
        custom_packages: Optional[List[str]] = None,
        max_packages: int = 1000,
    ) -> None:
        self.ai_only = ai_only
        self.max_packages = max_packages
        self.target_packages = set(KNOWN_AI_PACKAGES)
        if custom_packages:
            for p in custom_packages:
                self.target_packages.add(p.lower().replace("-", "_"))

    def discover(self) -> List[Asset]:
        assets: List[Asset] = []
        now = time.time()

        try:
            dists = list(importlib.metadata.distributions())[: self.max_packages]
        except Exception:
            return []

        for dist in dists:
            try:
                raw_name = dist.metadata.get("Name", dist.name if hasattr(dist, "name") else "unknown")
                pkg_name = str(raw_name).strip()
                norm_name = pkg_name.lower().replace("-", "_")
                version = dist.version or "0.0.0"

                if self.ai_only and norm_name not in self.target_packages:
                    # Check if summary mentions AI / LLM
                    summary = str(dist.metadata.get("Summary", "")).lower()
                    if not any(k in summary for k in ("llm", "large language model", "machine learning", "neural", "artificial intelligence")):
                        continue

                asset_id = f"package:{norm_name}:{version}"
                prov = AssetProvenance(
                    source=AssetSource.DEPENDENCY_MANIFEST,
                    provider_name=self.name,
                    reference="importlib.metadata",
                    observed_at=now,
                    details={"package_name": pkg_name, "version": version},
                )

                assets.append(
                    Asset.create(
                        asset_id=asset_id,
                        asset_type=AssetType.PACKAGE.value,
                        name=pkg_name,
                        version=version,
                        source=AssetSource.DEPENDENCY_MANIFEST,
                        status=AssetStatus.ACTIVE,
                        metadata={
                            "distribution": pkg_name,
                            "installed_version": version,
                        },
                        tags=["dependency", "package", "python"],
                        confidence=DiscoveryConfidence.HIGH,
                        provenance=[prov],
                    )
                )
            except Exception:
                continue

        return assets
