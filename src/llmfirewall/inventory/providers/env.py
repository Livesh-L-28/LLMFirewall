"""Environment-driven AI Asset Discovery provider."""

import os
import time
from typing import Dict, List, Optional

from llmfirewall.inventory.models import (
    Asset,
    AssetProvenance,
    AssetSource,
    AssetStatus,
    AssetType,
    DiscoveryConfidence,
)
from llmfirewall.inventory.providers.base import DiscoveryProvider


class EnvironmentDiscoveryProvider(DiscoveryProvider):
    """Safely identifies AI providers, endpoints, and models from environment variables without capturing secrets."""

    name: str = "environment_discovery"
    source_type: AssetSource = AssetSource.ENVIRONMENT

    def __init__(self, env_dict: Optional[Dict[str, str]] = None) -> None:
        self.env = env_dict if env_dict is not None else os.environ

    def discover(self) -> List[Asset]:
        assets: List[Asset] = []
        now = time.time()

        # Provider Key Signals: Name -> list of env var triggers
        provider_signals = {
            "openai": ["OPENAI_API_KEY", "OPENAI_API_BASE", "OPENAI_ORG_ID"],
            "anthropic": ["ANTHROPIC_API_KEY", "ANTHROPIC_API_BASE"],
            "cohere": ["COHERE_API_KEY"],
            "huggingface": ["HF_TOKEN", "HUGGINGFACE_API_KEY", "HF_HOME"],
            "aws_bedrock": ["AWS_BEDROCK_REGION", "BEDROCK_ENDPOINT"],
            "google_vertex": ["GEMINI_API_KEY", "GOOGLE_API_KEY", "VERTEX_PROJECT_ID"],
            "azure_openai": ["AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_KEY"],
            "ollama": ["OLLAMA_HOST", "OLLAMA_ORIGINS"],
        }

        for provider, triggers in provider_signals.items():
            matched_triggers = [t for t in triggers if t in self.env]
            if matched_triggers:
                p_prov = AssetProvenance(
                    source=AssetSource.ENVIRONMENT,
                    provider_name=self.name,
                    reference=f"env:{','.join(matched_triggers)}",
                    observed_at=now,
                    details={"matched_keys": matched_triggers},
                )
                assets.append(
                    Asset.create(
                        asset_id=f"provider:{provider}",
                        asset_type=AssetType.MODEL_PROVIDER.value,
                        name=f"Model Provider: {provider.capitalize()}",
                        source=AssetSource.ENVIRONMENT,
                        status=AssetStatus.ACTIVE,
                        metadata={
                            "configured": True,
                            "detection_method": "environment_variable_presence",
                        },
                        tags=["provider", "llm_backend", provider],
                        confidence=DiscoveryConfidence.HIGH,
                        provenance=[p_prov],
                    )
                )

        # Discovered Models from Environment
        model_vars = ["OPENAI_MODEL", "ANTHROPIC_MODEL", "LLM_MODEL", "MODEL_NAME", "OLLAMA_MODEL"]
        for m_var in model_vars:
            val = self.env.get(m_var)
            if val and val.strip():
                clean_val = val.strip()
                m_id = f"model:{clean_val.lower().replace('/', '_')}"
                assets.append(
                    Asset.create(
                        asset_id=m_id,
                        asset_type=AssetType.MODEL.value,
                        name=clean_val,
                        source=AssetSource.ENVIRONMENT,
                        status=AssetStatus.ACTIVE,
                        metadata={"configured_via": m_var},
                        tags=["model", "environment"],
                        confidence=DiscoveryConfidence.MEDIUM,
                        provenance=[
                            AssetProvenance(
                                source=AssetSource.ENVIRONMENT,
                                provider_name=self.name,
                                reference=f"env:{m_var}",
                                observed_at=now,
                            )
                        ],
                    )
                )

        return assets
