"""Configuration-driven AI Asset Discovery provider."""

from typing import Any, Dict, List, Optional
import time

from llmfirewall.inventory.models import (
    Asset,
    AssetProvenance,
    AssetSource,
    AssetStatus,
    AssetType,
    DiscoveryConfidence,
)
from llmfirewall.inventory.providers.base import DiscoveryProvider


class ConfigDiscoveryProvider(DiscoveryProvider):
    """Discovers AI assets declared in LLMFirewall configuration and runtime components."""

    name: str = "config_discovery"
    source_type: AssetSource = AssetSource.CONFIGURATION

    def __init__(
        self,
        config: Optional[Any] = None,
        firewall_instance: Optional[Any] = None,
        raw_config_dict: Optional[Dict[str, Any]] = None,
        firewall: Optional[Any] = None,
    ) -> None:
        self.config = config
        self.firewall = firewall if firewall is not None else firewall_instance
        self.raw_config = raw_config_dict or {}

    def discover(self) -> List[Asset]:
        assets: List[Asset] = []
        now = time.time()

        # 1. Discover Firewall Application itself
        prov_app = AssetProvenance(
            source=AssetSource.CONFIGURATION,
            provider_name=self.name,
            reference="llmfirewall.config",
            observed_at=now,
            details={"tier": "security_perimeter"},
        )
        assets.append(
            Asset.create(
                asset_id="application:firewall",
                asset_type=AssetType.APPLICATION.value,
                name="LLMFirewall Orchestrator",
                version="0.1.0",
                environment=getattr(self.config, "environment", "production"),
                source=AssetSource.CONFIGURATION,
                status=AssetStatus.ACTIVE,
                metadata={"fail_fast": getattr(self.config, "fail_fast", False)},
                tags=["security", "perimeter", "core"],
                confidence=DiscoveryConfidence.HIGH,
                provenance=[prov_app],
            )
        )

        # 2. Discover from Firewall instance if provided
        if self.firewall:
            # Policy Engine & Policy
            try:
                pol_cfg = getattr(self.firewall, "_policy_engine", None)
                if pol_cfg and hasattr(pol_cfg, "config"):
                    p_name = getattr(pol_cfg.config, "name", "default_policy")
                    p_ver = str(getattr(pol_cfg.config, "version", "1.0"))
                    p_prov = AssetProvenance(
                        source=AssetSource.CONFIGURATION,
                        provider_name=self.name,
                        reference="policy_engine.config",
                        observed_at=now,
                    )
                    assets.append(
                        Asset.create(
                            asset_id=f"policy:{p_name}",
                            asset_type=AssetType.POLICY.value,
                            name=f"Security Policy: {p_name}",
                            version=p_ver,
                            source=AssetSource.CONFIGURATION,
                            status=AssetStatus.ACTIVE,
                            metadata={"rules_count": len(getattr(pol_cfg.config, "rules", []))},
                            tags=["policy", "governance"],
                            confidence=DiscoveryConfidence.HIGH,
                            provenance=[p_prov],
                        )
                    )
            except Exception:
                pass

            # Detectors as Security Controls
            try:
                det_engine = getattr(self.firewall, "_detector_engine", None)
                if det_engine and hasattr(det_engine, "detectors"):
                    for det in det_engine.detectors:
                        d_name = getattr(det, "name", "unknown_detector")
                        c_prov = AssetProvenance(
                            source=AssetSource.CONFIGURATION,
                            provider_name=self.name,
                            reference=f"detector:{d_name}",
                            observed_at=now,
                        )
                        assets.append(
                            Asset.create(
                                asset_id=f"control:{d_name}",
                                asset_type=AssetType.SECURITY_CONTROL.value,
                                name=f"Security Control: {d_name}",
                                source=AssetSource.CONFIGURATION,
                                status=AssetStatus.ACTIVE,
                                metadata={
                                    "enabled": getattr(det, "enabled", True),
                                    "detector_class": det.__class__.__name__,
                                },
                                tags=["control", "guardrail", "detector"],
                                confidence=DiscoveryConfidence.HIGH,
                                provenance=[c_prov],
                            )
                        )
            except Exception:
                pass

            # Tools
            try:
                tool_reg = getattr(self.firewall, "tool_registry", None)
                if tool_reg and hasattr(tool_reg, "list_tools"):
                    for t in tool_reg.list_tools():
                        t_name = getattr(t, "name", "tool")
                        perm = str(getattr(t, "permission", "execute"))
                        t_prov = AssetProvenance(
                            source=AssetSource.CONFIGURATION,
                            provider_name=self.name,
                            reference=f"tool_registry:{t_name}",
                            observed_at=now,
                        )
                        assets.append(
                            Asset.create(
                                asset_id=f"tool:{t_name}",
                                asset_type=AssetType.TOOL.value,
                                name=f"Tool: {t_name}",
                                source=AssetSource.CONFIGURATION,
                                status=AssetStatus.ACTIVE,
                                metadata={"permission": perm},
                                tags=["tool", "action"],
                                confidence=DiscoveryConfidence.HIGH,
                                provenance=[t_prov],
                            )
                        )
            except Exception:
                pass

            # Capabilities
            try:
                cap_eng = getattr(self.firewall, "capability_engine", None)
                if cap_eng and hasattr(cap_eng, "registry"):
                    for cap in cap_eng.registry.get_all_capabilities():
                        c_name = getattr(cap, "name", "capability")
                        c_prov = AssetProvenance(
                            source=AssetSource.CONFIGURATION,
                            provider_name=self.name,
                            reference=f"capability_engine:{c_name}",
                            observed_at=now,
                        )
                        assets.append(
                            Asset.create(
                                asset_id=f"capability:{c_name}",
                                asset_type=AssetType.CAPABILITY.value,
                                name=f"Capability: {c_name}",
                                source=AssetSource.CONFIGURATION,
                                status=AssetStatus.ACTIVE,
                                metadata={
                                    "action": getattr(cap, "action", "read"),
                                    "resource_pattern": getattr(cap, "resource_pattern", "*"),
                                },
                                tags=["capability", "authorization"],
                                confidence=DiscoveryConfidence.HIGH,
                                provenance=[c_prov],
                            )
                        )
            except Exception:
                pass

        # 3. Discover from raw config dictionary (models, agents, tools, databases)
        if self.raw_config:
            # Models
            for m in self.raw_config.get("models", []):
                if isinstance(m, dict):
                    m_id = m.get("id") or f"model:{m.get('name', 'unnamed')}"
                    assets.append(
                        Asset.create(
                            asset_id=m_id,
                            asset_type=AssetType.MODEL.value,
                            name=m.get("name", m_id),
                            version=m.get("version"),
                            source=AssetSource.CONFIGURATION,
                            metadata={
                                "provider": m.get("provider", "unknown"),
                                "context_window": m.get("context_window"),
                            },
                            tags=["model", "llm"],
                            confidence=DiscoveryConfidence.HIGH,
                            provenance=[
                                AssetProvenance(
                                    source=AssetSource.CONFIGURATION,
                                    provider_name=self.name,
                                    reference="raw_config.models",
                                    observed_at=now,
                                )
                            ],
                        )
                    )

            # Agents
            for a in self.raw_config.get("agents", []):
                if isinstance(a, dict):
                    a_id = a.get("id") or f"agent:{a.get('name', 'unnamed')}"
                    assets.append(
                        Asset.create(
                            asset_id=a_id,
                            asset_type=AssetType.AGENT.value,
                            name=a.get("name", a_id),
                            version=a.get("version"),
                            source=AssetSource.CONFIGURATION,
                            metadata={
                                "role": a.get("role", "assistant"),
                                "model": a.get("model"),
                                "tools": a.get("tools", []),
                            },
                            tags=["agent", "autonomous"],
                            confidence=DiscoveryConfidence.HIGH,
                            provenance=[
                                AssetProvenance(
                                    source=AssetSource.CONFIGURATION,
                                    provider_name=self.name,
                                    reference="raw_config.agents",
                                    observed_at=now,
                                )
                            ],
                        )
                    )

            # Tools
            for t in self.raw_config.get("tools", []):
                if isinstance(t, dict):
                    t_id = t.get("id") or f"tool:{t.get('name', 'unnamed')}"
                    assets.append(
                        Asset.create(
                            asset_id=t_id,
                            asset_type=AssetType.TOOL.value,
                            name=t.get("name", t_id),
                            source=AssetSource.CONFIGURATION,
                            metadata={
                                "category": t.get("category", "utility"),
                                "permission": t.get("permission", "read_write"),
                            },
                            tags=["tool", t.get("category", "utility")],
                            confidence=DiscoveryConfidence.HIGH,
                            provenance=[
                                AssetProvenance(
                                    source=AssetSource.CONFIGURATION,
                                    provider_name=self.name,
                                    reference="raw_config.tools",
                                    observed_at=now,
                                )
                            ],
                        )
                    )

            # Databases / Datastores
            for db in self.raw_config.get("databases", []):
                if isinstance(db, dict):
                    db_id = db.get("id") or f"database:{db.get('name', 'unnamed')}"
                    assets.append(
                        Asset.create(
                            asset_id=db_id,
                            asset_type=AssetType.DATABASE.value,
                            name=db.get("name", db_id),
                            source=AssetSource.CONFIGURATION,
                            metadata={
                                "engine": db.get("engine", "sql"),
                                "read_only": db.get("read_only", False),
                            },
                            tags=["database", "datastore", db.get("engine", "sql")],
                            confidence=DiscoveryConfidence.HIGH,
                            provenance=[
                                AssetProvenance(
                                    source=AssetSource.CONFIGURATION,
                                    provider_name=self.name,
                                    reference="raw_config.databases",
                                    observed_at=now,
                                )
                            ],
                        )
                    )

        return assets
