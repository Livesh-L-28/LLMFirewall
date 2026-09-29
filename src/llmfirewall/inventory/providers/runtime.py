"""Runtime telemetry and observation AI Asset Discovery provider."""

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


class RuntimeDiscoveryProvider(DiscoveryProvider):
    """Discovers AI assets and updates last_seen timestamps from production runtime telemetry events."""

    name: str = "runtime_discovery"
    source_type: AssetSource = AssetSource.RUNTIME

    def __init__(self, events: Optional[List[Dict[str, Any]]] = None) -> None:
        self.events = events or []

    def observe_event(self, event: Dict[str, Any]) -> None:
        self.events.append(event)

    def add_events(self, events: List[Dict[str, Any]]) -> None:
        self.events.extend(events)

    def discover(self) -> List[Asset]:
        assets: List[Asset] = []
        now = time.time()

        for evt in self.events:
            evt_type = str(evt.get("event_type", "")).upper()
            t_stamp = float(evt.get("timestamp", now))

            # 1. Agent invocation
            agent_id = evt.get("agent_id") or evt.get("agent")
            if agent_id:
                clean_id = agent_id if ":" in agent_id else f"agent:{agent_id}"
                prov = AssetProvenance(
                    source=AssetSource.RUNTIME,
                    provider_name=self.name,
                    reference=f"runtime_event:{evt_type}",
                    observed_at=t_stamp,
                    details={"session_id": evt.get("session_id")},
                )
                agent_tools = evt.get("tools", [])
                assets.append(
                    Asset.create(
                        asset_id=clean_id,
                        asset_type=AssetType.AGENT.value,
                        name=f"Runtime Agent: {agent_id}",
                        source=AssetSource.RUNTIME,
                        status=AssetStatus.ACTIVE,
                        metadata={"last_runtime_event": evt_type, "tools": agent_tools},
                        tags=["runtime", "observed", "agent"],
                        confidence=DiscoveryConfidence.HIGH,
                        provenance=[prov],
                        first_seen=t_stamp,
                        last_seen=t_stamp,
                    )
                )

                # Also register associated tools if provided
                for t in agent_tools:
                    t_clean = t if ":" in t else f"tool:{t}"
                    assets.append(
                        Asset.create(
                            asset_id=t_clean,
                            asset_type=AssetType.TOOL.value,
                            name=f"Runtime Tool: {t}",
                            source=AssetSource.RUNTIME,
                            status=AssetStatus.ACTIVE,
                            metadata={"owning_agent": clean_id},
                            tags=["runtime", "observed", "tool"],
                            confidence=DiscoveryConfidence.HIGH,
                            provenance=[prov],
                            first_seen=t_stamp,
                            last_seen=t_stamp,
                        )
                    )

            # 2. Tool invocation
            tool_name = evt.get("tool_name") or evt.get("tool_id") or evt.get("tool")
            if tool_name:
                clean_id = tool_name if ":" in tool_name else f"tool:{tool_name}"
                prov = AssetProvenance(
                    source=AssetSource.RUNTIME,
                    provider_name=self.name,
                    reference=f"runtime_event:{evt_type}",
                    observed_at=t_stamp,
                )
                assets.append(
                    Asset.create(
                        asset_id=clean_id,
                        asset_type=AssetType.TOOL.value,
                        name=f"Runtime Tool: {tool_name}",
                        source=AssetSource.RUNTIME,
                        status=AssetStatus.ACTIVE,
                        metadata={"last_invoked": t_stamp, "endpoint": evt.get("endpoint", "")},
                        tags=["runtime", "observed", "tool"],
                        confidence=DiscoveryConfidence.HIGH,
                        provenance=[prov],
                        first_seen=t_stamp,
                        last_seen=t_stamp,
                    )
                )

            # 3. Model call
            model_name = evt.get("model") or evt.get("model_name")
            if model_name:
                clean_id = model_name if ":" in model_name else f"model:{model_name}"
                prov = AssetProvenance(
                    source=AssetSource.RUNTIME,
                    provider_name=self.name,
                    reference=f"runtime_event:{evt_type}",
                    observed_at=t_stamp,
                )
                assets.append(
                    Asset.create(
                        asset_id=clean_id,
                        asset_type=AssetType.MODEL.value,
                        name=f"Runtime Model: {model_name}",
                        source=AssetSource.RUNTIME,
                        status=AssetStatus.ACTIVE,
                        metadata={"last_requested": t_stamp},
                        tags=["runtime", "observed", "model"],
                        confidence=DiscoveryConfidence.HIGH,
                        provenance=[prov],
                        first_seen=t_stamp,
                        last_seen=t_stamp,
                    )
                )

            # 4. RAG Source access
            rag_source = evt.get("rag_source")
            if rag_source:
                clean_id = rag_source if ":" in rag_source else f"rag:{rag_source}"
                prov = AssetProvenance(
                    source=AssetSource.RUNTIME,
                    provider_name=self.name,
                    reference=f"runtime_event:{evt_type}",
                    observed_at=t_stamp,
                )
                assets.append(
                    Asset.create(
                        asset_id=clean_id,
                        asset_type=AssetType.RAG_SOURCE.value,
                        name=f"Runtime RAG Source: {rag_source}",
                        source=AssetSource.RUNTIME,
                        status=AssetStatus.ACTIVE,
                        tags=["runtime", "observed", "rag"],
                        confidence=DiscoveryConfidence.HIGH,
                        provenance=[prov],
                        first_seen=t_stamp,
                        last_seen=t_stamp,
                    )
                )

        return assets
