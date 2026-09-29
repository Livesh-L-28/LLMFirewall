"""AssetInventory and DiscoveryEngine orchestrating AI asset discovery, normalization, and KnowledgeGraph synchronization."""

from collections import deque
import hashlib
import json
import logging
from pathlib import Path
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from llmfirewall.attack_graph.engine import AttackGraph
from llmfirewall.audit import AuditLogger
from llmfirewall.core.models import Action, AuditEvent, Severity
from llmfirewall.graph.engine import KnowledgeGraph
from llmfirewall.graph.models import Node, NodeType, RelationshipType
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
from llmfirewall.inventory.providers.base import DiscoveryProvider
from llmfirewall.inventory.providers.code import CodeDiscoveryProvider
from llmfirewall.inventory.providers.config import ConfigDiscoveryProvider
from llmfirewall.inventory.providers.dependencies import DependencyDiscoveryProvider
from llmfirewall.inventory.providers.env import EnvironmentDiscoveryProvider
from llmfirewall.inventory.providers.import_provider import ImportDiscoveryProvider
from llmfirewall.inventory.providers.manual import ManualDiscoveryProvider
from llmfirewall.inventory.providers.runtime import RuntimeDiscoveryProvider

logger = logging.getLogger("llmfirewall.inventory")


class InventoryMetrics:
    """Thread-safe bounded telemetry metrics for inventory and discovery operations without unbounded asset labels."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.inventory_assets_total = 0
        self.inventory_discovery_runs_total = 0
        self.inventory_discovery_failures_total = 0
        self.inventory_assets_discovered_total = 0
        self.inventory_assets_changed_total = 0
        self.inventory_assets_removed_total = 0
        self.inventory_query_total = 0

    def record_run(self, discovered: int, changed: int, removed: int, failed: bool = False) -> None:
        with self._lock:
            self.inventory_discovery_runs_total += 1
            if failed:
                self.inventory_discovery_failures_total += 1
            self.inventory_assets_discovered_total += discovered
            self.inventory_assets_changed_total += changed
            self.inventory_assets_removed_total += removed

    def record_query(self) -> None:
        with self._lock:
            self.inventory_query_total += 1

    def update_total_assets(self, count: int) -> None:
        with self._lock:
            self.inventory_assets_total = count

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "inventory_assets_total": self.inventory_assets_total,
                "inventory_discovery_runs_total": self.inventory_discovery_runs_total,
                "inventory_discovery_failures_total": self.inventory_discovery_failures_total,
                "inventory_assets_discovered_total": self.inventory_assets_discovered_total,
                "inventory_assets_changed_total": self.inventory_assets_changed_total,
                "inventory_assets_removed_total": self.inventory_assets_removed_total,
                "inventory_query_total": self.inventory_query_total,
            }

    def reset(self) -> None:
        with self._lock:
            self.inventory_assets_total = 0
            self.inventory_discovery_runs_total = 0
            self.inventory_discovery_failures_total = 0
            self.inventory_assets_discovered_total = 0
            self.inventory_assets_changed_total = 0
            self.inventory_assets_removed_total = 0
            self.inventory_query_total = 0


def normalize_asset_id(first_arg: str, second_arg: Optional[str] = None) -> str:
    """Normalize asset IDs into canonical, deterministic domain-prefixed identities."""
    import re
    if second_arg is not None:
        known_types = {t.value for t in AssetType}
        if first_arg.lower() in known_types or ":" not in first_arg:
            asset_type = first_arg.lower()
            raw_id = second_arg
        else:
            raw_id = first_arg
            asset_type = second_arg.lower()
    else:
        raw_id = first_arg
        asset_type = AssetType.CUSTOM.value

    clean = raw_id.strip()
    parts = clean.split(":", 1)
    if len(parts) == 2:
        prefix = parts[0].strip().lower()
        body = parts[1].strip().lower()
    else:
        prefix = asset_type.strip().lower()
        body = clean.lower()

    # Clean body: replace whitespace and special punctuation with underscore while preserving hyphens, dots, alphanumeric
    clean_body = re.sub(r"[\s/\\!@#$%^&*+=~`|<>?,;]+", "_", body).strip("_")
    return f"{prefix}:{clean_body}"


class DiscoveryEngine:
    """Orchestrator executing discovery providers with fault-isolation and partial recovery."""

    def __init__(self, providers: Optional[List[DiscoveryProvider]] = None) -> None:
        self._providers: List[DiscoveryProvider] = providers or []

    def register_provider(self, provider: DiscoveryProvider) -> None:
        self._providers.append(provider)

    def list_providers(self) -> List[DiscoveryProvider]:
        return list(self._providers)

    def run_discovery(self) -> Tuple[List[Asset], Dict[str, Any], List[str]]:
        """Run all registered discovery providers with failure isolation."""
        all_raw_assets: List[Asset] = []
        provider_results: Dict[str, Any] = {}
        warnings: List[str] = []

        for prov in self._providers:
            p_name = prov.name
            t0 = time.perf_counter()
            try:
                found = prov.discover()
                dur_ms = (time.perf_counter() - t0) * 1000.0
                provider_results[p_name] = {
                    "status": "success",
                    "assets_found": len(found),
                    "duration_ms": round(dur_ms, 2),
                }
                all_raw_assets.extend(found)
            except Exception as exc:
                dur_ms = (time.perf_counter() - t0) * 1000.0
                logger.warning("Discovery provider '%s' failed: %s", p_name, exc)
                provider_results[p_name] = {
                    "status": "failed",
                    "error": str(exc),
                    "duration_ms": round(dur_ms, 2),
                }
                warnings.append(f"Provider '{p_name}' failed: {exc}")

        return all_raw_assets, provider_results, warnings

    def run_all(self) -> DiscoveryResult:
        """Run discovery providers and wrap in a structured DiscoveryResult."""
        assets, prov_results, warnings = self.run_discovery()
        failures = sum(1 for p in prov_results.values() if p.get("status") == "failed")
        successes = sum(1 for p in prov_results.values() if p.get("status") == "success")
        if failures > 0 and successes > 0:
            status = DiscoveryStatus.PARTIAL
        elif failures > 0 and successes == 0:
            status = DiscoveryStatus.FAILED
        else:
            status = DiscoveryStatus.COMPLETE

        total_dur = sum(v.get("duration_ms", 0.0) for v in prov_results.values())
        return DiscoveryResult(
            status=status,
            provider_results=prov_results,
            assets_discovered=len(assets),
            assets_added=len(assets),
            assets_changed=0,
            assets_removed=0,
            warnings=warnings,
            duration_ms=total_dur,
        )


class AssetInventory:
    """Authoritative AI Asset Inventory managing discovery, normalization, deduplication, and graph integration.
    
    Invariants:
    - Never stores credentials or secrets.
    - Tracks multi-source provenance and records explicit conflict states.
    - Feeds Phase 32 KnowledgeGraph and Phase 33 AttackGraph without maintaining an unrelated database.
    - Strictly bounds capacity against memory exhaustion.
    """

    def __init__(
        self,
        kg: Optional[KnowledgeGraph] = None,
        attack_graph: Optional[AttackGraph] = None,
        max_assets: int = 50000,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        self.kg = kg if kg is not None else KnowledgeGraph()
        self.attack_graph = attack_graph
        self.max_assets = max(1, min(max_assets, 1000000))
        self.audit_logger = audit_logger
        self.metrics = InventoryMetrics()
        self._lock = threading.RLock()

        self._assets: Dict[str, Asset] = {}
        self.manual_provider = ManualDiscoveryProvider()
        self.discovery_engine = DiscoveryEngine(
            providers=[
                ConfigDiscoveryProvider(),
                EnvironmentDiscoveryProvider(),
                DependencyDiscoveryProvider(),
                self.manual_provider,
            ]
        )

    # -------------------------------------------------------------------------
    # Audit & Telemetry
    # -------------------------------------------------------------------------

    def _emit_audit(self, event_type: str, details: Dict[str, Any]) -> None:
        if not self.audit_logger:
            return
        try:
            event = AuditEvent(
                scan_id=f"INVENTORY-{details.get('asset_id') or 'event'}",
                action_taken=Action.ALLOW,
                risk_score=0.0,
                max_severity=Severity.LOW,
                metadata={
                    "inventory_event": event_type,
                    **details,
                },
            )
            self.audit_logger.emit(event)
        except Exception as exc:
            logger.warning("Failed to emit inventory audit event %s: %s", event_type, exc)

    # -------------------------------------------------------------------------
    # Core Asset Management & Normalization
    # -------------------------------------------------------------------------

    def __len__(self) -> int:
        with self._lock:
            return len(self._assets)

    def register(self, asset: Asset) -> Asset:
        """Register or merge a normalized asset into inventory."""
        with self._lock:
            if len(self._assets) >= self.max_assets and asset.id not in self._assets:
                raise RuntimeError(f"Asset inventory capacity limit of {self.max_assets} assets reached.")

            canonical_id = normalize_asset_id(asset.id, asset.type)
            norm_type = asset.type.strip().lower()

            if canonical_id != asset.id or norm_type != asset.type:
                # Rebuild with canonical id
                asset = Asset.create(
                    asset_id=canonical_id,
                    asset_type=norm_type,
                    name=asset.name,
                    version=asset.version,
                    environment=asset.environment,
                    source=asset.source,
                    status=asset.status,
                    metadata=asset.metadata,
                    tags=asset.tags,
                    owner=asset.owner,
                    confidence=asset.confidence,
                    provenance=asset.provenance,
                    first_seen=asset.first_seen,
                    last_seen=asset.last_seen,
                )

            existing = self._assets.get(canonical_id)
            if existing:
                merged = self._merge_assets(existing, asset)
                self._assets[canonical_id] = merged
                self._emit_audit("ASSET_MERGED", {"asset_id": canonical_id, "source": asset.source.value})
                res_asset = merged
            else:
                self._assets[canonical_id] = asset
                self.manual_provider.register(asset)
                self._emit_audit("ASSET_REGISTERED", {"asset_id": canonical_id, "type": asset.type})
                res_asset = asset

            self.metrics.update_total_assets(len(self._assets))
            return res_asset

    def _merge_assets(self, existing: Asset, incoming: Asset) -> Asset:
        """Safely combine attributes, provenance, and detect conflicts across sources."""
        now = time.time()
        f_seen = min(existing.first_seen, incoming.first_seen)
        l_seen = max(existing.last_seen, incoming.last_seen)

        # Provenance: deduplicate by (source, reference)
        combined_prov = list(existing.provenance)
        existing_refs = {(p.source.value, p.reference) for p in combined_prov}
        for p in incoming.provenance:
            if (p.source.value, p.reference) not in existing_refs:
                combined_prov.append(p)
                existing_refs.add((p.source.value, p.reference))

        # Conflict Detection
        conflicts = list(existing.conflicts)
        if incoming.version and existing.version and incoming.version != existing.version:
            conflicts.append(
                AssetConflict(
                    field="version",
                    configured_value=existing.version,
                    observed_value=incoming.version,
                    detected_at=now,
                    description=f"Version discrepancy: '{existing.version}' vs '{incoming.version}'.",
                )
            )

        if (
            incoming.environment != "unknown"
            and existing.environment != "unknown"
            and incoming.environment != existing.environment
        ):
            conflicts.append(
                AssetConflict(
                    field="environment",
                    configured_value=existing.environment,
                    observed_value=incoming.environment,
                    detected_at=now,
                    description=f"Environment mismatch: '{existing.environment}' vs '{incoming.environment}'.",
                )
            )

        # Merge metadata
        merged_meta = dict(existing.metadata)
        merged_meta.update(incoming.metadata)
        merged_meta = sanitize_metadata_secrets(merged_meta)

        # Merge tags
        combined_tags = sorted(list(set(existing.tags + incoming.tags)))

        # Status: ACTIVE takes precedence
        effective_status = (
            AssetStatus.ACTIVE
            if (existing.status == AssetStatus.ACTIVE or incoming.status == AssetStatus.ACTIVE)
            else incoming.status
        )

        return Asset(
            id=existing.id,
            type=existing.type,
            name=incoming.name or existing.name,
            version=incoming.version or existing.version,
            environment=incoming.environment if incoming.environment != "unknown" else existing.environment,
            source=incoming.source,
            status=effective_status,
            metadata=merged_meta,
            first_seen=f_seen,
            last_seen=l_seen,
            tags=combined_tags,
            owner=incoming.owner or existing.owner,
            confidence=incoming.confidence if incoming.confidence == DiscoveryConfidence.HIGH else existing.confidence,
            provenance=combined_prov,
            conflicts=conflicts,
            fingerprint=incoming.fingerprint or existing.fingerprint,
        )

    def get(self, asset_id: str) -> Optional[Asset]:
        """Lookup an asset by normalized or raw identifier."""
        self.metrics.record_query()
        with self._lock:
            # Direct match
            if asset_id in self._assets:
                return self._assets[asset_id]
            # Try normalizing
            norm_id = asset_id.strip().lower().replace("-", "_")
            if norm_id in self._assets:
                return self._assets[norm_id]
            # Search body
            for aid, a in self._assets.items():
                if aid.endswith(f":{norm_id}"):
                    return a
            return None

    def remove(self, asset_id: str, reason: str = "") -> bool:
        """Mark an asset as REMOVED based on verified evidence without destroying provenance."""
        with self._lock:
            asset = self.get(asset_id)
            if not asset:
                return False

            updated = Asset(
                id=asset.id,
                type=asset.type,
                name=asset.name,
                version=asset.version,
                environment=asset.environment,
                source=asset.source,
                status=AssetStatus.REMOVED,
                metadata={**asset.metadata, "removal_reason": reason, "removed_at": time.time()},
                first_seen=asset.first_seen,
                last_seen=time.time(),
                tags=asset.tags,
                owner=asset.owner,
                confidence=asset.confidence,
                provenance=asset.provenance,
                conflicts=asset.conflicts,
                fingerprint=asset.fingerprint,
            )
            self._assets[asset.id] = updated
            self._emit_audit("ASSET_REMOVED", {"asset_id": asset.id, "reason": reason})
            self.metrics.record_run(0, 0, 1)
            return True

    def list_assets(
        self,
        type: Optional[str] = None,
        environment: Optional[str] = None,
        status: Optional[str] = None,
        source: Optional[str] = None,
        tag: Optional[str] = None,
    ) -> List[Asset]:
        """List assets matching optional attribute filters."""
        self.metrics.record_query()
        with self._lock:
            results = list(self._assets.values())

            if type:
                t_clean = type.strip().lower()
                results = [a for a in results if a.type == t_clean]
            if environment:
                e_clean = environment.strip().lower()
                results = [a for a in results if a.environment == e_clean]
            if status:
                s_clean = status.strip().upper()
                results = [a for a in results if a.status.value == s_clean]
            if source:
                src_clean = source.strip().upper()
                results = [a for a in results if a.source.value == src_clean]
            if tag:
                tag_clean = tag.strip().lower()
                results = [a for a in results if tag_clean in [t.lower() for t in a.tags]]

            return sorted(results, key=lambda a: a.id)

    def search(
        self,
        query: str,
        type: Optional[str] = None,
        environment: Optional[str] = None,
        status: Optional[str] = None,
        source: Optional[str] = None,
        tag: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> List[Asset]:
        """Search assets by text query across ID, name, tags, and metadata."""
        base_assets = self.list_assets(type=type, environment=environment, status=status, source=source, tag=tag)
        q = query.strip().lower()
        if not q and not provider:
            return base_assets

        filtered: List[Asset] = []
        for a in base_assets:
            if provider:
                p_clean = provider.strip().lower()
                prov_match = any(p_clean in str(p.details.get("provider", "")).lower() or p_clean in p.provider_name.lower() for p in a.provenance)
                if not prov_match:
                    continue

            if not q:
                filtered.append(a)
                continue

            # Check query against id, name, tags, or metadata
            if (
                q in a.id.lower()
                or q in a.name.lower()
                or any(q in t.lower() for t in a.tags)
                or q in json.dumps(a.metadata).lower()
            ):
                filtered.append(a)

        return filtered

    # -------------------------------------------------------------------------
    # Discovery Orchestration
    # -------------------------------------------------------------------------

    def discover(
        self,
        providers: Optional[List[DiscoveryProvider]] = None,
        sync_graph: bool = True,
    ) -> DiscoveryResult:
        """Execute discovery cycle, register assets, update graph, and return structured result."""
        t0 = time.perf_counter()
        now = time.time()
        self._emit_audit("DISCOVERY_STARTED", {"timestamp": now})

        engine = DiscoveryEngine(providers=providers) if providers else self.discovery_engine
        raw_assets, provider_results, warnings = engine.run_discovery()

        initial_count = len(self._assets)
        added_count = 0
        changed_count = 0

        with self._lock:
            for raw_a in raw_assets:
                canonical_id = normalize_asset_id(raw_a.id, raw_a.type)
                existing = self._assets.get(canonical_id)

                if existing:
                    old_fp = existing.fingerprint
                    merged = self.register(raw_a)
                    if merged.fingerprint != old_fp:
                        changed_count += 1
                else:
                    self.register(raw_a)
                    added_count += 1

            self.metrics.record_run(len(raw_assets), changed_count, 0, failed=bool(warnings and not raw_assets))

        # Synchronize into KnowledgeGraph if requested
        if sync_graph:
            self.sync_to_graph()

        dur_ms = (time.perf_counter() - t0) * 1000.0

        # Determine overall execution status
        failed_providers = [k for k, v in provider_results.items() if v.get("status") == "failed"]
        if not failed_providers:
            overall_status = DiscoveryStatus.COMPLETE
        elif len(failed_providers) < len(provider_results):
            overall_status = DiscoveryStatus.PARTIAL
        else:
            overall_status = DiscoveryStatus.FAILED

        result = DiscoveryResult(
            status=overall_status,
            provider_results=provider_results,
            assets_discovered=len(raw_assets),
            assets_added=added_count,
            assets_changed=changed_count,
            assets_removed=0,
            warnings=warnings,
            duration_ms=dur_ms,
            timestamp=now,
        )

        self._emit_audit(
            "DISCOVERY_COMPLETED",
            {
                "status": overall_status.value,
                "assets_discovered": len(raw_assets),
                "assets_added": added_count,
                "assets_changed": changed_count,
                "duration_ms": round(dur_ms, 2),
            },
        )
        return result

    # -------------------------------------------------------------------------
    # Stale Asset Detection
    # -------------------------------------------------------------------------

    def stale_assets(self, stale_threshold_seconds: float = 86400 * 7) -> List[Asset]:
        """Identify active assets unobserved beyond the freshness threshold and mark them STALE."""
        now = time.time()
        stale: List[Asset] = []

        with self._lock:
            for a_id, a in self._assets.items():
                if a.status == AssetStatus.ACTIVE and (now - a.last_seen) > stale_threshold_seconds:
                    updated = Asset(
                        id=a.id,
                        type=a.type,
                        name=a.name,
                        version=a.version,
                        environment=a.environment,
                        source=a.source,
                        status=AssetStatus.STALE,
                        metadata={**a.metadata, "stale_since": now},
                        first_seen=a.first_seen,
                        last_seen=a.last_seen,
                        tags=a.tags,
                        owner=a.owner,
                        confidence=a.confidence,
                        provenance=a.provenance,
                        conflicts=a.conflicts,
                        fingerprint=a.fingerprint,
                    )
                    self._assets[a_id] = updated
                    stale.append(updated)
                    self._emit_audit("ASSET_UPDATED", {"asset_id": a.id, "status": AssetStatus.STALE.value})

        return stale

    # Alias for convenience
    mark_stale_assets = stale_assets

    # -------------------------------------------------------------------------
    # Phase 32 KnowledgeGraph Synchronization
    # -------------------------------------------------------------------------

    def sync_to_graph(self, kg: Optional[KnowledgeGraph] = None) -> KnowledgeGraph:
        """Populate Phase 32 KnowledgeGraph nodes and infer structural relationships from active inventory."""
        target_kg = kg if kg is not None else self.kg

        with self._lock:
            # 1. Add all active assets as KnowledgeGraph nodes
            for a in self._assets.values():
                if a.status in (AssetStatus.ACTIVE, AssetStatus.STALE):
                    # Map to known NodeType if present
                    n_type = a.type
                    try:
                        n_type = NodeType(a.type).value
                    except ValueError:
                        n_type = NodeType.CUSTOM.value

                    # Add or update node
                    if not target_kg.get_node(a.id):
                        target_kg.add_node(
                            node_or_id=a.id,
                            node_type=n_type,
                            properties={
                                "name": a.name,
                                "version": a.version or "",
                                "environment": a.environment,
                                "source": a.source.value,
                                "fingerprint": a.fingerprint,
                                **a.metadata,
                            },
                        )

            # 2. Infer and add structural relationships
            for a in self._assets.values():
                if a.type == AssetType.AGENT.value:
                    # Agent USES Model
                    model_ref = a.metadata.get("model")
                    if model_ref:
                        m_id = model_ref if ":" in model_ref else f"model:{model_ref}"
                        if target_kg.get_node(m_id):
                            target_kg.add_relationship(a.id, RelationshipType.USES.value, m_id)

                    # Agent CAN_CALL Tool
                    tools_list = a.metadata.get("tools", [])
                    for t in tools_list:
                        t_id = t if ":" in t else f"tool:{t}"
                        if target_kg.get_node(t_id):
                            target_kg.add_relationship(a.id, RelationshipType.CAN_CALL.value, t_id)

                elif a.type == AssetType.MODEL.value:
                    # Model PROVIDED_BY Model Provider
                    provider_ref = a.metadata.get("provider")
                    if provider_ref:
                        p_id = f"provider:{provider_ref.lower()}"
                        if target_kg.get_node(p_id):
                            target_kg.add_relationship(a.id, RelationshipType.PART_OF.value, p_id)

                elif a.type == AssetType.SECURITY_CONTROL.value:
                    # Security Control PROTECTS Application
                    if target_kg.get_node("application:firewall"):
                        target_kg.add_relationship(a.id, RelationshipType.PROTECTS.value, "application:firewall")

                elif a.type == AssetType.POLICY.value:
                    # Policy GOVERNS Application
                    if target_kg.get_node("application:firewall"):
                        target_kg.add_relationship(a.id, RelationshipType.GOVERNS.value, "application:firewall")

        return target_kg

    # -------------------------------------------------------------------------
    # Relationship & Security Posture Exposure Views
    # -------------------------------------------------------------------------

    def related_assets(self, asset_id: str) -> List[Dict[str, Any]]:
        """Query underlying KnowledgeGraph for directly connected assets and relationships."""
        norm_id = asset_id
        asset = self.get(asset_id)
        if asset:
            norm_id = asset.id

        related: List[Dict[str, Any]] = []
        # Outgoing edges
        for edge in self.kg.store.get_out_edges(norm_id):
            related.append({
                "direction": "out",
                "relationship": edge.type,
                "target_id": edge.target,
            })
        # Incoming edges
        for edge in self.kg.store.get_in_edges(norm_id):
            related.append({
                "direction": "in",
                "relationship": edge.type,
                "source_id": edge.source,
            })

        return related

    def attack_surface(self, asset_id: str) -> AssetExposure:
        """Synthesize comprehensive security exposure view integrating Phase 32 & Phase 33."""
        asset = self.get(asset_id)
        target_id = asset.id if asset else asset_id
        target_type = asset.type if asset else "unknown"
        env = asset.environment if asset else "unknown"
        sources = [p.source.value for p in asset.provenance] if asset else []

        # 1. Entry points
        entry_points: List[str] = []
        if self.attack_graph:
            for ep in self.attack_graph.list_entry_points():
                if ep.target_asset_id == target_id or target_id in ep.target_asset_id:
                    entry_points.append(ep.entry_point_id)

        # 2. Tools & Capabilities
        tools: List[str] = []
        capabilities: List[str] = []
        for edge in self.kg.store.get_out_edges(target_id):
            if edge.type in (RelationshipType.CAN_CALL.value, RelationshipType.USES.value):
                tgt_node = self.kg.get_node(edge.target)
                if tgt_node and tgt_node.type == NodeType.TOOL.value:
                    tools.append(edge.target)
                elif tgt_node and tgt_node.type == NodeType.CAPABILITY.value:
                    capabilities.append(edge.target)

        # 3. Protecting Controls
        controls: List[str] = []
        for edge in self.kg.store.get_in_edges(target_id):
            if edge.type in (RelationshipType.PROTECTS.value, "PROTECTED_BY"):
                controls.append(edge.source)
        for edge in self.kg.store.get_out_edges(target_id):
            if edge.type in (RelationshipType.PROTECTED_BY.value, "PROTECTED_BY"):
                controls.append(edge.target)

        # 4. Attack Paths
        attack_paths: List[Dict[str, Any]] = []
        assumptions: Set[str] = set()
        if self.attack_graph:
            paths = self.attack_graph.find_paths(source=target_id, max_depth=4)
            for p in paths:
                attack_paths.append(p.to_dict())
                assumptions.update(p.assumptions)

        # 5. Security Findings
        findings: List[Dict[str, Any]] = []
        for edge in self.kg.store.get_in_edges(target_id):
            if edge.type in (RelationshipType.AFFECTS.value, RelationshipType.HAS_FINDING.value):
                f_node = self.kg.get_node(edge.source)
                if f_node:
                    findings.append(f_node.to_dict())

        return AssetExposure(
            asset_id=target_id,
            asset_type=target_type,
            environment=env,
            sources=sorted(list(set(sources))),
            entry_points=sorted(list(set(entry_points))),
            tools=sorted(list(set(tools))),
            capabilities=sorted(list(set(capabilities))),
            attack_paths=attack_paths,
            security_controls=sorted(list(set(controls))),
            findings=findings,
            assumptions=sorted(list(assumptions)),
            last_seen=asset.last_seen if asset else time.time(),
        )

    # -------------------------------------------------------------------------
    # Snapshots & Baseline Diff
    # -------------------------------------------------------------------------

    def snapshot(self, inventory_version: str = "1.0") -> InventorySnapshot:
        """Create a tamper-evident, canonical snapshot of the entire asset inventory."""
        with self._lock:
            active_assets = list(self._assets.values())
            kg_hash = self.kg.snapshot().graph_hash
            sources = sorted(list({a.source.value for a in active_assets}))

            return InventorySnapshot.create(
                assets=active_assets,
                sources=sources,
                graph_hash=kg_hash,
                inventory_version=inventory_version,
            )

    @staticmethod
    def diff(
        previous: InventorySnapshot,
        current: InventorySnapshot,
    ) -> InventoryDiff:
        """Compute the architectural difference between two inventory snapshots."""
        prev_assets = {a.id: a for a in previous.assets}
        curr_assets = {a.id: a for a in current.assets}

        # Removed: present and not REMOVED in previous, but absent or marked REMOVED in current
        removed = []
        for pid, pa in prev_assets.items():
            if pa.status != AssetStatus.REMOVED:
                if pid not in curr_assets or curr_assets[pid].status == AssetStatus.REMOVED:
                    removed.append(pid)
        removed.sort()

        # Added: present and not REMOVED in current, but absent or previously REMOVED in previous
        added = []
        for cid, ca in curr_assets.items():
            if ca.status != AssetStatus.REMOVED:
                if cid not in prev_assets or prev_assets[cid].status == AssetStatus.REMOVED:
                    added.append(cid)
        added.sort()

        changed: List[str] = []
        config_changed: List[str] = []

        for common_id in set(curr_assets.keys()).intersection(prev_assets.keys()):
            if common_id in added or common_id in removed:
                continue

            a_prev = prev_assets[common_id]
            a_curr = curr_assets[common_id]

            if a_prev.fingerprint != a_curr.fingerprint or a_prev.status != a_curr.status:
                changed.append(common_id)

            if a_prev.metadata != a_curr.metadata or a_prev.version != a_curr.version:
                config_changed.append(common_id)

        # Sources change
        new_sources = sorted(list(set(current.sources) - set(previous.sources)))

        # Relationships change (via graph hashes)
        rel_changed: List[str] = []
        if previous.graph_hash != current.graph_hash:
            rel_changed.append("knowledge_graph_topology_updated")

        is_identical = not (added or removed or changed or new_sources or rel_changed)

        return InventoryDiff(
            assets_added=added,
            assets_removed=removed,
            assets_changed=sorted(changed),
            relationships_changed=rel_changed,
            sources_changed=new_sources,
            configurations_changed=sorted(config_changed),
            is_identical=is_identical,
        )

    # -------------------------------------------------------------------------
    # Import & Export
    # -------------------------------------------------------------------------

    def export_to_file(self, path: str, format_type: str = "json") -> None:
        """Export inventory snapshot to a JSON or YAML file."""
        snap = self.snapshot()
        p = Path(path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)

        fmt = format_type.lower()
        if fmt == "json":
            p.write_text(snap.to_json(indent=2), encoding="utf-8")
        elif fmt in ("yaml", "yml"):
            try:
                import yaml
                p.write_text(yaml.dump(snap.to_dict(), sort_keys=False), encoding="utf-8")
            except ImportError:
                p.write_text(snap.to_json(indent=2), encoding="utf-8")
        else:
            p.write_text(snap.to_json(indent=2), encoding="utf-8")

        self._emit_audit("INVENTORY_EXPORTED", {"output_file": str(p), "assets_count": snap.assets_count})

    def import_from_file(self, path: str, format_type: str = "auto") -> DiscoveryResult:
        """Import and register assets from an external inventory file."""
        provider = ImportDiscoveryProvider(file_path=path, format_type=format_type)
        res = self.discover(providers=[provider])
        self._emit_audit("INVENTORY_IMPORTED", {"input_file": str(path), "assets_added": res.assets_added})
        return res
