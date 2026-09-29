"""Data models, provenance, and schemas for Phase 34 — AI Asset Inventory & Discovery."""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
import time
from typing import Any, Dict, List, Optional, Set
import uuid
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class AssetType(str, Enum):
    """Controlled taxonomy of discoverable AI assets."""
    APPLICATION = "application"
    AGENT = "agent"
    MODEL = "model"
    MODEL_PROVIDER = "model_provider"
    TOOL = "tool"
    API = "api"
    PROMPT = "prompt"
    PROMPT_TEMPLATE = "prompt_template"
    RAG_SOURCE = "rag_source"
    DOCUMENT_STORE = "document_store"
    DOCUMENT = "document"
    MEMORY_STORE = "memory_store"
    VECTOR_STORE = "vector_store"
    DATABASE = "database"
    DEPENDENCY = "dependency"
    PACKAGE = "package"
    CONTAINER = "container"
    CONFIGURATION = "configuration"
    POLICY = "policy"
    SECURITY_CONTROL = "security_control"
    CAPABILITY = "capability"
    INTEGRATION = "integration"
    ENDPOINT = "endpoint"
    CUSTOM = "custom"


class AssetStatus(str, Enum):
    """Lifecycle status of a discovered AI asset."""
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    STALE = "STALE"
    REMOVED = "REMOVED"
    UNKNOWN = "UNKNOWN"


class AssetSource(str, Enum):
    """Origin or discovery mechanism through which an asset was identified."""
    CONFIGURATION = "CONFIGURATION"
    RUNTIME = "RUNTIME"
    CODE = "CODE"
    DEPENDENCY_MANIFEST = "DEPENDENCY_MANIFEST"
    DOCKER = "DOCKER"
    ENVIRONMENT = "ENVIRONMENT"
    API = "API"
    PLUGIN = "PLUGIN"
    USER_REGISTERED = "USER_REGISTERED"
    GRAPH = "GRAPH"


class DiscoveryConfidence(str, Enum):
    """Source-reliability confidence rating for an asset discovery."""
    HIGH = "HIGH"        # Verifiable local config, manifest, or runtime telemetry
    MEDIUM = "MEDIUM"    # Heuristic code inspection or inferred relationship
    LOW = "LOW"          # Ambiguous reference or partial detection
    UNKNOWN = "UNKNOWN"  # Unverified external input


class DiscoveryStatus(str, Enum):
    """Execution status of a discovery cycle."""
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


# Patterns for preventing secret storage in asset metadata
SECRET_PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9]{20,}", re.IGNORECASE),
    re.compile(r"ghp_[a-zA-Z0-9]{20,}", re.IGNORECASE),
    re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
    re.compile(r"(password|passwd|pwd|secret|api_key|apikey|private_key)\s*[:=]\s*[^\s]+", re.IGNORECASE),
]


def sanitize_metadata_secrets(data: Any) -> Any:
    """Recursively scrub any credential or secret patterns from asset metadata dictionaries."""
    if isinstance(data, dict):
        clean = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(s in k_lower for s in ("api_key", "apikey", "secret", "token", "password", "passwd", "credential", "private_key", "auth_token")):
                clean[k] = "[REDACTED_CREDENTIAL]"
            else:
                clean[k] = sanitize_metadata_secrets(v)
        return clean
    elif isinstance(data, list):
        return [sanitize_metadata_secrets(item) for item in data]
    elif isinstance(data, str):
        for pattern in SECRET_PATTERNS:
            if pattern.search(data):
                return "[REDACTED_SECRET]"
        return data
    return data


class AssetProvenance(BaseModel):
    """Verifiable audit record explaining how and where an asset was discovered."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    source: AssetSource = Field(..., description="Classification of the discovery channel.")
    provider_name: str = Field(..., description="Discovery provider module or identifier.")
    reference: str = Field(default="", description="Reference file, config path, or event source.")
    observed_at: float = Field(default_factory=time.time, description="Epoch timestamp when observed.")
    details: Dict[str, Any] = Field(default_factory=dict, description="Safe auxiliary context (no secrets).")

    @field_validator("details")
    @classmethod
    def sanitize_details(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        return sanitize_metadata_secrets(v)


class AssetConflict(BaseModel):
    """Recorded conflict between different discovery sources (e.g. configured vs runtime version)."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    field: str = Field(..., description="Attribute name in conflict.")
    configured_value: Any = Field(default=None, description="Value declared in configuration.")
    observed_value: Any = Field(default=None, description="Value observed during runtime or discovery.")
    detected_at: float = Field(default_factory=time.time, description="Epoch timestamp of detection.")
    description: str = Field(default="", description="Explanation of the discrepancy.")


class Asset(BaseModel):
    """Normalized, auditable AI asset record representing an architectural component.
    
    Invariants:
    1. Stable Identifiers: Deterministic domain-prefixed identities (e.g. 'agent:customer-support').
    2. Zero Raw Secrets: Attributes strictly sanitize keys, passwords, and tokens.
    3. Multi-Source Provenance: Retains discovery history without destructive overwrite.
    4. Conflict Transparency: Mismatches between sources are recorded as explicit conflicts.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(..., min_length=1, max_length=256, description="Stable, unique asset identifier.")
    type: str = Field(default=AssetType.CUSTOM.value, description="Classification type of asset.")
    name: str = Field(..., description="Human-readable asset name.")
    version: Optional[str] = Field(default=None, description="Version or release tag of asset.")
    environment: str = Field(default="unknown", description="Deployment environment: dev, test, staging, prod.")
    source: AssetSource = Field(default=AssetSource.USER_REGISTERED, description="Primary discovery source.")
    status: AssetStatus = Field(default=AssetStatus.ACTIVE, description="Current operational state.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Sanitized asset properties (no secrets).")
    first_seen: float = Field(default_factory=time.time, description="Epoch timestamp of initial discovery.")
    last_seen: float = Field(default_factory=time.time, description="Epoch timestamp of most recent observation.")
    tags: List[str] = Field(default_factory=list, description="User-assigned categorizations (ai, critical, etc.).")
    owner: Optional[str] = Field(default=None, description="Team or service owner identifier.")
    confidence: DiscoveryConfidence = Field(default=DiscoveryConfidence.HIGH, description="Discovery reliability.")
    provenance: List[AssetProvenance] = Field(default_factory=list, description="Discovery source provenance records.")
    conflicts: List[AssetConflict] = Field(default_factory=list, description="Recorded discrepancies across sources.")
    fingerprint: str = Field(default="", description="Cryptographic SHA-256 fingerprint for change detection.")

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Asset ID cannot be empty.")
        if len(clean) > 256:
            raise ValueError("Asset ID exceeds maximum length of 256 characters.")
        # Reject invalid path traversal characters in asset IDs
        if "../" in clean or "..\\" in clean:
            raise ValueError("Asset ID cannot contain directory traversal sequences.")
        return clean

    @field_validator("type")
    @classmethod
    def normalize_type(cls, v: str) -> str:
        clean = v.strip().lower()
        if not clean:
            raise ValueError("Asset type cannot be empty.")
        return clean

    @field_validator("environment")
    @classmethod
    def normalize_env(cls, v: str) -> str:
        clean = v.strip().lower()
        if clean in ("prod", "production"):
            return "production"
        elif clean in ("stage", "staging"):
            return "staging"
        elif clean in ("test", "testing"):
            return "testing"
        elif clean in ("dev", "development"):
            return "development"
        return clean or "unknown"

    @field_validator("metadata")
    @classmethod
    def scrub_metadata(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        # Enforce max metadata size (64KB serialized)
        dumped = json.dumps(v, default=str)
        if len(dumped.encode("utf-8")) > 65536:
            raise ValueError("Asset metadata exceeds maximum size limit of 64KB.")
        return sanitize_metadata_secrets(v)

    @model_validator(mode="before")
    @classmethod
    def prepare_asset_data(cls, data: Any) -> Any:
        if isinstance(data, dict):
            asset_id = str(data.get("id", "")).strip()
            asset_type = str(data.get("type", AssetType.CUSTOM.value)).strip().lower()
            version = data.get("version") or ""
            env = str(data.get("environment", "unknown")).strip().lower()
            meta = data.get("metadata") or {}
            if isinstance(meta, dict):
                dumped = json.dumps(meta, default=str)
                if len(dumped.encode("utf-8")) > 65536:
                    raise ValueError("Asset metadata exceeds maximum size limit of 64KB.")
                clean_meta = sanitize_metadata_secrets(meta)
                data["metadata"] = clean_meta
                sorted_meta = json.dumps(clean_meta, sort_keys=True, default=str)
            else:
                sorted_meta = "{}"
            if not data.get("fingerprint"):
                fp_raw = f"{asset_id}|{asset_type}|{version}|{env}|{sorted_meta}"
                data["fingerprint"] = hashlib.sha256(fp_raw.encode("utf-8")).hexdigest()
        return data

    @classmethod
    def create(
        cls,
        asset_id: str,
        asset_type: str,
        name: str,
        version: Optional[str] = None,
        environment: str = "unknown",
        source: AssetSource = AssetSource.USER_REGISTERED,
        status: AssetStatus = AssetStatus.ACTIVE,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        owner: Optional[str] = None,
        confidence: DiscoveryConfidence = DiscoveryConfidence.HIGH,
        provenance: Optional[List[AssetProvenance]] = None,
        first_seen: Optional[float] = None,
        last_seen: Optional[float] = None,
    ) -> "Asset":
        """Factory computing deterministic asset fingerprint."""
        now = time.time()
        f_seen = first_seen if first_seen is not None else now
        l_seen = last_seen if last_seen is not None else now

        clean_meta = sanitize_metadata_secrets(metadata or {})
        sorted_meta = json.dumps(clean_meta, sort_keys=True, default=str)
        fp_raw = f"{asset_id.strip()}|{asset_type.strip().lower()}|{version or ''}|{environment.strip().lower()}|{sorted_meta}"
        fp = hashlib.sha256(fp_raw.encode("utf-8")).hexdigest()

        return cls(
            id=asset_id,
            type=asset_type,
            name=name,
            version=version,
            environment=environment,
            source=source,
            status=status,
            metadata=clean_meta,
            first_seen=f_seen,
            last_seen=l_seen,
            tags=sorted(list(set(tags or []))),
            owner=owner,
            confidence=confidence,
            provenance=provenance or [],
            conflicts=[],
            fingerprint=fp,
        )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class DiscoveryResult(BaseModel):
    """Structured report returned upon completion of a discovery cycle."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    status: DiscoveryStatus = Field(..., description="Overall discovery execution status.")
    provider_results: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="Per-provider metrics.")
    assets_discovered: int = Field(default=0, ge=0, description="Total assets identified in run.")
    assets_added: int = Field(default=0, ge=0, description="New assets registered.")
    assets_changed: int = Field(default=0, ge=0, description="Existing assets with modified metadata.")
    assets_removed: int = Field(default=0, ge=0, description="Assets marked removed.")
    warnings: List[str] = Field(default_factory=list, description="Non-fatal warnings or provider errors.")
    duration_ms: float = Field(default=0.0, ge=0.0, description="Execution duration in milliseconds.")
    timestamp: float = Field(default_factory=time.time, description="Run completion timestamp.")

    @property
    def provider_statuses(self) -> Dict[str, str]:
        return {k: v.get("status", "unknown") for k, v in self.provider_results.items()}

    def summary(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "assets_discovered": self.assets_discovered,
            "assets_added": self.assets_added,
            "assets_changed": self.assets_changed,
            "assets_removed": self.assets_removed,
            "warnings_count": len(self.warnings),
            "duration_ms": round(self.duration_ms, 2),
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class InventorySnapshot(BaseModel):
    """Tamper-evident, serializable baseline snapshot of the asset inventory."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(default="1.0.0", description="Snapshot schema version.")
    inventory_version: str = Field(default="1.0", description="Inventory release version.")
    created_at: float = Field(default_factory=time.time, description="Creation epoch timestamp.")
    assets_count: int = Field(default=0, ge=0, description="Total count of assets captured.")
    assets: List[Asset] = Field(default_factory=list, description="Sorted list of captured assets.")
    sources: List[str] = Field(default_factory=list, description="Distinct discovery sources contributing.")
    graph_hash: str = Field(default="", description="Correlating KnowledgeGraph snapshot hash.")
    snapshot_hash: str = Field(default="", description="Cryptographic SHA-256 digest of canonical inventory.")

    @classmethod
    def create(
        cls,
        assets: List[Asset],
        sources: Optional[List[str]] = None,
        graph_hash: str = "",
        inventory_version: str = "1.0",
        timestamp: Optional[float] = None,
    ) -> "InventorySnapshot":
        now = timestamp if timestamp is not None else time.time()
        sorted_assets = sorted(assets, key=lambda a: a.id)
        distinct_sources = sorted(list(set(sources or [a.source.value for a in sorted_assets])))

        canonical = {
            "schema_version": "1.0.0",
            "inventory_version": inventory_version,
            "assets": [f"{a.id}:{a.fingerprint}" for a in sorted_assets],
            "sources": distinct_sources,
            "graph_hash": graph_hash,
        }
        digest = hashlib.sha256(json.dumps(canonical, sort_keys=True).encode("utf-8")).hexdigest()

        return cls(
            schema_version="1.0.0",
            inventory_version=inventory_version,
            created_at=now,
            assets_count=len(sorted_assets),
            assets=sorted_assets,
            sources=distinct_sources,
            graph_hash=graph_hash,
            snapshot_hash=digest,
        )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


class InventoryDiff(BaseModel):
    """Comparative delta between two inventory snapshots for drift tracking and governance."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    assets_added: List[str] = Field(default_factory=list, description="IDs of newly discovered assets.")
    assets_removed: List[str] = Field(default_factory=list, description="IDs of removed or decommissioned assets.")
    assets_changed: List[str] = Field(default_factory=list, description="IDs of assets with modified fingerprint/metadata.")
    relationships_changed: List[str] = Field(default_factory=list, description="Discovered graph relationship changes.")
    sources_changed: List[str] = Field(default_factory=list, description="New discovery sources observed.")
    configurations_changed: List[str] = Field(default_factory=list, description="Assets with configuration delta.")
    is_identical: bool = Field(default=False, description="True if inventories are identical.")

    @property
    def added_assets(self) -> List[str]:
        return self.assets_added

    @property
    def removed_assets(self) -> List[str]:
        return self.assets_removed

    @property
    def changed_assets(self) -> List[str]:
        return self.assets_changed

    def summary(self) -> Dict[str, Any]:
        return {
            "is_identical": self.is_identical,
            "assets_added_count": len(self.assets_added),
            "assets_removed_count": len(self.assets_removed),
            "assets_changed_count": len(self.assets_changed),
            "relationships_changed_count": len(self.relationships_changed),
            "configurations_changed_count": len(self.configurations_changed),
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class AssetExposure(BaseModel):
    """Holistic security posture and exposure view for an asset synthesized across Phases 32-34."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    asset_id: str = Field(..., description="Target asset ID.")
    asset_type: str = Field(..., description="Target asset type.")
    environment: str = Field(default="unknown", description="Operational environment.")
    sources: List[str] = Field(default_factory=list, description="Discovery sources confirming asset.")
    entry_points: List[str] = Field(default_factory=list, description="Reachable ingress channels.")
    tools: List[str] = Field(default_factory=list, description="Accessible tools or functions.")
    capabilities: List[str] = Field(default_factory=list, description="Granted capabilities.")
    attack_paths: List[Dict[str, Any]] = Field(default_factory=list, description="Candidate or tested attack paths.")
    security_controls: List[str] = Field(default_factory=list, description="Defensive controls protecting asset.")
    findings: List[Dict[str, Any]] = Field(default_factory=list, description="Vulnerability findings affecting asset.")
    assumptions: List[str] = Field(default_factory=list, description="Architectural assumptions recorded.")
    last_seen: float = Field(default_factory=time.time, description="Last seen epoch timestamp.")

    @property
    def accessible_tools(self) -> List[str]:
        return self.tools

    @property
    def protecting_controls(self) -> List[str]:
        return self.security_controls

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")
