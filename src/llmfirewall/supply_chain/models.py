"""Data models and enums for Phase 28: AI Supply-Chain & Model Security."""

from enum import Enum
import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.models import Action, Finding, Severity


class ModelSourceType(str, Enum):
    """Generic model source classifications."""
    LOCAL_FILE = "LOCAL_FILE"
    PACKAGE = "PACKAGE"
    INTERNAL_REGISTRY = "INTERNAL_REGISTRY"
    REMOTE_REGISTRY = "REMOTE_REGISTRY"
    OBJECT_STORAGE = "OBJECT_STORAGE"
    HTTP = "HTTP"
    API_PROVIDER = "API_PROVIDER"
    UNKNOWN = "UNKNOWN"


class ModelTrustLevel(str, Enum):
    """Model trust classifications determined by policy."""
    TRUSTED = "TRUSTED"
    CONTROLLED = "CONTROLLED"
    EXTERNAL = "EXTERNAL"
    UNTRUSTED = "UNTRUSTED"
    UNKNOWN = "UNKNOWN"


class ModelApprovalStatus(str, Enum):
    """Approval lifecycle state for a model artifact."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REVOKED = "REVOKED"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


class ModelFormat(str, Enum):
    """Model serialization format classification."""
    SAFETENSORS = "safetensors"
    ONNX = "onnx"
    GGUF = "gguf"
    TORCHSCRIPT = "torchscript"
    PICKLE = "pickle"
    TORCH_CHECKPOINT = "torch_checkpoint"
    JOBLIB = "joblib"
    FRAMEWORK_SPECIFIC = "framework-specific"
    UNKNOWN = "unknown"


class IntegrityStatus(str, Enum):
    """Cryptographic integrity verification result."""
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"


class DependencyScope(str, Enum):
    """Dependency relationship scope."""
    DIRECT = "DIRECT"
    TRANSITIVE = "TRANSITIVE"
    UNKNOWN = "UNKNOWN"


class DependencySourceType(str, Enum):
    """Origin of a Python package dependency."""
    PYPI = "PyPI"
    PRIVATE_REGISTRY = "private_registry"
    LOCAL_WHEEL = "local_wheel"
    EDITABLE_INSTALL = "editable_install"
    UNKNOWN = "unknown"


class ModelArtifact(BaseModel):
    """Normalized model artifact representation."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(..., description="Unique model identifier or name.")
    version: str = Field(default="unknown", description="Model version or tag.")
    provider: Optional[str] = Field(default=None, description="Model provider or vendor.")
    source_type: ModelSourceType = Field(default=ModelSourceType.UNKNOWN, description="Source classification.")
    source: str = Field(default="unknown", description="Source location, URI, or repository name.")
    location: Optional[str] = Field(default=None, description="Local path or endpoint URI (credentials excluded).")
    format: ModelFormat = Field(default=ModelFormat.UNKNOWN, description="Model serialization format.")
    size_bytes: Optional[int] = Field(default=None, description="Artifact size in bytes if local.")
    sha256: Optional[str] = Field(default=None, description="Cryptographic SHA-256 digest.")
    sha512: Optional[str] = Field(default=None, description="Optional SHA-512 digest.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe auxiliary metadata (no secrets).")


class ModelProvenance(BaseModel):
    """Provenance and lineage tracking record for a loaded/evaluated model."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    model_name: str = Field(..., description="Name of the model.")
    model_version: str = Field(..., description="Version of the model.")
    provider: Optional[str] = Field(default=None, description="Model provider.")
    source: str = Field(default="unknown", description="Model source identifier.")
    download_location: Optional[str] = Field(default=None, description="Safe path or URI without credentials.")
    artifact_hash: Optional[str] = Field(default=None, description="Verified cryptographic hash (e.g. SHA-256).")
    loaded_at: float = Field(default_factory=time.time, description="Timestamp when model was loaded/verified.")
    scanner_version: str = Field(default="0.1.0", description="Version of the supply-chain scanner.")
    policy_version: Optional[str] = Field(default=None, description="Version or hash of the approving policy.")
    trust_level: ModelTrustLevel = Field(default=ModelTrustLevel.UNKNOWN, description="Assigned policy trust level.")
    approval_status: ModelApprovalStatus = Field(default=ModelApprovalStatus.UNKNOWN, description="Registry approval state.")


class IntegrityResult(BaseModel):
    """Result of an artifact or asset cryptographic integrity check."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    status: IntegrityStatus = Field(..., description="Verification status.")
    algorithm: str = Field(default="sha256", description="Hash algorithm used.")
    expected_hash: Optional[str] = Field(default=None, description="Hash expected by manifest/policy.")
    actual_hash: Optional[str] = Field(default=None, description="Hash computed from the artifact.")
    details: Optional[str] = Field(default=None, description="Safe explanatory status message.")


class ModelSecurityDecision(BaseModel):
    """Security evaluation decision for a model artifact."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    action: Action = Field(..., description="ALLOW, WARN, BLOCK, or QUARANTINE.")
    model: str = Field(..., description="Model name.")
    version: str = Field(..., description="Model version.")
    source: str = Field(..., description="Model source.")
    hash_status: IntegrityStatus = Field(..., description="Integrity status.")
    format: ModelFormat = Field(..., description="Serialization format.")
    findings: List[Finding] = Field(default_factory=list, description="Security findings emitted.")
    policy: str = Field(default="default", description="Evaluated policy name/rule.")
    trace_id: Optional[str] = Field(default=None, description="Observability trace ID.")


class DependencyArtifact(BaseModel):
    """Normalized dependency package metadata."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(..., description="Package name.")
    version: str = Field(..., description="Installed package version.")
    source: DependencySourceType = Field(default=DependencySourceType.UNKNOWN, description="Package origin.")
    scope: DependencyScope = Field(default=DependencyScope.UNKNOWN, description="Direct or transitive.")
    installed_location: Optional[str] = Field(default=None, description="Installed path on filesystem.")
    sha256: Optional[str] = Field(default=None, description="Optional package artifact hash.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe dependency metadata.")


class VulnerabilityFinding(BaseModel):
    """Normalized vulnerability intelligence record from an external provider."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    package: str = Field(..., description="Vulnerable package name.")
    version: str = Field(..., description="Affected package version.")
    identifier: str = Field(..., description="Vulnerability ID (e.g. CVE-2023-XXXXX, GHSA-XXXX).")
    severity: Severity = Field(default=Severity.MEDIUM, description="Normalized severity.")
    summary: Optional[str] = Field(default=None, description="Safe summary of the vulnerability.")
    source: str = Field(default="provider", description="Vulnerability database source.")
    published_at: Optional[str] = Field(default=None, description="Date/timestamp published.")
    fixed_versions: List[str] = Field(default_factory=list, description="Fixed package versions.")


class ConfigArtifact(BaseModel):
    """Deterministic, secret-safe configuration artifact representation."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    config_type: str = Field(..., description="Type of configuration (e.g. 'firewall', 'model_hyperparameters').")
    sha256: str = Field(..., description="Deterministic cryptographic digest of sanitized config.")
    source: str = Field(default="FILE", description="Config source: FILE, ENVIRONMENT, CLI, DATABASE, DEFAULT.")
    keys_present: List[str] = Field(default_factory=list, description="List of non-secret config keys.")
    timestamp: float = Field(default_factory=time.time, description="Timestamp recorded.")


class PromptArtifact(BaseModel):
    """Normalized representation of a protected system/guardrail prompt."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(..., description="Prompt identifier (e.g. 'assistant_system').")
    version: str = Field(default="1", description="Prompt template version.")
    sha256: str = Field(..., description="SHA-256 digest of prompt template content.")
    length_chars: int = Field(..., description="Length of prompt content in characters.")
    loaded_at: float = Field(default_factory=time.time, description="Timestamp recorded.")


class PolicyArtifact(BaseModel):
    """Protected representation of an active security policy."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    policy_id: str = Field(..., description="Policy identifier or filename.")
    version: str = Field(default="1", description="Policy version.")
    sha256: str = Field(..., description="Deterministic SHA-256 digest of policy rules.")
    loaded_at: float = Field(default_factory=time.time, description="Timestamp policy loaded.")


class DeploymentMetadata(BaseModel):
    """Deployment runtime context and container image metadata."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    application_version: str = Field(default="0.1.0", description="Application release version.")
    container_image: Optional[str] = Field(default=None, description="Container image repository.")
    container_tag: Optional[str] = Field(default=None, description="Container image tag.")
    container_digest: Optional[str] = Field(default=None, description="Container image SHA-256 digest.")
    deployment_id: Optional[str] = Field(default=None, description="Unique deployment identifier.")


class SnapshotDiff(BaseModel):
    """Comparison diff between two SecuritySnapshots."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    models_added: List[str] = Field(default_factory=list)
    models_removed: List[str] = Field(default_factory=list)
    models_changed: List[str] = Field(default_factory=list)

    dependencies_added: List[str] = Field(default_factory=list)
    dependencies_removed: List[str] = Field(default_factory=list)
    dependencies_changed: List[str] = Field(default_factory=list)

    configs_changed: List[str] = Field(default_factory=list)
    policies_changed: List[str] = Field(default_factory=list)
    prompts_changed: List[str] = Field(default_factory=list)

    is_identical: bool = Field(default=True, description="Whether snapshots are strictly identical.")


class SecuritySnapshot(BaseModel):
    """Full AI supply-chain security snapshot representing current state."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(default="1", description="Snapshot schema version.")
    timestamp: float = Field(default_factory=time.time, description="Timestamp of snapshot creation.")
    deployment: DeploymentMetadata = Field(default_factory=DeploymentMetadata, description="Deployment metadata.")
    models: List[ModelArtifact] = Field(default_factory=list, description="Model artifacts.")
    dependencies: List[DependencyArtifact] = Field(default_factory=list, description="Dependency artifacts.")
    configurations: List[ConfigArtifact] = Field(default_factory=list, description="Config artifacts.")
    policies: List[PolicyArtifact] = Field(default_factory=list, description="Policy artifacts.")
    prompts: List[PromptArtifact] = Field(default_factory=list, description="Prompt artifacts.")
    snapshot_hash: str = Field(default="", description="Deterministic fingerprint of entire snapshot.")

    @classmethod
    def create(
        cls,
        deployment: Optional[DeploymentMetadata] = None,
        models: Optional[List[ModelArtifact]] = None,
        dependencies: Optional[List[DependencyArtifact]] = None,
        configurations: Optional[List[ConfigArtifact]] = None,
        policies: Optional[List[PolicyArtifact]] = None,
        prompts: Optional[List[PromptArtifact]] = None,
    ) -> "SecuritySnapshot":
        """Factory method computing the deterministic snapshot_hash."""
        dep = deployment or DeploymentMetadata()
        mod_list = sorted(models or [], key=lambda m: (m.name, m.version))
        deps_list = sorted(dependencies or [], key=lambda d: (d.name, d.version))
        cfg_list = sorted(configurations or [], key=lambda c: c.config_type)
        pol_list = sorted(policies or [], key=lambda p: p.policy_id)
        prm_list = sorted(prompts or [], key=lambda pr: pr.name)

        # Deterministic payload serialization
        summary = {
            "app_version": dep.application_version,
            "container_digest": dep.container_digest or "",
            "models": [(m.name, m.version, m.sha256 or "") for m in mod_list],
            "dependencies": [(d.name, d.version, d.sha256 or "") for d in deps_list],
            "configs": [(c.config_type, c.sha256) for c in cfg_list],
            "policies": [(p.policy_id, p.version, p.sha256) for p in pol_list],
            "prompts": [(pr.name, pr.version, pr.sha256) for pr in prm_list],
        }
        serialized = json.dumps(summary, sort_keys=True)
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        return cls(
            schema_version="1",
            timestamp=time.time(),
            deployment=dep,
            models=mod_list,
            dependencies=deps_list,
            configurations=cfg_list,
            policies=pol_list,
            prompts=prm_list,
            snapshot_hash=digest,
        )

    def diff(self, other: "SecuritySnapshot") -> SnapshotDiff:
        """Compare this snapshot with another snapshot to detect drift and additions/removals."""
        # Models
        self_m = {m.name: m for m in self.models}
        oth_m = {m.name: m for m in other.models}
        m_added = [name for name in oth_m if name not in self_m]
        m_removed = [name for name in self_m if name not in oth_m]
        m_changed = [
            name for name in self_m
            if name in oth_m and (self_m[name].version != oth_m[name].version or self_m[name].sha256 != oth_m[name].sha256)
        ]

        # Dependencies
        self_d = {d.name: d for d in self.dependencies}
        oth_d = {d.name: d for d in other.dependencies}
        d_added = [name for name in oth_d if name not in self_d]
        d_removed = [name for name in self_d if name not in oth_d]
        d_changed = [
            name for name in self_d
            if name in oth_d and (self_d[name].version != oth_d[name].version or self_d[name].sha256 != oth_d[name].sha256)
        ]

        # Configurations
        self_c = {c.config_type: c.sha256 for c in self.configurations}
        oth_c = {c.config_type: c.sha256 for c in other.configurations}
        c_changed = [k for k in self_c if k in oth_c and self_c[k] != oth_c[k]]
        c_changed.extend([k for k in oth_c if k not in self_c])
        c_changed.extend([k for k in self_c if k not in oth_c])

        # Policies
        self_p = {p.policy_id: p.sha256 for p in self.policies}
        oth_p = {p.policy_id: p.sha256 for p in other.policies}
        p_changed = [k for k in self_p if k in oth_p and self_p[k] != oth_p[k]]
        p_changed.extend([k for k in oth_p if k not in self_p])
        p_changed.extend([k for k in self_p if k not in oth_p])

        # Prompts
        self_pr = {pr.name: pr.sha256 for pr in self.prompts}
        oth_pr = {pr.name: pr.sha256 for pr in other.prompts}
        pr_changed = [k for k in self_pr if k in oth_pr and self_pr[k] != oth_pr[k]]
        pr_changed.extend([k for k in oth_pr if k not in self_pr])
        pr_changed.extend([k for k in self_pr if k not in oth_pr])

        is_id = (
            not m_added and not m_removed and not m_changed
            and not d_added and not d_removed and not d_changed
            and not c_changed and not p_changed and not pr_changed
            and self.snapshot_hash == other.snapshot_hash
        )

        return SnapshotDiff(
            models_added=sorted(m_added),
            models_removed=sorted(m_removed),
            models_changed=sorted(m_changed),
            dependencies_added=sorted(d_added),
            dependencies_removed=sorted(d_removed),
            dependencies_changed=sorted(d_changed),
            configs_changed=sorted(list(set(c_changed))),
            policies_changed=sorted(list(set(p_changed))),
            prompts_changed=sorted(list(set(pr_changed))),
            is_identical=is_id,
        )
