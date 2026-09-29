"""Public exports for Phase 28: AI Supply-Chain & Model Security."""

from llmfirewall.supply_chain.dependencies import (
    DependencyScanner,
    OfflineVulnerabilityProvider,
    VulnerabilityProvider,
)
from llmfirewall.supply_chain.guard import ModelLoadingGuard
from llmfirewall.supply_chain.integrity import (
    IntegrityManager,
    hash_configuration,
    hash_policy_artifact,
    hash_prompt_artifact,
    sanitize_config_dict,
)
from llmfirewall.supply_chain.manifest import (
    ModelManifest,
    ModelSecurityRegistry,
)
from llmfirewall.supply_chain.models import (
    ConfigArtifact,
    DependencyArtifact,
    DependencyScope,
    DependencySourceType,
    DeploymentMetadata,
    IntegrityResult,
    IntegrityStatus,
    ModelApprovalStatus,
    ModelArtifact,
    ModelFormat,
    ModelProvenance,
    ModelSecurityDecision,
    ModelSourceType,
    ModelTrustLevel,
    PolicyArtifact,
    PromptArtifact,
    SecuritySnapshot,
    SnapshotDiff,
    VulnerabilityFinding,
)
from llmfirewall.supply_chain.verifier import (
    HASH_CHUNK_SIZE,
    ModelVerifier,
    compute_streaming_hash,
    detect_model_format,
    is_unsafe_serialization,
)

__all__ = [
    # Models & Enums
    "ModelSourceType",
    "ModelTrustLevel",
    "ModelApprovalStatus",
    "ModelFormat",
    "IntegrityStatus",
    "DependencyScope",
    "DependencySourceType",
    "ModelArtifact",
    "ModelProvenance",
    "IntegrityResult",
    "ModelSecurityDecision",
    "DependencyArtifact",
    "VulnerabilityFinding",
    "ConfigArtifact",
    "PromptArtifact",
    "PolicyArtifact",
    "DeploymentMetadata",
    "SnapshotDiff",
    "SecuritySnapshot",
    # Verifiers & Guards
    "ModelVerifier",
    "ModelLoadingGuard",
    "compute_streaming_hash",
    "detect_model_format",
    "is_unsafe_serialization",
    "HASH_CHUNK_SIZE",
    # Manifest & Registry
    "ModelManifest",
    "ModelSecurityRegistry",
    # Dependencies
    "DependencyScanner",
    "VulnerabilityProvider",
    "OfflineVulnerabilityProvider",
    # Integrity
    "IntegrityManager",
    "hash_configuration",
    "hash_policy_artifact",
    "hash_prompt_artifact",
    "sanitize_config_dict",
]
