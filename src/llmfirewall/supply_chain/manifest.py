"""Model manifest parser and lightweight security metadata registry."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from llmfirewall.core.exceptions import ConfigurationError
from llmfirewall.core.models import Finding, Severity, ThreatType
from llmfirewall.supply_chain.models import (
    ModelApprovalStatus,
    ModelArtifact,
    ModelFormat,
    ModelProvenance,
    ModelSourceType,
    ModelTrustLevel,
)
from llmfirewall.tools.path_security import validate_path_safety


def safe_load_yaml_or_json(content: str) -> Any:
    """Load JSON or YAML content safely."""
    try:
        return json.loads(content)
    except Exception:
        pass

    try:
        import yaml  # type: ignore
        return yaml.safe_load(content)
    except ImportError:
        raise ConfigurationError(
            "YAML manifest parsing requires 'PyYAML'. Please install PyYAML (`pip install PyYAML`) or use JSON format."
        )
    except Exception as exc:
        raise ConfigurationError(f"Failed to parse YAML manifest: {exc}")


class ModelManifest:
    """Represents a validated model inventory manifest (e.g. models.yaml)."""

    def __init__(
        self,
        version: str = "1.0",
        models: Optional[Dict[str, ModelArtifact]] = None,
        raw_metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.version = version
        self.models: Dict[str, ModelArtifact] = models or {}
        self.raw_metadata: Dict[str, Any] = raw_metadata or {}

    @classmethod
    def load_from_file(cls, file_path: Union[str, Path]) -> "ModelManifest":
        """Safely load and validate a model manifest YAML/JSON file without executing code."""
        path_str = str(file_path)
        path_finding = validate_path_safety(path_str)
        if path_finding:
            raise ConfigurationError(f"Manifest path rejected: {path_finding.description}")

        resolved = Path(path_str).resolve()
        if not resolved.is_file():
            raise FileNotFoundError(f"Model manifest file not found: {resolved}")

        with open(resolved, "r", encoding="utf-8") as f:
            content = f.read()

        data = safe_load_yaml_or_json(content)

        if not isinstance(data, dict):
            raise ConfigurationError("Model manifest must be a mapping/dictionary.")

        manifest_version = str(data.get("version", "1.0"))
        models_data = data.get("models", {})
        if not isinstance(models_data, dict):
            raise ConfigurationError("'models' entry in manifest must be a dictionary.")

        parsed_models: Dict[str, ModelArtifact] = {}
        for name, item in models_data.items():
            if not isinstance(item, dict):
                raise ConfigurationError(f"Model entry for '{name}' must be a dictionary.")

            version = str(item.get("version", "unknown"))
            sha256 = item.get("sha256")
            source = item.get("source", "unknown")
            fmt_str = item.get("format", "unknown")
            provider = item.get("provider")
            location = item.get("location")

            # Validate format enum
            try:
                fmt = ModelFormat(fmt_str.lower())
            except ValueError:
                fmt = ModelFormat.UNKNOWN

            parsed_models[name] = ModelArtifact(
                name=name,
                version=version,
                provider=provider,
                source_type=ModelSourceType.LOCAL_FILE if location else ModelSourceType.INTERNAL_REGISTRY,
                source=source,
                location=location,
                format=fmt,
                sha256=sha256,
            )

        return cls(version=manifest_version, models=parsed_models, raw_metadata=data)

    def get_model(self, name: str) -> Optional[ModelArtifact]:
        return self.models.get(name)


class ModelSecurityRegistry:
    """Lightweight security metadata registry for tracking model approvals, trust, and change detection."""

    def __init__(self) -> None:
        # Key: model_name -> ModelProvenance
        self._registry: Dict[str, ModelProvenance] = {}
        self._revocations: Dict[str, str] = {}  # model_name -> reason

    def register_approval(
        self,
        model_name: str,
        version: str,
        sha256: str,
        source: str = "internal",
        trust_level: ModelTrustLevel = ModelTrustLevel.TRUSTED,
        policy_version: Optional[str] = None,
    ) -> ModelProvenance:
        """Register an approved model artifact."""
        provenance = ModelProvenance(
            model_name=model_name,
            model_version=version,
            source=source,
            artifact_hash=sha256,
            trust_level=trust_level,
            approval_status=ModelApprovalStatus.APPROVED,
            policy_version=policy_version,
        )
        self._registry[model_name] = provenance
        return provenance

    def revoke_model(self, model_name: str, reason: str = "Revoked by security policy") -> None:
        """Mark a model as revoked."""
        self._revocations[model_name] = reason
        if model_name in self._registry:
            prev = self._registry[model_name]
            self._registry[model_name] = ModelProvenance(
                model_name=prev.model_name,
                model_version=prev.model_version,
                source=prev.source,
                artifact_hash=prev.artifact_hash,
                trust_level=ModelTrustLevel.UNTRUSTED,
                approval_status=ModelApprovalStatus.REVOKED,
                policy_version=prev.policy_version,
            )

    def is_revoked(self, model_name: str) -> bool:
        return model_name in self._revocations

    def get_provenance(self, model_name: str) -> Optional[ModelProvenance]:
        return self._registry.get(model_name)

    def detect_model_change(self, artifact: ModelArtifact) -> Optional[Finding]:
        """Detect if the same model name and version has a differing hash (critical supply-chain signal)."""
        existing = self._registry.get(artifact.name)
        if not existing:
            return None

        if existing.model_version == artifact.version:
            if existing.artifact_hash and artifact.sha256:
                if existing.artifact_hash.lower() != artifact.sha256.lower():
                    return Finding(
                        detector_name="model_change_detector",
                        threat_type=ThreatType.POLICY_VIOLATION,
                        description=(
                            f"Model artifact change detected for '{artifact.name}' (v{artifact.version}): "
                            f"registered hash {existing.artifact_hash} != new hash {artifact.sha256}."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=1.0,
                        metadata={
                            "violation": "MODEL_ARTIFACT_CHANGED",
                            "model": artifact.name,
                            "version": artifact.version,
                            "previous_hash": existing.artifact_hash,
                            "current_hash": artifact.sha256,
                        },
                    )

        return None
