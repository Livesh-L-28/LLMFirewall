"""Context manager guard and model loader wrapper to enforce security policies prior to model loading."""

from contextlib import contextmanager
from typing import Any, Callable, Generator, List, Optional, Union

from llmfirewall.core.exceptions import BlockedPromptError, LLMFirewallError
from llmfirewall.core.models import Action
from llmfirewall.supply_chain.manifest import ModelSecurityRegistry
from llmfirewall.supply_chain.models import (
    ModelArtifact,
    ModelFormat,
    ModelProvenance,
    ModelSecurityDecision,
    ModelSourceType,
    ModelTrustLevel,
)
from llmfirewall.supply_chain.verifier import ModelVerifier, detect_model_format


class ModelLoadingGuard:
    """Provides guarded execution and policy evaluation before an ML model is loaded into memory."""

    def __init__(
        self,
        verifier: Optional[ModelVerifier] = None,
        registry: Optional[ModelSecurityRegistry] = None,
    ) -> None:
        self.verifier = verifier or ModelVerifier()
        self.registry = registry or ModelSecurityRegistry()

    def evaluate(
        self,
        model_name: str,
        path_or_location: Optional[str] = None,
        version: str = "unknown",
        expected_hash: Optional[str] = None,
        expected_version: Optional[str] = None,
        source: str = "local",
        format_type: Optional[ModelFormat] = None,
    ) -> ModelSecurityDecision:
        """Perform comprehensive pre-load verification."""
        # Check revocation in registry
        if self.registry.is_revoked(model_name):
            from llmfirewall.core.models import Finding, Severity, ThreatType
            finding = Finding(
                detector_name="model_registry",
                threat_type=ThreatType.POLICY_VIOLATION,
                description=f"Model '{model_name}' has been explicitly revoked.",
                severity=Severity.CRITICAL,
                confidence=1.0,
                metadata={"violation": "MODEL_REVOKED"},
            )
            return ModelSecurityDecision(
                action=Action.BLOCK,
                model=model_name,
                version=version,
                source=source,
                hash_status=self.verifier.verify_artifact(path_or_location).status if path_or_location else None,
                format=format_type or ModelFormat.UNKNOWN,
                findings=[finding],
                policy="revocation_policy",
            )

        fmt = format_type
        if not fmt and path_or_location:
            fmt = detect_model_format(path_or_location)

        src_type = ModelSourceType.LOCAL_FILE if path_or_location else ModelSourceType.UNKNOWN
        artifact = ModelArtifact(
            name=model_name,
            version=version,
            source_type=src_type,
            source=source,
            location=path_or_location,
            format=fmt or ModelFormat.UNKNOWN,
            sha256=expected_hash,
        )

        # Check for model change / drift against registry
        change_finding = self.registry.detect_model_change(artifact)
        decision = self.verifier.evaluate_model(
            artifact=artifact,
            expected_version=expected_version,
            expected_hash=expected_hash,
        )

        if change_finding:
            decision = ModelSecurityDecision(
                action=Action.BLOCK,
                model=decision.model,
                version=decision.version,
                source=decision.source,
                hash_status=decision.hash_status,
                format=decision.format,
                findings=[change_finding] + decision.findings,
                policy=decision.policy,
            )

        return decision

    @contextmanager
    def guard(
        self,
        model_name: str,
        path_or_location: Optional[str] = None,
        version: str = "unknown",
        expected_hash: Optional[str] = None,
        expected_version: Optional[str] = None,
        source: str = "local",
        format_type: Optional[ModelFormat] = None,
    ) -> Generator[ModelSecurityDecision, None, None]:
        """Context manager protecting the execution of model-loading code blocks.
        
        Example:
            with guard.guard("llama-3", path="/models/llama3.safetensors", expected_hash="..."):
                model = load_model("/models/llama3.safetensors")
        """
        decision = self.evaluate(
            model_name=model_name,
            path_or_location=path_or_location,
            version=version,
            expected_hash=expected_hash,
            expected_version=expected_version,
            source=source,
            format_type=format_type,
        )

        if decision.action == Action.BLOCK:
            descriptions = [f.description for f in decision.findings]
            raise BlockedPromptError(
                f"Model loading blocked by supply-chain policy: {'; '.join(descriptions)}"
            )

        yield decision
