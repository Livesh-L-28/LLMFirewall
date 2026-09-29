"""Release and evidence manifests for Phase 31: AI Security Governance."""

import hashlib
import json
import time
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall._version import __version__
from llmfirewall.governance.decisions import GovernanceDecision


class EvidenceArtifactRecord(BaseModel):
    """Immutable hash record of a governance evidence artifact."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_name: str = Field(..., description="Logical name of evidence artifact.")
    sha256: str = Field(..., description="Cryptographic SHA-256 hash of artifact content.")
    timestamp: float = Field(default_factory=time.time, description="Collection timestamp.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe metadata.")


class EvidenceManifest(BaseModel):
    """Machine-readable manifest cataloging all security evidence supporting a release decision.
    
    Security Invariant:
    Zero Secret Logging: Contains artifact identifiers and SHA-256 hashes, never sensitive text or tokens.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(default="1", description="Evidence manifest schema version.")
    release_id: str = Field(..., description="Unique release identifier.")
    decision: GovernanceDecision = Field(..., description="Governance decision reached based on this evidence.")
    evidence: List[EvidenceArtifactRecord] = Field(default_factory=list, description="Indexed evidence artifact hashes.")
    retention_days: int = Field(default=90, description="Configured compliance retention period in days.")
    generated_at: float = Field(default_factory=time.time, description="Generation epoch timestamp.")

    def to_json(self) -> str:
        return json.dumps(self.model_dump(mode="json"), indent=2, sort_keys=True)


class SecurityReleaseManifest(BaseModel):
    """Formal security release manifest capturing all evaluated security state for a release candidate.
    
    Invariants:
    1. Comprehensive Cryptographic Lineage: Records model, prompt, policy, configuration, and dependency hashes.
    2. Zero Secret Infiltration: Never includes API keys, tokens, or plaintext secrets.
    3. Reproducibility: Includes manifest_hash verifying exact governance inputs and outputs.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    release_id: str = Field(default_factory=lambda: f"REL-{uuid.uuid4().hex[:8].upper()}")
    application_version: str = Field(default="unknown", description="Application or service version under evaluation.")
    llmfirewall_version: str = Field(default=__version__, description="LLMFirewall package version.")
    model: Dict[str, Any] = Field(default_factory=dict, description="Verified model identity (name, version, hash, provider).")
    prompt_hash: Optional[str] = Field(default=None, description="SHA-256 hash of system prompts.")
    policy_hash: Optional[str] = Field(default=None, description="SHA-256 hash of evaluated governance policy.")
    configuration_hash: Optional[str] = Field(default=None, description="SHA-256 hash of security configuration.")
    dependency_hash: Optional[str] = Field(default=None, description="SHA-256 hash of software dependencies.")
    test_suite_version: Optional[str] = Field(default=None, description="Version of security test suite.")
    baseline_id: Optional[str] = Field(default=None, description="Correlating security baseline ID.")
    timestamp: float = Field(default_factory=time.time, description="Release evaluation epoch timestamp.")
    decision: GovernanceDecision = Field(default=GovernanceDecision.NOT_EVALUATED, description="Final governance decision.")
    gate_summary: Dict[str, Any] = Field(default_factory=dict, description="Passed, failed, and review gate tallies.")
    manifest_hash: str = Field(default="", description="Cryptographic SHA-256 digest of release manifest parameters.")

    @classmethod
    def create(
        cls,
        release_id: Optional[str] = None,
        application_version: str = "unknown",
        model: Optional[Dict[str, Any]] = None,
        prompt_hash: Optional[str] = None,
        policy_hash: Optional[str] = None,
        configuration_hash: Optional[str] = None,
        dependency_hash: Optional[str] = None,
        test_suite_version: Optional[str] = None,
        baseline_id: Optional[str] = None,
        decision: GovernanceDecision = GovernanceDecision.NOT_EVALUATED,
        gate_summary: Optional[Dict[str, Any]] = None,
        timestamp: Optional[float] = None,
    ) -> "SecurityReleaseManifest":
        """Factory computing the deterministic manifest_hash."""
        rel_id = release_id or f"REL-{uuid.uuid4().hex[:8].upper()}"
        now = timestamp if timestamp is not None else time.time()
        mod_dict = model or {}
        g_sum = gate_summary or {}

        summary = {
            "release_id": rel_id,
            "application_version": application_version,
            "llmfirewall_version": __version__,
            "model": mod_dict,
            "prompt_hash": prompt_hash or "",
            "policy_hash": policy_hash or "",
            "configuration_hash": configuration_hash or "",
            "dependency_hash": dependency_hash or "",
            "test_suite_version": test_suite_version or "",
            "baseline_id": baseline_id or "",
            "decision": decision.value,
            "gate_summary": g_sum,
            "timestamp": round(now, 4),
        }
        serialized = json.dumps(summary, sort_keys=True)
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        return cls(
            release_id=rel_id,
            application_version=application_version,
            llmfirewall_version=__version__,
            model=mod_dict,
            prompt_hash=prompt_hash,
            policy_hash=policy_hash,
            configuration_hash=configuration_hash,
            dependency_hash=dependency_hash,
            test_suite_version=test_suite_version,
            baseline_id=baseline_id,
            timestamp=now,
            decision=decision,
            gate_summary=g_sum,
            manifest_hash=digest,
        )

    def to_json(self) -> str:
        return json.dumps(self.model_dump(mode="json"), indent=2, sort_keys=True)
