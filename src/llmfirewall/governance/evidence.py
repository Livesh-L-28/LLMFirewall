"""Security evidence model and collection containers for Phase 31."""

import hashlib
import json
import time
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.eval.models import SecurityEvaluationReport, SecurityTestResult
from llmfirewall.governance.decisions import GovernanceDecision
from llmfirewall.governance.findings import GovernanceFinding
from llmfirewall.governance.manifest import EvidenceArtifactRecord, EvidenceManifest
from llmfirewall.supply_chain.models import SecuritySnapshot, SnapshotDiff


class SecurityEvidence(BaseModel):
    """Unified container for all security evidence collected across the evaluation lifecycle.
    
    Invariants:
    1. Comprehensive Multi-Phase Ingestion: Ingests Phase 27 (RAG), Phase 28 (Supply Chain),
       Phase 29 (Agent Capabilities), and Phase 30 (Continuous Security Testing).
    2. Evidence Integrity: Calculates deterministic SHA-256 digests for each evidence segment.
    3. Safe Serialization: Excludes raw confidential texts and tokens.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    release_id: str = Field(default_factory=lambda: f"EVID-{uuid.uuid4().hex[:8].upper()}")
    evaluation_report: Optional[SecurityEvaluationReport] = Field(default=None, description="Phase 30 evaluation report.")
    test_results: List[SecurityTestResult] = Field(default_factory=list, description="Raw security test results.")
    snapshot: Optional[SecuritySnapshot] = Field(default=None, description="Phase 28 security snapshot.")
    snapshot_diff: Optional[SnapshotDiff] = Field(default=None, description="Drift diff against baseline snapshot.")
    model_identity: Optional[Dict[str, Any]] = Field(default=None, description="Model name, version, hash, provider.")
    prompt_hash: Optional[str] = Field(default=None, description="SHA-256 digest of system prompts.")
    policy_version: Optional[str] = Field(default=None, description="Security policy version.")
    policy_hash: Optional[str] = Field(default=None, description="SHA-256 digest of policy rules.")
    configuration_hash: Optional[str] = Field(default=None, description="SHA-256 digest of firewall config.")
    dependency_hash: Optional[str] = Field(default=None, description="SHA-256 digest of dependencies.")
    agent_capabilities: List[str] = Field(default_factory=list, description="Active agent capabilities.")
    rag_provenance_records: List[Dict[str, Any]] = Field(default_factory=list, description="RAG document provenance records.")
    findings: List[GovernanceFinding] = Field(default_factory=list, description="Normalized findings extracted from tests or scans.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe operational metadata.")
    collected_at: float = Field(default_factory=time.time, description="Collection epoch timestamp.")

    def artifact_hashes(self) -> Dict[str, str]:
        """Compute SHA-256 digests for all present evidence artifacts."""
        hashes: Dict[str, str] = {}

        if self.evaluation_report is not None:
            raw = json.dumps(self.evaluation_report.model_dump(mode="json"), sort_keys=True)
            hashes["evaluation_report"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()

        if self.test_results:
            raw = json.dumps([t.model_dump(mode="json") for t in self.test_results], sort_keys=True)
            hashes["test_results"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()

        if self.snapshot is not None:
            hashes["snapshot"] = self.snapshot.snapshot_hash

        if self.model_identity:
            raw = json.dumps(self.model_identity, sort_keys=True)
            hashes["model_identity"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()

        if self.prompt_hash:
            hashes["prompt"] = self.prompt_hash

        if self.policy_hash:
            hashes["policy"] = self.policy_hash

        if self.configuration_hash:
            hashes["configuration"] = self.configuration_hash

        if self.dependency_hash:
            hashes["dependency"] = self.dependency_hash

        if self.agent_capabilities:
            raw = json.dumps(sorted(self.agent_capabilities))
            hashes["agent_capabilities"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()

        if self.findings:
            raw = json.dumps([f.fingerprint for f in self.findings], sort_keys=True)
            hashes["findings"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()

        return hashes

    def to_evidence_manifest(
        self,
        decision: GovernanceDecision,
        retention_days: int = 90,
    ) -> EvidenceManifest:
        """Convert evidence container into an EvidenceManifest."""
        art_hashes = self.artifact_hashes()
        records = [
            EvidenceArtifactRecord(
                artifact_name=name,
                sha256=digest,
                timestamp=self.collected_at,
            )
            for name, digest in sorted(art_hashes.items())
        ]
        return EvidenceManifest(
            schema_version="1",
            release_id=self.release_id,
            decision=decision,
            evidence=records,
            retention_days=retention_days,
            generated_at=time.time(),
        )
