"""Phase 62 — Advanced Memory Security.

Provides memory provenance tracking, cryptographic content digests, trust labels,
strict multi-tenant/session boundaries, and sleeper/indirect memory poisoning detection.
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.models import Action, Finding, Severity, ThreatType
from llmfirewall.detectors.prompt_injection import PromptInjectionDetector
from llmfirewall.rag.models import ContextItem, SourceProvenance
from llmfirewall.runtime.models import TrustLevel


class MemoryTrustLabel(str, Enum):
    """Trust tier of an agent memory record."""
    TRUSTED = "TRUSTED"          # Authoritative system instructions or confirmed safe memories
    VERIFIED = "VERIFIED"        # User or tool memory vetted by security detectors
    UNTRUSTED = "UNTRUSTED"      # Raw, unvetted external context or unauthenticated input
    QUARANTINED = "QUARANTINED"  # Flagged memory isolated from agent context


class MemoryProvenanceRecord(BaseModel):
    """Cryptographically anchored provenance metadata for stored agent memories."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    memory_id: str = Field(default_factory=lambda: f"mem-{uuid.uuid4().hex[:10]}")
    session_id: str = Field(..., description="Owning session identifier")
    tenant_id: Optional[str] = Field(default=None, description="Owning tenant identifier if multi-tenant")
    author_role: str = Field(default="assistant", description="Originating role: user, assistant, system, tool")
    trust_label: MemoryTrustLabel = Field(default=MemoryTrustLabel.VERIFIED)
    content_hash: str = Field(..., description="SHA-256 digest of original memory content")
    created_at: float = Field(default_factory=time.time)
    last_accessed_at: float = Field(default_factory=time.time)
    lineage: List[str] = Field(default_factory=list, description="Source identifiers forming memory lineage")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe auxiliary metadata")

    @staticmethod
    def compute_hash(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()


class MemoryPoisoningAssessment(BaseModel):
    """Outcome of evaluating a memory item for poisoning or sleeper attacks."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    memory_id: str
    is_poisoned: bool = Field(default=False)
    poison_type: Optional[str] = Field(default=None, description="Classification: SLEEPER_INJECTION, AUTHORITY_OVERRIDE, DATA_POISON")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    findings: List[Finding] = Field(default_factory=list)
    quarantine_recommended: bool = Field(default=False)
    reason: str = Field(default="Memory evaluated safe.")


class MemoryPoisoningDetector:
    """Detects stealth prompt injection, delayed sleeper commands, and persistent memory poisoning."""

    def __init__(
        self,
        injection_detector: Optional[PromptInjectionDetector] = None,
    ) -> None:
        self.injection_detector = injection_detector or PromptInjectionDetector()
        # Common sleeper injection triggers (instructions conditioned on future events)
        self._sleeper_phrases = [
            "in future turns",
            "from now on, whenever",
            "if the user asks about",
            "when you are asked to",
            "as a secret instruction",
            "never tell the user that",
            "system override directive",
            "pretend you are in developer mode",
            "silently exfiltrate",
        ]

    def inspect_memory(
        self,
        content: str,
        memory_id: str = "mem-unknown",
    ) -> MemoryPoisoningAssessment:
        """Inspect memory text for poisoning attacks, sleeper commands, and instruction overrides."""
        findings: List[Finding] = []
        is_poisoned = False
        poison_type = None
        confidence = 0.0

        lower_text = content.lower()

        # 1. Check sleeper injection phrases
        for phrase in self._sleeper_phrases:
            if phrase in lower_text:
                is_poisoned = True
                poison_type = "SLEEPER_INJECTION"
                confidence = 0.90
                findings.append(
                    Finding(
                        detector_name="memory_poisoning_detector",
                        threat_type=ThreatType.PROMPT_INJECTION,
                        severity=Severity.HIGH,
                        confidence=confidence,
                        description=f"Sleeper instruction trigger detected in memory: '{phrase}'",
                        matched_text=phrase,
                    )
                )
                break

        # 2. Check general prompt injection patterns
        if not is_poisoned and len(content) > 10:
            inj_findings = self.injection_detector.detect(
                content,
                context={"source_type": "memory", "direction": "input"},
            )
            if inj_findings:
                is_poisoned = True
                poison_type = "INSTRUCTION_OVERRIDE"
                confidence = max(f.confidence for f in inj_findings)
                findings.extend(inj_findings)

        reason = (
            f"Memory poisoning detected ({poison_type}): {findings[0].description}"
            if is_poisoned
            else "Memory evaluated safe."
        )

        return MemoryPoisoningAssessment(
            memory_id=memory_id,
            is_poisoned=is_poisoned,
            poison_type=poison_type,
            confidence=confidence,
            findings=findings,
            quarantine_recommended=is_poisoned,
            reason=reason,
        )


class SessionMemoryBoundary:
    """Enforces strict multi-tenant and cross-session isolation on agent memories."""

    def __init__(self) -> None:
        # (session_id, tenant_id) -> list of memory_ids
        self._registry: Dict[str, MemoryProvenanceRecord] = {}

    def register_memory(self, record: MemoryProvenanceRecord) -> None:
        """Register memory record inside session boundary."""
        self._registry[record.memory_id] = record

    def validate_access(
        self,
        memory_id: str,
        requesting_session_id: str,
        requesting_tenant_id: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Verify that requesting session/tenant is authorized to access the target memory."""
        record = self._registry.get(memory_id)
        if record is None:
            # Memory unknown to boundary
            return False, f"Memory '{memory_id}' not found in boundary registry."

        # Tenant boundary check
        if record.tenant_id != requesting_tenant_id:
            return False, f"Cross-tenant memory access denied: record tenant '{record.tenant_id}' != requesting tenant '{requesting_tenant_id}'."

        # Session boundary check
        if record.session_id != requesting_session_id:
            return False, f"Cross-session memory leakage blocked: record belongs to session '{record.session_id}', not '{requesting_session_id}'."

        # Quarantine check
        if record.trust_label == MemoryTrustLabel.QUARANTINED:
            return False, f"Memory '{memory_id}' is quarantined due to past security violations."

        return True, "Memory access authorized within session boundary."


class AdvancedMemorySecurityGuard:
    """Orchestrates memory write/read guards with provenance, boundary checks, and poisoning defense."""

    def __init__(
        self,
        poisoning_detector: Optional[MemoryPoisoningDetector] = None,
        boundary: Optional[SessionMemoryBoundary] = None,
    ) -> None:
        self.poisoning_detector = poisoning_detector or MemoryPoisoningDetector()
        self.boundary = boundary or SessionMemoryBoundary()
        self._quarantined_memories: Dict[str, str] = {}

    def secure_write(
        self,
        content: str,
        session_id: str,
        tenant_id: Optional[str] = None,
        author_role: str = "assistant",
        memory_id: Optional[str] = None,
    ) -> Tuple[bool, MemoryProvenanceRecord, MemoryPoisoningAssessment]:
        """Evaluate memory for poisoning, create provenance record, and register boundary."""
        mid = memory_id or f"mem-{uuid.uuid4().hex[:10]}"
        content_hash = MemoryProvenanceRecord.compute_hash(content)

        assessment = self.poisoning_detector.inspect_memory(content, memory_id=mid)

        trust_label = (
            MemoryTrustLabel.QUARANTINED if assessment.is_poisoned else MemoryTrustLabel.VERIFIED
        )

        record = MemoryProvenanceRecord(
            memory_id=mid,
            session_id=session_id,
            tenant_id=tenant_id,
            author_role=author_role,
            trust_label=trust_label,
            content_hash=content_hash,
        )

        if assessment.is_poisoned:
            self._quarantined_memories[mid] = content
            self.boundary.register_memory(record)
            return False, record, assessment

        self.boundary.register_memory(record)
        return True, record, assessment

    def secure_read(
        self,
        memory_id: str,
        requesting_session_id: str,
        requesting_tenant_id: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Verify boundary isolation before returning memory content to context."""
        return self.boundary.validate_access(
            memory_id=memory_id,
            requesting_session_id=requesting_session_id,
            requesting_tenant_id=requesting_tenant_id,
        )
