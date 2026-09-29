"""Logical Quarantine Store and Document Ingestion Scanner for RAG.

Phase 27: Advanced RAG & Context Security.
Guarantees:
- Quarantined content is segregated and NEVER enters active retrieval results
- Hashing and change detection between document versions
- Bounded metadata storage without raw secret/PII retention
"""

from __future__ import annotations

import collections
import hashlib
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from llmfirewall.firewall import Firewall

from llmfirewall.core.models import Action, Finding
from llmfirewall.observability.models import EventSeverity, SecurityEvent, SecurityEventType
from llmfirewall.rag.cache import SecurityScanCache
from llmfirewall.rag.models import (
    DocumentIngestionResult,
    DocumentSecurityStatus,
    SourceProvenance,
)


class QuarantineStore:
    """Logical quarantine repository segregating flagged or malicious documents."""

    def __init__(self, max_items: int = 5000) -> None:
        self.max_items = max_items
        self._items: collections.OrderedDict[str, Dict[str, Any]] = collections.OrderedDict()

    def quarantine(
        self,
        document_id: str,
        content_hash: str,
        reason: str,
        findings: List[Finding],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Place a document into quarantine."""
        if len(self._items) >= self.max_items:
            self._items.popitem(last=False)

        entry = {
            "document_id": document_id,
            "content_hash": content_hash,
            "reason": reason,
            "findings_count": len(findings),
            "threat_types": [f.threat_type.value for f in findings],
            "quarantined_at": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {},
        }
        self._items[document_id] = entry

    def is_quarantined(self, document_id: str) -> bool:
        """Check if document_id is currently quarantined."""
        return document_id in self._items

    def get(self, document_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve quarantine metadata."""
        return self._items.get(document_id)

    def release(self, document_id: str) -> bool:
        """Release document from quarantine (e.g. after manual analyst review)."""
        if document_id in self._items:
            del self._items[document_id]
            return True
        return False

    @property
    def count(self) -> int:
        return len(self._items)

    def list_quarantined(self) -> List[Dict[str, Any]]:
        return list(self._items.values())


class DocumentIngestionScanner:
    """Pre-indexing security scanner validating raw documents and chunks."""

    def __init__(
        self,
        firewall: Firewall,
        quarantine_store: Optional[QuarantineStore] = None,
        cache: Optional[SecurityScanCache] = None,
    ) -> None:
        self.firewall = firewall
        self.quarantine_store = quarantine_store or QuarantineStore()
        self.cache = cache or SecurityScanCache()
        self.version_history: Dict[str, str] = {}  # document_id -> content_hash

    def scan_document(
        self,
        content: str,
        document_id: str,
        provenance: Optional[SourceProvenance] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> DocumentIngestionResult:
        """Scan a document prior to chunking and embedding.
        
        Evaluates prompt injection, secrets, PII, and custom policies.
        Quarantines or blocks if malicious instructions are detected.
        """
        t0 = time.monotonic()
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        # Version change tracking
        prev_hash = self.version_history.get(document_id)
        is_modified = prev_hash is not None and prev_hash != content_hash
        self.version_history[document_id] = content_hash

        # Check Cache
        cache_key = self.cache.make_key(
            content_hash=content_hash,
            policy_version=self.firewall.policy_engine.policy.version,
        )
        cached_res = self.cache.get(cache_key)

        if cached_res is not None:
            scan_res = cached_res
        else:
            scan_context = {
                "source_type": "document",
                "document_id": document_id,
                "direction": "input",
                **(context or {}),
            }
            scan_res = self.firewall.check_prompt(
                prompt=content,
                context=scan_context,
            )
            self.cache.put(cache_key, scan_res)

        elapsed_ms = (time.monotonic() - t0) * 1000.0

        # Assess security status & quarantine action
        status = DocumentSecurityStatus.APPROVED
        action = scan_res.decision.action
        quarantine_reason = None

        if action == Action.BLOCK:
            status = DocumentSecurityStatus.BLOCKED
            quarantine_reason = f"Document rejected by policy: {scan_res.decision.reason}"
            self.quarantine_store.quarantine(
                document_id=document_id,
                content_hash=content_hash,
                reason=quarantine_reason,
                findings=scan_res.findings,
            )
        elif action == Action.WARN or any(f.threat_type.value == "prompt_injection" for f in scan_res.findings):
            status = DocumentSecurityStatus.FLAGGED
            if any(f.threat_type.value == "prompt_injection" for f in scan_res.findings):
                status = DocumentSecurityStatus.QUARANTINED
                quarantine_reason = "Indirect prompt injection detected in knowledge document"
                self.quarantine_store.quarantine(
                    document_id=document_id,
                    content_hash=content_hash,
                    reason=quarantine_reason,
                    findings=scan_res.findings,
                )

        # Record observability event
        try:
            ev_type = SecurityEventType.DOCUMENT_QUARANTINED if status == DocumentSecurityStatus.QUARANTINED else SecurityEventType.DOCUMENT_SCANNED
            self.firewall.event_store.write(
                SecurityEvent(
                    event_type=ev_type,
                    severity=EventSeverity.HIGH if action == Action.BLOCK else EventSeverity.INFO,
                    request_id=document_id,
                    component="rag_ingestion",
                    action=action,
                    threat_types=[f.threat_type.value for f in scan_res.findings],
                    findings_count=len(scan_res.findings),
                    metadata={
                        "document_id": document_id,
                        "status": status.value,
                        "is_modified": is_modified,
                        "duration_ms": round(elapsed_ms, 2),
                    },
                )
            )
        except Exception:
            pass

        return DocumentIngestionResult(
            document_id=document_id,
            status=status,
            action=action,
            content_hash=content_hash,
            findings=scan_res.findings,
            quarantine_reason=quarantine_reason,
            execution_time_ms=elapsed_ms,
            metadata={"is_modified": is_modified},
        )
