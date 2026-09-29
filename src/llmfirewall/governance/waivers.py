"""Security waivers and risk acceptance models for Phase 31."""

from datetime import datetime, timezone
import hashlib
import json
import time
from typing import Any, Dict, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field, field_validator

from llmfirewall.governance.findings import GovernanceFinding


class SecurityWaiver(BaseModel):
    """Explicit, time-bounded, and auditable risk waiver for a security control or finding.
    
    Security Invariants:
    1. Mandatory Attribution: Anonymous waivers are strictly rejected (owner required).
    2. Mandatory Justification: Every waiver must document an explicit business/technical reason.
    3. Strict Time Bounding: Permanent waivers are prohibited; an expiration epoch is mandatory.
    4. Explicit Scope: A waiver for test PI-001 never matches test TOOL-001 unless explicitly wildcarded.
    5. Tamper Resistance: SHA-256 integrity digest verifies the waiver parameters have not been mutated.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: f"WAIVER-{uuid.uuid4().hex[:8].upper()}")
    owner: str = Field(..., min_length=2, description="Designated owner or engineering lead accountable for waiver.")
    reason: str = Field(..., min_length=5, description="Auditable justification for risk acceptance.")
    created_at: float = Field(default_factory=time.time, description="Creation epoch timestamp.")
    expires_at: float = Field(..., description="Mandatory epoch timestamp when waiver ceases to be valid.")
    test_id: Optional[str] = Field(default=None, description="Scoped test identifier (e.g. 'PI-001').")
    rule_id: Optional[str] = Field(default=None, description="Scoped policy rule identifier.")
    category: Optional[str] = Field(default=None, description="Scoped attack category.")
    resource: Optional[str] = Field(default=None, description="Scoped resource or tool descriptor.")
    finding_fingerprint: Optional[str] = Field(default=None, description="Scoped finding fingerprint.")
    sha256: str = Field(default="", description="Cryptographic integrity digest over waiver fields.")

    @field_validator("owner")
    @classmethod
    def validate_owner(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Waiver owner cannot be blank.")
        return clean

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Waiver reason cannot be blank.")
        return clean

    @classmethod
    def create(
        cls,
        owner: str,
        reason: str,
        expires_at: float,
        test_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        category: Optional[str] = None,
        resource: Optional[str] = None,
        finding_fingerprint: Optional[str] = None,
        waiver_id: Optional[str] = None,
        created_at: Optional[float] = None,
    ) -> "SecurityWaiver":
        """Factory creating a SecurityWaiver with valid cryptographic integrity checksum."""
        now = created_at if created_at is not None else time.time()
        w_id = waiver_id or f"WAIVER-{uuid.uuid4().hex[:8].upper()}"

        digest = cls._calculate_digest(
            w_id=w_id,
            owner=owner.strip(),
            reason=reason.strip(),
            created_at=now,
            expires_at=expires_at,
            test_id=test_id,
            rule_id=rule_id,
            category=category,
            resource=resource,
            finding_fingerprint=finding_fingerprint,
        )

        return cls(
            id=w_id,
            owner=owner.strip(),
            reason=reason.strip(),
            created_at=now,
            expires_at=expires_at,
            test_id=test_id,
            rule_id=rule_id,
            category=category,
            resource=resource,
            finding_fingerprint=finding_fingerprint,
            sha256=digest,
        )

    @staticmethod
    def _calculate_digest(
        w_id: str,
        owner: str,
        reason: str,
        created_at: float,
        expires_at: float,
        test_id: Optional[str],
        rule_id: Optional[str],
        category: Optional[str],
        resource: Optional[str],
        finding_fingerprint: Optional[str],
    ) -> str:
        payload = {
            "id": w_id,
            "owner": owner,
            "reason": reason,
            "created_at": round(created_at, 4),
            "expires_at": round(expires_at, 4),
            "test_id": test_id or "",
            "rule_id": rule_id or "",
            "category": category or "",
            "resource": resource or "",
            "finding_fingerprint": finding_fingerprint or "",
        }
        serialized = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def verify_integrity(self) -> bool:
        """Verify that the waiver's sha256 matches its current parameters."""
        expected = self._calculate_digest(
            w_id=self.id,
            owner=self.owner,
            reason=self.reason,
            created_at=self.created_at,
            expires_at=self.expires_at,
            test_id=self.test_id,
            rule_id=self.rule_id,
            category=self.category,
            resource=self.resource,
            finding_fingerprint=self.finding_fingerprint,
        )
        return self.sha256 == expected

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        """Return True if the current time exceeds the waiver's expires_at."""
        now = current_time if current_time is not None else time.time()
        return now > self.expires_at

    def matches_finding(self, finding: GovernanceFinding) -> bool:
        """Strictly determine if this waiver applies to a specific GovernanceFinding."""
        # Integrity must be valid
        if not self.verify_integrity():
            return False

        # Expiration check
        if self.is_expired():
            return False

        # Fingerprint match
        if self.finding_fingerprint:
            return self.finding_fingerprint == finding.fingerprint

        # Test ID match (exact scope)
        if self.test_id is not None:
            if not finding.test_id or self.test_id != finding.test_id:
                return False

        # Rule ID match
        if self.rule_id is not None:
            if not finding.rule_id or self.rule_id != finding.rule_id:
                return False

        # Category match
        if self.category is not None:
            if (self.category or "").lower() != (finding.category or "").lower():
                return False

        # Resource match
        if self.resource is not None:
            if (self.resource or "").lower() != (finding.resource or "").lower():
                return False

        # If at least one scoping criteria matched or explicitly defined
        has_scope = any([
            self.test_id is not None,
            self.rule_id is not None,
            self.category is not None,
            self.resource is not None,
            self.finding_fingerprint is not None,
        ])
        return has_scope
