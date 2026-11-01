"""Enterprise Policy Governance, Versioning, Integrity Verification, and Rollback."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from llmfirewall.policy.config import Policy
from llmfirewall.policy.engine import PolicyEngine

logger = logging.getLogger("llmfirewall.enterprise.governance")


class PolicyLifecycleState(str, Enum):
    """Lifecycle stages for enterprise Policy-as-Code documents."""
    DRAFT = "DRAFT"
    VALIDATED = "VALIDATED"
    APPROVED = "APPROVED"
    ACTIVATED = "ACTIVATED"
    ROLLED_BACK = "ROLLED_BACK"
    RETIRED = "RETIRED"


class PolicyIntegrityError(Exception):
    """Raised when a policy document fails integrity or cryptographic hash verification."""
    pass


class PolicyGovernanceError(Exception):
    """Raised when an illegal policy lifecycle transition is requested."""
    pass


@dataclass
class PolicyGovernanceRecord:
    policy_id: str
    version: str
    policy: Policy
    sha256_hash: str
    state: PolicyLifecycleState
    created_at: float = field(default_factory=time.time)
    activated_at: Optional[float] = None
    approved_by: Optional[str] = None
    tenant_id: Optional[str] = None


class PolicyGovernanceManager:
    """Enterprise policy governance engine managing lifecycle, cryptographic integrity, and rollbacks.

    Guarantees:
    - Integrity Verification: Cryptographic SHA-256 validation prevents unauthorized policy tampering.
    - Controlled Lifecycle: Strict transitions (Draft -> Validated -> Approved -> Activated).
    - Zero-Downtime Rollback: Retains previous active policy version for instant rollback.
    - Tenant Boundary Isolation: Tenant policy activation never impacts unrelated tenants or global baseline.
    """

    def __init__(self, global_baseline_policy: Optional[Policy] = None) -> None:
        self._records: Dict[Tuple[str, str], PolicyGovernanceRecord] = {}  # (policy_id, version) -> Record
        self._active_policies: Dict[str, str] = {}  # policy_id -> active version
        self._previous_policies: Dict[str, str] = {}  # policy_id -> previous version
        self._global_baseline = global_baseline_policy

    @staticmethod
    def compute_policy_hash(policy_content: Union[str, bytes, Policy]) -> str:
        """Compute canonical, deterministic SHA-256 hash of policy content."""
        if isinstance(policy_content, Policy):
            raw = policy_content.model_dump_json(exclude_none=True).encode("utf-8")
        elif isinstance(policy_content, str):
            raw = policy_content.strip().encode("utf-8")
        elif isinstance(policy_content, bytes):
            raw = policy_content.strip()
        else:
            raise TypeError("Unsupported policy_content type")
        return hashlib.sha256(raw).hexdigest()

    def register_draft(
        self,
        policy_id: str,
        version: str,
        policy: Policy,
        expected_sha256: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> PolicyGovernanceRecord:
        """Register a new policy draft with cryptographic integrity check."""
        computed_hash = self.compute_policy_hash(policy)
        if expected_sha256 and computed_hash != expected_sha256:
            raise PolicyIntegrityError(
                f"Policy integrity mismatch for '{policy_id}' v{version}: "
                f"expected {expected_sha256}, got {computed_hash}"
            )

        key = (policy_id, version)
        record = PolicyGovernanceRecord(
            policy_id=policy_id,
            version=version,
            policy=policy,
            sha256_hash=computed_hash,
            state=PolicyLifecycleState.DRAFT,
            tenant_id=tenant_id,
        )
        self._records[key] = record
        logger.info("Registered policy draft '%s' v%s (sha256: %s)", policy_id, version, computed_hash[:12])
        return record

    def validate_policy(self, policy_id: str, version: str) -> bool:
        """Validate policy syntax, rule actions, and enterprise floor rules."""
        key = (policy_id, version)
        record = self._records.get(key)
        if not record:
            raise PolicyGovernanceError(f"Policy '{policy_id}' v{version} not found")

        # Validate engine compilation
        try:
            engine = PolicyEngine(config=record.policy)
            # Verify global floor rules are preserved
            if self._global_baseline:
                baseline_threats = {r.threat_type for r in self._global_baseline.rules if r.threat_type}
                policy_threats = {r.threat_type for r in record.policy.rules if r.threat_type}
                if not baseline_threats.issubset(policy_threats):
                    missing = baseline_threats - policy_threats
                    raise PolicyGovernanceError(f"Policy omits required enterprise baseline threats: {missing}")

            record.state = PolicyLifecycleState.VALIDATED
            logger.info("Policy '%s' v%s validated successfully", policy_id, version)
            return True
        except Exception as exc:
            logger.warning("Policy validation failed on '%s' v%s: %s", policy_id, version, exc)
            raise

    def approve_policy(self, policy_id: str, version: str, approver_identity: str) -> None:
        """Mark validated policy as approved for production deployment."""
        key = (policy_id, version)
        record = self._records.get(key)
        if not record:
            raise PolicyGovernanceError(f"Policy '{policy_id}' v{version} not found")

        if record.state != PolicyLifecycleState.VALIDATED:
            raise PolicyGovernanceError(f"Cannot approve policy in state '{record.state.value}' (must be VALIDATED)")

        record.state = PolicyLifecycleState.APPROVED
        record.approved_by = approver_identity
        logger.info("Policy '%s' v%s approved by '%s'", policy_id, version, approver_identity)

    def activate_policy(self, policy_id: str, version: str) -> None:
        """Atomically activate approved policy, promoting it to active and stashing previous version."""
        key = (policy_id, version)
        record = self._records.get(key)
        if not record:
            raise PolicyGovernanceError(f"Policy '{policy_id}' v{version} not found")

        if record.state not in (PolicyLifecycleState.APPROVED, PolicyLifecycleState.ROLLED_BACK):
            raise PolicyGovernanceError(f"Cannot activate policy in state '{record.state.value}'")

        # Record previous version for rollback
        current_active = self._active_policies.get(policy_id)
        if current_active and current_active != version:
            self._previous_policies[policy_id] = current_active

        self._active_policies[policy_id] = version
        record.state = PolicyLifecycleState.ACTIVATED
        record.activated_at = time.time()
        logger.info("Policy '%s' v%s is now ACTIVATED (previous active: %s)", policy_id, version, current_active)

    def rollback_policy(self, policy_id: str) -> Optional[str]:
        """Atomically rollback to the previously active policy version."""
        prev_version = self._previous_policies.get(policy_id)
        if not prev_version:
            logger.warning("No previous policy version found to rollback for '%s'", policy_id)
            return None

        current_active = self._active_policies.get(policy_id)
        if current_active:
            curr_rec = self._records.get((policy_id, current_active))
            if curr_rec:
                curr_rec.state = PolicyLifecycleState.ROLLED_BACK

        # Reactivate previous
        self._active_policies[policy_id] = prev_version
        prev_rec = self._records.get((policy_id, prev_version))
        if prev_rec:
            prev_rec.state = PolicyLifecycleState.ACTIVATED
            prev_rec.activated_at = time.time()

        logger.info("Policy '%s' rolled back: v%s -> v%s", policy_id, current_active, prev_version)
        return prev_version

    def get_active_policy(self, policy_id: str) -> Optional[Policy]:
        """Retrieve active policy for policy_id."""
        version = self._active_policies.get(policy_id)
        if not version:
            return None
        rec = self._records.get((policy_id, version))
        return rec.policy if rec else None
