"""Phase 63 — Multi-Tenant Policy Engine and Isolation Manager."""

from typing import Dict, List, Optional

from llmfirewall.core.models import Action
from llmfirewall.policy.config import Policy, PolicyConfig, PolicyRule
from llmfirewall.policy.engine import PolicyEngine, get_default_policy


class TenantPolicyManager:
    """Manages tenant-specific security policies while enforcing enterprise baseline floors."""

    def __init__(self, global_policy: Optional[Policy] = None) -> None:
        self.global_policy = global_policy or get_default_policy()
        self._tenant_policies: Dict[str, Policy] = {}
        self._tenant_engines: Dict[str, PolicyEngine] = {}

    def register_tenant_policy(self, tenant_id: str, policy: Policy) -> None:
        """Register a custom policy for a tenant.
        
        Security Invariant:
        Tenant policies can add stricter rules, but cannot eliminate global baseline rules.
        """
        # Combine global rules with tenant-specific rules
        combined_rules: List[PolicyRule] = list(self.global_policy.rules)
        for rule in policy.rules:
            # Overwrite or append tenant-specific rules
            combined_rules = [r for r in combined_rules if r.name != rule.name]
            combined_rules.append(rule)

        effective_policy = Policy(
            version=policy.version,
            default_action=self.global_policy.default_action,
            rules=combined_rules,
            redaction_config=policy.redaction_config or self.global_policy.redaction_config,
        )

        self._tenant_policies[tenant_id] = effective_policy
        self._tenant_engines[tenant_id] = PolicyEngine(config=effective_policy)

    def get_effective_policy(self, tenant_id: Optional[str] = None) -> Policy:
        """Retrieve effective policy for a tenant, or global policy if unregistered."""
        if not tenant_id or tenant_id not in self._tenant_policies:
            return self.global_policy
        return self._tenant_policies[tenant_id]

    def get_effective_engine(self, tenant_id: Optional[str] = None) -> PolicyEngine:
        """Retrieve PolicyEngine configured for target tenant."""
        if not tenant_id or tenant_id not in self._tenant_engines:
            return PolicyEngine(config=self.global_policy)
        return self._tenant_engines[tenant_id]
