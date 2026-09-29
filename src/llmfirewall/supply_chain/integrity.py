"""Configuration, prompt, and policy integrity hashing and drift detection."""

import hashlib
import json
from typing import Any, Dict, List, Optional, Set, Tuple

from llmfirewall.core.models import Finding, Severity, ThreatType
from llmfirewall.supply_chain.models import (
    ConfigArtifact,
    PolicyArtifact,
    PromptArtifact,
    SecuritySnapshot,
    SnapshotDiff,
)

# Known secret/sensitive field names to strip prior to hashing configuration
SENSITIVE_KEY_NAMES: Set[str] = {
    "api_key",
    "apikey",
    "secret",
    "password",
    "token",
    "access_token",
    "private_key",
    "client_secret",
}


def sanitize_config_dict(data: Any) -> Any:
    """Recursively strip sensitive values while preserving key structure and types."""
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(sens in k_lower for sens in SENSITIVE_KEY_NAMES):
                # Hash the existence of key without including value
                sanitized[k] = "[REDACTED_SECRET]"
            else:
                sanitized[k] = sanitize_config_dict(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_config_dict(item) for item in data]
    return data


def hash_configuration(config_data: Dict[str, Any], config_type: str = "firewall", source: str = "FILE") -> ConfigArtifact:
    """Deterministically hash a configuration dictionary without exposing secrets."""
    sanitized = sanitize_config_dict(config_data)
    serialized = json.dumps(sanitized, sort_keys=True)
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    keys_present = sorted(list(config_data.keys()))

    return ConfigArtifact(
        config_type=config_type,
        sha256=digest,
        source=source,
        keys_present=keys_present,
    )


def hash_prompt_artifact(prompt_text: str, name: str, version: str = "1") -> PromptArtifact:
    """Create a normalized PromptArtifact with cryptographic digest without logging prompt content."""
    digest = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()
    return PromptArtifact(
        name=name,
        version=version,
        sha256=digest,
        length_chars=len(prompt_text),
    )


def hash_policy_artifact(policy_rules_or_yaml: Any, policy_id: str = "default", version: str = "1") -> PolicyArtifact:
    """Create a PolicyArtifact with deterministic cryptographic digest."""
    if isinstance(policy_rules_or_yaml, (dict, list)):
        serialized = json.dumps(policy_rules_or_yaml, sort_keys=True)
    else:
        serialized = str(policy_rules_or_yaml)

    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return PolicyArtifact(
        policy_id=policy_id,
        version=version,
        sha256=digest,
    )


class IntegrityManager:
    """Tracks baseline configurations, policies, and prompts to detect security drift."""

    def __init__(self) -> None:
        self.baseline_configs: Dict[str, ConfigArtifact] = {}
        self.baseline_policies: Dict[str, PolicyArtifact] = {}
        self.baseline_prompts: Dict[str, PromptArtifact] = {}

    def set_baseline_config(self, artifact: ConfigArtifact) -> None:
        self.baseline_configs[artifact.config_type] = artifact

    def set_baseline_policy(self, artifact: PolicyArtifact) -> None:
        self.baseline_policies[artifact.policy_id] = artifact

    def set_baseline_prompt(self, artifact: PromptArtifact) -> None:
        self.baseline_prompts[artifact.name] = artifact

    def check_config_drift(self, current_config: Dict[str, Any], config_type: str = "firewall") -> Optional[Finding]:
        """Detect drift between baseline configuration and current active configuration."""
        baseline = self.baseline_configs.get(config_type)
        if not baseline:
            return None

        current_art = hash_configuration(current_config, config_type=config_type)
        if current_art.sha256 != baseline.sha256:
            return Finding(
                detector_name="configuration_integrity",
                threat_type=ThreatType.POLICY_VIOLATION,
                description=(
                    f"Security configuration drift detected in '{config_type}': "
                    f"baseline hash {baseline.sha256[:12]} != current hash {current_art.sha256[:12]}."
                ),
                severity=Severity.HIGH,
                confidence=1.0,
                metadata={
                    "violation": "SECURITY_CONFIG_DRIFT",
                    "config_type": config_type,
                    "baseline_hash": baseline.sha256,
                    "current_hash": current_art.sha256,
                },
            )
        return None

    def check_policy_drift(self, current_policy_data: Any, policy_id: str = "default") -> Optional[Finding]:
        """Detect drift between approved baseline policy and active policy rules."""
        baseline = self.baseline_policies.get(policy_id)
        if not baseline:
            return None

        current_art = hash_policy_artifact(current_policy_data, policy_id=policy_id)
        if current_art.sha256 != baseline.sha256:
            return Finding(
                detector_name="policy_integrity",
                threat_type=ThreatType.POLICY_VIOLATION,
                description=(
                    f"Security policy drift detected in policy '{policy_id}': "
                    f"baseline hash {baseline.sha256[:12]} != current hash {current_art.sha256[:12]}."
                ),
                severity=Severity.CRITICAL,
                confidence=1.0,
                metadata={
                    "violation": "POLICY_DRIFT",
                    "policy_id": policy_id,
                    "baseline_hash": baseline.sha256,
                    "current_hash": current_art.sha256,
                },
            )
        return None

    def check_prompt_drift(self, current_prompt_text: str, name: str) -> Optional[Finding]:
        """Detect unexpected changes to security-critical system or guardrail prompts."""
        baseline = self.baseline_prompts.get(name)
        if not baseline:
            return None

        current_art = hash_prompt_artifact(current_prompt_text, name=name)
        if current_art.sha256 != baseline.sha256:
            return Finding(
                detector_name="prompt_integrity",
                threat_type=ThreatType.POLICY_VIOLATION,
                description=(
                    f"Security prompt template drift detected in '{name}': "
                    f"expected template hash {baseline.sha256[:12]} != current hash {current_art.sha256[:12]}."
                ),
                severity=Severity.HIGH,
                confidence=1.0,
                metadata={
                    "violation": "PROMPT_DRIFT",
                    "prompt_name": name,
                    "baseline_hash": baseline.sha256,
                    "current_hash": current_art.sha256,
                },
            )
        return None
