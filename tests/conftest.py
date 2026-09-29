"""Global pytest fixtures and test helpers for LLMFirewall test suite."""

import pytest
from typing import Dict, Any

from llmfirewall import (
    Action,
    AuditConfig,
    DetectorConfig,
    Firewall,
    FirewallConfig,
    PIIConfig,
    PolicyConfig,
    PolicyRule,
    PromptInjectionConfig,
    RedactionConfig,
    RiskConfig,
    SecretConfig,
    Severity,
    ThreatType,
)
from llmfirewall.risk.engine import RiskEngine
from llmfirewall.policy.engine import PolicyEngine
from llmfirewall.policy.redactor import SafeRedactor


@pytest.fixture
def default_firewall() -> Firewall:
    """Provide a standard Firewall instance with default security configuration."""
    return Firewall()


@pytest.fixture
def default_config() -> FirewallConfig:
    """Provide a fresh default FirewallConfig model."""
    return FirewallConfig()


@pytest.fixture
def strict_config() -> FirewallConfig:
    """Provide a strict security configuration that blocks on any PII, secret, or injection."""
    strict_policy = PolicyConfig(
        rules=[
            PolicyRule(
                id="strict_block_pii",
                description="Block on any detected PII",
                threat_type=ThreatType.PII,
                action=Action.BLOCK,
            ),
            PolicyRule(
                id="strict_block_secrets",
                description="Block on any detected secret",
                threat_type=ThreatType.SECRET,
                action=Action.BLOCK,
            ),
            PolicyRule(
                id="strict_block_injection",
                description="Block on any prompt injection",
                threat_type=ThreatType.PROMPT_INJECTION,
                action=Action.BLOCK,
            ),
        ],
        default_action=Action.ALLOW,
    )
    return FirewallConfig(
        detectors=DetectorConfig(
            prompt_injection=PromptInjectionConfig(enabled=True),
            pii=PIIConfig(enabled=True),
            secrets=SecretConfig(enabled=True),
            fail_fast=True,
        ),
        policy=strict_policy,
        risk=RiskConfig(low_threshold=0.10, medium_threshold=0.30, high_threshold=0.60, critical_threshold=0.80),
    )


@pytest.fixture
def strict_firewall(strict_config: FirewallConfig) -> Firewall:
    """Provide a Firewall instance configured in strict blocking mode."""
    return Firewall(config=strict_config)


@pytest.fixture
def risk_engine() -> RiskEngine:
    """Provide a default RiskEngine instance."""
    return RiskEngine()


@pytest.fixture
def policy_engine() -> PolicyEngine:
    """Provide a default PolicyEngine instance."""
    return PolicyEngine()


@pytest.fixture
def redactor() -> SafeRedactor:
    """Provide a default SafeRedactor instance."""
    return SafeRedactor()
