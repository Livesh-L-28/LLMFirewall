"""Stage 5 Enterprise Readiness & Production Hardening Test Suite.

Validates:
1. Resilience engineering (FailurePolicy, CircuitBreaker, retry_with_backoff)
2. Distributed rate limiting (InMemoryRateLimiter, RedisRateLimiter, DistributedRateLimiter)
3. Dynamic secrets management (EnvSecretProvider, FileSecretProvider, VaultSecretProvider)
4. Key rotation & lifecycle (DynamicKeyManager, KeyVersion)
5. Observability & zero-retention logging (OpenTelemetryBridge, SafeAuditEvent)
6. Policy governance, integrity, and atomic rollback (PolicyGovernanceManager)
7. Deployment assets YAML validation (Docker & Kubernetes manifests)
"""

from __future__ import annotations

import glob
import json
import os
import tempfile
import time
from unittest.mock import MagicMock, patch

import pytest
import yaml

from llmfirewall.core.models import Action, Finding, ScanResult, Severity, ThreatType
from llmfirewall.enterprise import (
    CircuitBreaker,
    CircuitBreakerOpenError,
    CircuitState,
    DistributedRateLimiter,
    DynamicKeyManager,
    EnvSecretProvider,
    FailurePolicy,
    FileSecretProvider,
    InMemoryRateLimiter,
    KeyMetadata,
    KeyRotationResult,
    KeyVersion,
    OpenTelemetryBridge,
    PolicyGovernanceError,
    PolicyGovernanceManager,
    PolicyGovernanceRecord,
    PolicyIntegrityError,
    PolicyLifecycleState,
    RateLimitDimension,
    RateLimitResult,
    RedisRateLimiter,
    SafeAuditEvent,
    VaultSecretProvider,
    retry_with_backoff,
)
from llmfirewall.policy.config import Policy, PolicyRule


# -----------------------------------------------------------------------------
# 1. Resilience Engineering Tests
# -----------------------------------------------------------------------------

def test_failure_policy_enum():
    assert FailurePolicy.FAIL_OPEN.value == "FAIL_OPEN"
    assert FailurePolicy.FAIL_CLOSED.value == "FAIL_CLOSED"
    assert FailurePolicy.REJECT_TEMPORARILY.value == "REJECT_TEMPORARILY"


def test_circuit_breaker_transitions():
    cb = CircuitBreaker(
        name="test-breaker",
        failure_threshold=3,
        recovery_timeout=0.1,  # 100ms for fast test
    )
    assert cb.state == CircuitState.CLOSED
    assert cb.can_execute()

    # Record 2 failures (threshold is 3)
    cb.record_failure()
    cb.record_failure()
    assert cb.state == CircuitState.CLOSED

    # 3rd failure trips the breaker to OPEN
    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    assert not cb.can_execute()

    # Attempting execution while OPEN raises CircuitBreakerOpenError
    with pytest.raises(CircuitBreakerOpenError):
        with cb:
            pass

    # Wait for recovery timeout
    time.sleep(0.12)
    assert cb.can_execute()
    assert cb.state == CircuitState.HALF_OPEN

    # Success in HALF_OPEN closes the circuit
    cb.record_success()
    assert cb.state == CircuitState.CLOSED
    assert cb.can_execute()


def test_circuit_breaker_context_manager():
    cb = CircuitBreaker(name="cm-breaker", failure_threshold=2)

    # Successful call
    with cb:
        val = 1 + 1
    assert val == 2
    assert cb.state == CircuitState.CLOSED

    # Failing call
    with pytest.raises(ValueError):
        with cb:
            raise ValueError("Service exploded")

    assert cb._consecutive_failures == 1
    assert cb.state == CircuitState.CLOSED


def test_retry_with_backoff_decorator():
    attempts = 0

    @retry_with_backoff(
        max_retries=3,
        base_delay=0.01,
        max_delay=0.05,
        retryable_exceptions=(ConnectionError,),
        is_idempotent=True,
    )
    def flaky_func():
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise ConnectionError("Temporary glitch")
        return "SUCCESS"

    result = flaky_func()
    assert result == "SUCCESS"
    assert attempts == 3


def test_retry_with_backoff_non_retryable_exception():
    attempts = 0

    @retry_with_backoff(
        max_retries=3,
        base_delay=0.01,
        retryable_exceptions=(ConnectionError,),
        is_idempotent=True,
    )
    def fatal_func():
        nonlocal attempts
        attempts += 1
        raise KeyError("Invalid key")

    with pytest.raises(KeyError):
        fatal_func()

    # Should not have retried
    assert attempts == 1


# -----------------------------------------------------------------------------
# 2. Rate Limiting Tests
# -----------------------------------------------------------------------------

def test_in_memory_rate_limiter():
    limiter = InMemoryRateLimiter()

    # Allow up to 3 requests
    r1 = limiter.acquire("user1", limit=3, window_seconds=10.0)
    assert r1.allowed
    assert r1.remaining == 2

    r2 = limiter.acquire("user1", limit=3, window_seconds=10.0)
    assert r2.allowed
    assert r2.remaining == 1

    r3 = limiter.acquire("user1", limit=3, window_seconds=10.0)
    assert r3.allowed
    assert r3.remaining == 0

    # 4th request exceeds limit
    r4 = limiter.acquire("user1", limit=3, window_seconds=10.0)
    assert not r4.allowed
    assert r4.remaining == 0
    assert r4.retry_after_seconds > 0


def test_redis_rate_limiter_mocked():
    mock_redis = MagicMock()
    # Mock Lua script eval returning [1, 9, 0] (allowed, remaining=9, retry_after=0)
    mock_redis.eval.return_value = [1, 9, 0]

    limiter = RedisRateLimiter(client=mock_redis, namespace="test:rl")
    result = limiter.acquire("tenant_123", limit=10, window_seconds=60.0)

    assert result.allowed
    assert result.remaining == 9
    assert result.retry_after_seconds == 0.0
    mock_redis.eval.assert_called_once()


def test_distributed_rate_limiter_multidimensional():
    in_memory = InMemoryRateLimiter()
    dist_limiter = DistributedRateLimiter(
        backend=in_memory,
        default_rpm=10,
    )
    dist_limiter.set_tenant_quota("tenant_alpha", 5)

    # Check TENANT dimension
    res_tenant = dist_limiter.check(tenant_id="tenant_alpha")
    assert res_tenant.allowed

    # Check USER dimension
    res_user = dist_limiter.check(user_id="user_beta")
    assert res_user.allowed


def test_redis_rate_limiter_failure_policy():
    mock_failing_redis = MagicMock()
    mock_failing_redis.eval.side_effect = RuntimeError("Redis down")

    # Fail open
    limiter_open = RedisRateLimiter(
        client=mock_failing_redis,
        failure_policy=FailurePolicy.FAIL_OPEN,
    )
    res_open = limiter_open.acquire("tenant_test", limit=10)
    assert res_open.allowed
    assert res_open.failure_policy_applied == FailurePolicy.FAIL_OPEN

    # Fail closed
    limiter_closed = RedisRateLimiter(
        client=mock_failing_redis,
        failure_policy=FailurePolicy.FAIL_CLOSED,
    )
    res_closed = limiter_closed.acquire("tenant_test", limit=10)
    assert not res_closed.allowed
    assert res_closed.failure_policy_applied == FailurePolicy.FAIL_CLOSED


# -----------------------------------------------------------------------------
# 3. Dynamic Secrets & Vault Tests
# -----------------------------------------------------------------------------

def test_env_secret_provider(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-test1234567890abcdef")
    provider = EnvSecretProvider()

    assert provider.get_secret("OPENAI_API_KEY") == "sk-proj-test1234567890abcdef"
    assert provider.get_secret("NONEXISTENT_KEY") is None
    assert provider.has_secret("OPENAI_API_KEY")
    assert not provider.has_secret("NONEXISTENT_KEY")


def test_file_secret_provider():
    with tempfile.TemporaryDirectory() as tmpdir:
        secret_file = os.path.join(tmpdir, "db_pass.txt")
        with open(secret_file, "w") as f:
            f.write("super_secret_db_password\n")

        provider = FileSecretProvider(secrets_dir=tmpdir)
        val = provider.get_secret("db_pass.txt")
        assert val == "super_secret_db_password"
        assert provider.get_secret("nonexistent.txt") is None


def test_vault_secret_provider_mocked():
    mock_resp_data = {
        "data": {
            "data": {
                "api_key": "vault-secret-api-key-999",
                "signing_secret": "cryptographic-signing-key",
            }
        }
    }
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(mock_resp_data).encode("utf-8")
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response):
        vault = VaultSecretProvider(
            vault_addr="https://vault.internal:8200",
            vault_token="s.mock-vault-token",
            mount_point="secret",
        )

        val = vault.get_secret("llmfirewall/creds/api_key")
        assert val == "vault-secret-api-key-999"

        # Safe repr check: token and credentials must not be exposed
        assert "s.mock-vault-token" not in repr(vault)
        assert "vault-secret-api-key-999" not in repr(vault)


# -----------------------------------------------------------------------------
# 4. Key Rotation & Lifecycle Tests
# -----------------------------------------------------------------------------

def test_dynamic_key_manager_lifecycle():
    key_mgr = DynamicKeyManager(
        grace_period_seconds=1.0,
    )

    # Initial key generation
    assert key_mgr.active_version == 1
    assert len(key_mgr.active_key) == 32  # 256 bits

    # Zero leakage repr test
    k1 = key_mgr._keys[1]
    assert "[REDACTED_KEY_MATERIAL]" in repr(k1)
    assert k1.key_bytes.hex() not in repr(k1)
    assert "[REDACTED]" in repr(key_mgr)

    # Rotate to v2
    rotation = key_mgr.rotate_key()
    assert rotation.previous_version == 1
    assert rotation.new_version == 2
    assert key_mgr.active_version == 2

    # Both keys valid during grace period
    assert key_mgr.get_key(2) is not None
    assert key_mgr.get_key(1) is not None

    # Revoke v1 immediately
    revoked = key_mgr.revoke_key(1, reason="Emergency revocation")
    assert revoked is True
    assert key_mgr.get_key(1) is None
    assert key_mgr.get_key(2) is not None


# -----------------------------------------------------------------------------
# 5. OpenTelemetry & Safe Audit Event Tests
# -----------------------------------------------------------------------------

def test_opentelemetry_bridge_graceful_fallback():
    bridge = OpenTelemetryBridge(service_name="test-service")

    # W3C Context injection & extraction
    headers = {"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}
    tp = bridge.extract_traceparent(headers)
    assert tp == ("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7")

    carrier = {}
    bridge.inject_traceparent(carrier, tp[0], tp[1])
    assert carrier["traceparent"] == headers["traceparent"]

    # Metric recording (safe no-op or metric update)
    bridge.record_scan_metrics(
        direction="input",
        action="BLOCK",
        latency_seconds=0.015,
        threat_type="PROMPT_INJECTION",
    )

    # Safe attribute filtering
    raw_attrs = {
        "llmfirewall.action": "BLOCK",
        "llmfirewall.direction": "input",
        "user_prompt": "Drop database users;",  # Must be stripped
        "api_key": "sk-secret-key-123",        # Must be stripped
    }
    safe_attrs = bridge.filter_safe_attributes(raw_attrs)
    assert "llmfirewall.action" in safe_attrs
    assert "llmfirewall.direction" in safe_attrs
    assert "user_prompt" not in safe_attrs
    assert "api_key" not in safe_attrs


def test_safe_audit_event_zero_retention():
    event = SafeAuditEvent(
        event_id="req-12345",
        trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
        span_id="00f067aa0ba902b7",
        tenant_id_hash="hash_tenant_1",
        direction="input",
        action="REDACT",
        risk_score=0.45,
        rules_applied=["PII_SSN"],
        safe_metadata={"redacted_fields": 1},
    )

    json_str = event.to_json()
    data = json.loads(json_str)

    # Asserts
    assert data["action"] == "REDACT"
    assert data["tenant_id_hash"] == "hash_tenant_1"
    assert data["event_id"] == "req-12345"
    assert "PII_SSN" in data["rules_applied"]

    # Zero-retention invariants: prompt text or processed text NOT in audit event
    assert "prompt" not in data
    assert "processed_text" not in data


# -----------------------------------------------------------------------------
# 6. Enterprise Policy Governance Tests
# -----------------------------------------------------------------------------

def test_policy_governance_lifecycle():
    gov_mgr = PolicyGovernanceManager()

    valid_policy = Policy(
        version="1.4",
        name="finance-prod-policy",
        description="Finance production policy",
        rules=[
            PolicyRule(
                id="RULE_01",
                name="Block injections",
                action=Action.BLOCK,
                threat_type="prompt_injection",
            )
        ],
    )

    # Register draft
    rec = gov_mgr.register_draft(
        policy_id="finance_policy",
        version="1.0.0",
        policy=valid_policy,
    )
    assert rec.state == PolicyLifecycleState.DRAFT
    assert rec.version == "1.0.0"
    assert rec.sha256_hash is not None

    # Validate policy
    assert gov_mgr.validate_policy("finance_policy", "1.0.0") is True
    assert rec.state == PolicyLifecycleState.VALIDATED

    # Approve policy
    gov_mgr.approve_policy(
        policy_id="finance_policy",
        version="1.0.0",
        approver_identity="secops@internal.corp",
    )
    assert rec.state == PolicyLifecycleState.APPROVED

    # Activate policy
    gov_mgr.activate_policy("finance_policy", "1.0.0")
    assert rec.state == PolicyLifecycleState.ACTIVATED
    assert gov_mgr.get_active_policy("finance_policy") is not None


def test_policy_governance_tamper_detection():
    gov_mgr = PolicyGovernanceManager()

    pol = Policy(
        version="1.4",
        name="secure-policy",
        rules=[],
    )

    # Expected hash mismatch should raise PolicyIntegrityError
    with pytest.raises(PolicyIntegrityError):
        gov_mgr.register_draft(
            policy_id="tamper_test",
            version="1.0.0",
            policy=pol,
            expected_sha256="0000000000000000000000000000000000000000000000000000000000000000",
        )


def test_policy_governance_atomic_rollback():
    gov_mgr = PolicyGovernanceManager()

    p1 = Policy(version="1.4", name="p1", rules=[])
    p2 = Policy(version="1.4", name="p2", rules=[])

    # Stage, validate, approve, activate v1
    gov_mgr.register_draft("pol", "1.0.0", p1)
    gov_mgr.validate_policy("pol", "1.0.0")
    gov_mgr.approve_policy("pol", "1.0.0", approver_identity="admin")
    gov_mgr.activate_policy("pol", "1.0.0")

    # Stage, validate, approve, activate v2
    gov_mgr.register_draft("pol", "2.0.0", p2)
    gov_mgr.validate_policy("pol", "2.0.0")
    gov_mgr.approve_policy("pol", "2.0.0", approver_identity="admin")
    gov_mgr.activate_policy("pol", "2.0.0")
    assert gov_mgr.get_active_policy("pol").name == "p2"

    # Execute atomic rollback
    rolled_back_version = gov_mgr.rollback_policy("pol")
    assert rolled_back_version == "1.0.0"
    assert gov_mgr.get_active_policy("pol").name == "p1"


# -----------------------------------------------------------------------------
# 7. Deployment Manifests Validation
# -----------------------------------------------------------------------------

def test_deployment_manifests_yaml_validity():
    manifest_paths = glob.glob("deployments/**/*.yaml", recursive=True) + glob.glob(
        "deployments/**/*.yml", recursive=True
    )
    assert len(manifest_paths) >= 6, "Expected at least 6 deployment YAML manifests"

    for path in manifest_paths:
        with open(path, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))
            assert len(docs) > 0, f"Empty YAML file: {path}"
            for doc in docs:
                assert isinstance(doc, dict), f"YAML root is not a mapping in {path}"


def test_dockerfile_hardened_contents():
    dockerfile_path = "deployments/docker/Dockerfile.hardened"
    assert os.path.exists(dockerfile_path)

    with open(dockerfile_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Verify non-root user 10001
    assert "10001" in content
    assert "USER 10001:10001" in content

    # Verify multi-stage build
    assert "FROM python:3.12-slim-bookworm AS builder" in content
    assert "FROM python:3.12-slim-bookworm AS runtime" in content

    # Verify native healthcheck
    assert "HEALTHCHECK" in content
