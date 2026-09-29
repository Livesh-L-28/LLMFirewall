"""Unit tests for SecretDetector and secret detection rules."""

import pytest
from llmfirewall.core.models import Severity, ThreatType
from llmfirewall.detectors.secrets.detector import SecretDetector
from llmfirewall.detectors.secrets.entropy import calculate_shannon_entropy
from llmfirewall.detectors.secrets.rules import (
    APIKeyRule,
    CredentialConfigRule,
    PrivateKeyRule,
    TokenRule,
)
from tests.datasets.secret_dataset import (
    SECRET_DETECTION_SAMPLES,
    SECRET_NON_DETECTION_SAMPLES,
)


def test_shannon_entropy():
    # Identical repeated characters have zero entropy
    assert calculate_shannon_entropy("aaaaaaa") == 0.0
    # Common English words have low entropy
    word_entropy = calculate_shannon_entropy("password")
    # High-randomness cryptographic secrets have high entropy
    rand_entropy = calculate_shannon_entropy("xK9#mQ2$vL8!pZ1@wR")
    assert rand_entropy > word_entropy
    assert rand_entropy > 3.0


def test_api_key_rule_isolated():
    rule = APIKeyRule()
    key_str = "".join(["sk-", "proj-", "1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef"])
    text = f"Found key {key_str} here."
    matches = rule.evaluate(text)
    assert len(matches) == 1
    assert matches[0].rule_id == "api_key_rule"
    assert matches[0].severity == Severity.CRITICAL
    assert matches[0].replacement_text == "[REDACTED_OPENAI_KEY]"


def test_token_rule_isolated():
    rule = TokenRule()
    token_str = "".join(["gh", "p_", "0123456789abcdefghijklmnopqrstuvwxyz"])
    text = f"Token: {token_str}"
    matches = rule.evaluate(text)
    assert len(matches) == 1
    assert matches[0].rule_id == "token_rule"
    assert matches[0].replacement_text == "[REDACTED_GITHUB_TOKEN]"


def test_private_key_rule_isolated():
    rule = PrivateKeyRule()
    key_block = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0mockKeyPayloadForTestingOnlyNotRealKeyData\n"
        "-----END RSA PRIVATE KEY-----"
    )
    matches = rule.evaluate(key_block)
    assert len(matches) == 1
    assert matches[0].rule_id == "private_key_rule"
    assert matches[0].severity == Severity.CRITICAL
    assert matches[0].replacement_text == "[REDACTED_PRIVATE_KEY]"


def test_credential_config_rule_isolated():
    rule = CredentialConfigRule()
    conn_str = "postgres://usr:S3cur3P@ssw0rd!@localhost:5432/app"
    matches = rule.evaluate(conn_str)
    assert len(matches) == 1
    assert matches[0].rule_id == "credential_config_rule"
    assert matches[0].severity == Severity.CRITICAL


def test_secret_detector_security_guarantee_no_leak():
    """Verify that Finding.matched_text is STRICTLY None to prevent credential leakage."""
    detector = SecretDetector()
    ant_key = "".join(["sk-", "ant-", "api03-abc123XYZ456_mock789token0123456789"])
    text = f"Key: {ant_key}"
    findings = detector.detect(text)

    assert len(findings) == 1
    assert findings[0].threat_type == ThreatType.SECRET
    # CRITICAL: Matched raw token MUST NOT be stored
    assert findings[0].matched_text is None

    # Redaction span offsets must be valid
    assert findings[0].start_pos is not None
    assert findings[0].end_pos is not None
    assert text[findings[0].start_pos:findings[0].end_pos] == ant_key
    assert findings[0].replacement_text == "[REDACTED_ANTHROPIC_KEY]"


@pytest.mark.parametrize("sample,expected_rule", SECRET_DETECTION_SAMPLES)
def test_secret_detection_dataset(sample, expected_rule):
    detector = SecretDetector()
    findings = detector.detect(sample)

    assert len(findings) >= 1, f"Failed to detect secret in: {sample}"
    rule_ids = [f.metadata.get("rule_id") for f in findings]
    assert expected_rule in rule_ids
    assert findings[0].threat_type == ThreatType.SECRET
    assert findings[0].matched_text is None  # Safety invariant


@pytest.mark.parametrize("sample", SECRET_NON_DETECTION_SAMPLES)
def test_secret_non_detection_dataset(sample):
    detector = SecretDetector()
    findings = detector.detect(sample)
    assert len(findings) == 0, f"False positive detected on benign text: '{sample}' -> {findings}"


def test_secret_detector_metadata():
    detector = SecretDetector()
    assert detector.metadata.name == "secret_detector"
    assert ThreatType.SECRET in detector.metadata.supported_threats
    assert "input" in detector.metadata.supported_directions
    assert "output" in detector.metadata.supported_directions
