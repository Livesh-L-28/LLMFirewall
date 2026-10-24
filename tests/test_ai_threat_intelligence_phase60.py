"""Unit, integration, and security tests for Phase 60 — AI Threat Intelligence."""

import json
import pytest

from llmfirewall.core.models import Finding, Severity, ThreatType
from llmfirewall.threat_intel import (
    AIThreatIndicator,
    IndicatorMatch,
    ThreatFeedValidator,
    ThreatIntelFeed,
    ThreatIntelManager,
    ThreatIntelTrustLevel,
    ThreatPatternType,
)


def test_feed_canonical_hash_and_integrity_verification():
    """Verify deterministic hash computation and feed integrity verification."""
    ind1 = AIThreatIndicator(
        indicator_id="ind-jailbreak-01",
        name="Developer Mode Bypass",
        description="Attempts to toggle fictional developer mode",
        threat_type=ThreatType.JAILBREAK,
        pattern_type=ThreatPatternType.EXACT_KEYWORD,
        pattern="developer mode enabled",
    )
    feed = ThreatIntelFeed(
        feed_id="test.threat.intel",
        version="1.0.0",
        publisher="SecOps AI Intel",
        indicators=[ind1],
    )

    feed_hash = feed.compute_indicators_hash()
    assert isinstance(feed_hash, str) and len(feed_hash) == 64

    # Valid check
    valid, msg = ThreatFeedValidator.validate_feed_integrity(feed, expected_checksum=feed_hash)
    assert valid is True

    # Tampered checksum
    invalid, err_msg = ThreatFeedValidator.validate_feed_integrity(feed, expected_checksum="0" * 64)
    assert invalid is False
    assert "Checksum mismatch" in err_msg


def test_validator_rejects_redos_patterns():
    """Verify validator detects and blocks catastrophic backtracking regular expressions."""
    bad_ind = AIThreatIndicator(
        indicator_id="ind-bad-redos",
        name="Catastrophic ReDoS Pattern",
        description="Dangerous regex pattern",
        threat_type=ThreatType.PROMPT_INJECTION,
        pattern_type=ThreatPatternType.REGEX,
        pattern=r"(a+)+$",  # Classic ReDoS
    )
    errors = ThreatFeedValidator.validate_indicator_safety(bad_ind)
    assert len(errors) >= 1
    assert any("catastrophic backtracking" in e for e in errors)


def test_zero_automatic_trust_and_explicit_approval():
    """Verify external indicators are not evaluated until explicitly approved."""
    ind = AIThreatIndicator(
        indicator_id="ind-external-01",
        name="External Suspicious Tag",
        description="Unverified community indicator",
        threat_type=ThreatType.PROMPT_INJECTION,
        pattern_type=ThreatPatternType.EXACT_KEYWORD,
        pattern="SYSTEM_OVERRIDE_FLAG_ALPHA",
        trust_level=ThreatIntelTrustLevel.UNTRUSTED,
    )
    feed = ThreatIntelFeed(
        feed_id="community.feed",
        version="0.1.0",
        publisher="Untrusted Community",
        indicators=[ind],
    )

    manager = ThreatIntelManager()
    manager.register_feed(feed)

    text = "Query containing SYSTEM_OVERRIDE_FLAG_ALPHA for testing"

    # Default matching requires VERIFIED: should NOT match
    matches_before = manager.match_text(text)
    assert len(matches_before) == 0

    # Explicit approval
    manager.approve_indicator("ind-external-01")

    # Now should match
    matches_after = manager.match_text(text)
    assert len(matches_after) == 1
    assert matches_after[0].indicator_id == "ind-external-01"
    assert matches_after[0].matched_snippet == "SYSTEM_OVERRIDE_FLAG_ALPHA"

    # Convert to Finding
    findings = manager.to_findings(matches_after)
    assert len(findings) == 1
    assert findings[0].detector_name == "ai_threat_intel"
    assert findings[0].threat_type == ThreatType.PROMPT_INJECTION


def test_json_and_yaml_feed_roundtrip():
    """Verify safe import and export of threat intel feeds via JSON and YAML."""
    ind = AIThreatIndicator(
        indicator_id="ind-rt-01",
        name="Secret Exfiltration Probe",
        description="Probe searching for AWS keys",
        threat_type=ThreatType.SECRET,
        pattern_type=ThreatPatternType.EXACT_KEYWORD,
        pattern="export AWS_SECRET_ACCESS_KEY",
        trust_level=ThreatIntelTrustLevel.VERIFIED,
    )
    feed = ThreatIntelFeed(
        feed_id="core.ai.intel",
        version="1.2.0",
        publisher="LLMFirewall Intel Team",
        indicators=[ind],
    )

    manager = ThreatIntelManager()
    manager.register_feed(feed)

    json_str = manager.export_feed_json("core.ai.intel")
    assert "AWS_SECRET_ACCESS_KEY" in json_str

    # Import into new manager
    manager2 = ThreatIntelManager()
    imported_feed = manager2.import_feed_json(json_str, auto_trust=True)
    assert imported_feed.feed_id == "core.ai.intel"
    assert len(manager2.indicators) == 1

    # YAML import
    yaml_str = """
feed_id: yaml.ai.intel
version: 1.0.0
publisher: Tested Publisher
indicators:
  - indicator_id: ind-yaml-01
    name: Token Leak
    description: Leak test
    threat_type: secret
    pattern_type: EXACT_KEYWORD
    pattern: ghp_githubtokenhere
    trust_level: VERIFIED
"""
    manager3 = ThreatIntelManager()
    imported_yaml = manager3.import_feed_yaml(yaml_str, auto_trust=True)
    assert imported_yaml.feed_id == "yaml.ai.intel"
    assert len(manager3.indicators) == 1
