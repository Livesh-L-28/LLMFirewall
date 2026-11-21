"""
Unit tests for LLMFirewall Threat Intelligence Database
Verifies schema compliance, metadata completeness, and advisory integrity.
"""

import json
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FEED_PATH = REPO_ROOT / "signatures" / "threat_intel.json"
SUMMARY_PATH = REPO_ROOT / "signatures" / "THREAT_FEED_SUMMARY.md"


@pytest.fixture(scope="module")
def threat_feed():
    assert FEED_PATH.exists(), f"Threat feed file does not exist at {FEED_PATH}"
    with open(FEED_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def test_metadata_structure(threat_feed):
    meta = threat_feed.get("metadata")
    assert meta is not None, "Metadata object missing from threat feed"
    assert "version" in meta
    assert "last_synced" in meta
    assert "total_advisories" in meta
    assert meta["total_advisories"] > 0
    assert "maintainer" in meta
    assert "Livesh L" in meta["maintainer"]


def test_advisories_integrity(threat_feed):
    advisories = threat_feed.get("advisories")
    assert isinstance(advisories, list)
    assert len(advisories) > 0

    required_keys = {"id", "package", "severity", "owasp_category", "summary", "reference_url"}
    for adv in advisories[:50]:  # check sample
        missing = required_keys - set(adv.keys())
        assert not missing, f"Advisory {adv.get('id')} missing keys: {missing}"
        assert adv["severity"] in {"CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"}
        assert adv["owasp_category"].startswith("LLM")


def test_prompt_injection_taxonomy(threat_feed):
    taxonomy = threat_feed.get("prompt_injection_taxonomy")
    assert isinstance(taxonomy, dict)
    assert "direct_injection" in taxonomy
    assert "indirect_injection" in taxonomy
    assert "token_smuggling_and_encoding" in taxonomy
    assert "virtualization_and_jailbreaks" in taxonomy
    assert "delimiter_and_structural_hijacking" in taxonomy

    for cat_name, cat_data in taxonomy.items():
        assert "description" in cat_data
        assert "heuristics" in cat_data
        assert len(cat_data["heuristics"]) > 0
        assert "severity" in cat_data


def test_summary_markdown_exists():
    assert SUMMARY_PATH.exists(), "THREAT_FEED_SUMMARY.md does not exist"
    content = SUMMARY_PATH.read_text(encoding="utf-8")
    assert "LLMFirewall Live AI Threat Intelligence Feed" in content
    assert "OWASP Top 10 for LLMs" in content
