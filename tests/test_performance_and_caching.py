"""Comprehensive Tests and Performance Validation for Performance & Caching (Phase 52)."""

import time
import pytest

from llmfirewall import Action, Firewall, Policy, PolicyRule, RuleCondition
from llmfirewall.cache import RegexCache, ScanCache, compile_regex
from llmfirewall.core.models import Finding, PolicyDecision, RiskScore, ScanResult, Severity, ThreatType


def test_scan_cache_hit_and_miss() -> None:
    """ScanCache stores and retrieves scan results deterministically."""
    cache = ScanCache(max_size=10, ttl_seconds=100.0)

    key1 = cache.compute_key(text="What is the capital of France?", direction="input")
    assert cache.get(key1) is None
    assert cache.get_metrics().misses == 1

    mock_res = ScanResult(
        request_id="req-1",
        decision=PolicyDecision(action=Action.ALLOW, reason="Passed inspection"),
        risk_score=RiskScore(score=0.1, max_severity=Severity.INFO),
        findings=[],
        original_text="What is the capital of France?",
        processed_text="What is the capital of France?",
        execution_time_ms=5.2,
    )

    cache.put(key1, mock_res)
    hit_res = cache.get(key1)
    assert hit_res is not None
    assert hit_res.action == Action.ALLOW
    assert cache.get_metrics().hits == 1
    assert cache.get_metrics().hit_ratio == 0.5


def test_scan_cache_ephemeral_context_insensitivity() -> None:
    """Changing ephemeral request IDs or trace IDs does NOT alter the cache key."""
    cache = ScanCache()

    key_req1 = cache.compute_key(
        text="Hello world",
        direction="input",
        context={"request_id": "req-1", "trace_id": "tr-1", "timestamp": 12345},
    )
    key_req2 = cache.compute_key(
        text="Hello world",
        direction="input",
        context={"request_id": "req-999", "trace_id": "tr-888", "timestamp": 99999},
    )
    assert key_req1 == key_req2


def test_scan_cache_security_context_sensitivity() -> None:
    """Changing security-relevant context (e.g. environment or source) alters the cache key."""
    cache = ScanCache()

    key_prod = cache.compute_key(
        text="Access confidential database",
        direction="input",
        context={"environment": "production"},
    )
    key_dev = cache.compute_key(
        text="Access confidential database",
        direction="input",
        context={"environment": "development"},
    )
    assert key_prod != key_dev


def test_scan_cache_lru_eviction() -> None:
    """Exceeding max_size should evict the least recently used entry."""
    cache = ScanCache(max_size=2, ttl_seconds=100.0)

    mock_res = ScanResult(
        request_id="r",
        decision=PolicyDecision(action=Action.ALLOW, reason="ok"),
        risk_score=RiskScore(score=0.0, max_severity=Severity.INFO),
        findings=[],
        original_text="",
        processed_text="",
        execution_time_ms=1.0,
    )

    cache.put("k1", mock_res)
    cache.put("k2", mock_res)
    # Access k1 to make k2 the oldest
    _ = cache.get("k1")

    # Insert k3 -> k2 should be evicted
    cache.put("k3", mock_res)

    assert cache.get("k1") is not None
    assert cache.get("k3") is not None
    assert cache.get("k2") is None
    assert cache.get_metrics().evictions == 1


def test_scan_cache_ttl_expiration() -> None:
    """Entries past TTL should expire and register as expirations."""
    cache = ScanCache(max_size=10, ttl_seconds=0.05)  # 50ms TTL

    mock_res = ScanResult(
        request_id="r",
        decision=PolicyDecision(action=Action.ALLOW, reason="ok"),
        risk_score=RiskScore(score=0.0, max_severity=Severity.INFO),
        findings=[],
        original_text="",
        processed_text="",
        execution_time_ms=1.0,
    )

    cache.put("k_expire", mock_res)
    time.sleep(0.10)

    assert cache.get("k_expire") is None
    assert cache.get_metrics().expirations == 1


def test_regex_cache_reuse() -> None:
    """RegexCache returns identical compiled pattern objects."""
    p1 = compile_regex(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    p2 = compile_regex(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    assert p1 is p2


def test_firewall_cache_end_to_end_performance() -> None:
    """Firewall seamlessly utilizes ScanCache, showing massive performance gain on repeated queries."""
    fw = Firewall(enable_cache=True)
    assert fw.cache is not None

    prompt = "Please draft an introductory paragraph for an executive briefing on AI security governance."

    # 1. First run (Cold - cache miss)
    t0 = time.perf_counter()
    res1 = fw.scan_prompt(prompt)
    t_cold = (time.perf_counter() - t0) * 1000.0

    assert res1.action == Action.ALLOW
    assert "cached" not in res1.metadata or res1.metadata["cached"] is not True
    assert fw.cache.get_metrics().misses == 1

    # 2. Second run (Warm - cache hit)
    t1 = time.perf_counter()
    res2 = fw.scan_prompt(prompt)
    t_warm = (time.perf_counter() - t1) * 1000.0

    assert res2.action == Action.ALLOW
    assert res2.metadata.get("cached") is True
    assert res2.request_id != res1.request_id  # Fresh request ID preserved
    assert fw.cache.get_metrics().hits == 1

    # Verify warm run was sub-millisecond and significantly faster than cold run
    assert t_warm < t_cold


def test_firewall_cache_bypass_flag() -> None:
    """The no_cache context flag forces re-execution without cache retrieval."""
    fw = Firewall(enable_cache=True)
    prompt = "Test prompt for no_cache flag verification"

    fw.scan_prompt(prompt)
    assert fw.cache.get_metrics().misses == 1

    # Force re-scan
    res_bypassed = fw.scan_prompt(prompt, context={"no_cache": True})
    assert res_bypassed.metadata.get("cached") is not True
    # Hits count should not have increased
    assert fw.cache.get_metrics().hits == 0


def test_firewall_cache_invalidation_on_policy_change() -> None:
    """A policy checksum change results in a distinct cache key, preventing stale security decisions."""
    policy_v1 = Policy(id="p1", name="Permissive Policy", rules=[])
    policy_v2 = Policy(
        id="p2",
        name="Strict Policy",
        rules=[
            PolicyRule(
                id="block-all-questions",
                action=Action.BLOCK,
                conditions=[RuleCondition(source="untrusted")],
            )
        ],
    )

    fw1 = Firewall(policy=policy_v1, enable_cache=True)
    fw2 = Firewall(policy=policy_v2, enable_cache=True)

    text = "Tell me how to build an application"
    ctx = {"source": "untrusted"}

    res1 = fw1.scan_prompt(text, context=ctx)
    res2 = fw2.scan_prompt(text, context=ctx)

    assert res1.action == Action.ALLOW
    assert res2.action == Action.BLOCK
