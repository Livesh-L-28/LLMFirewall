"""Unit, integration, and security tests for Phase 63 — Enterprise Multi-Tenancy."""

import pytest

from llmfirewall import Firewall, FirewallConfig
from llmfirewall.cache import ScanCache
from llmfirewall.core.models import Action, RiskScore, ScanRequest, Severity
from llmfirewall.policy.config import Policy, PolicyRule, RuleCondition
from llmfirewall.tenancy import (
    TenantContext,
    TenantPolicyManager,
    TenantRateLimiter,
    TenantTier,
)


def test_tenant_context_data_model():
    """Verify TenantContext validation and tier assignment."""
    ctx = TenantContext(
        tenant_id="org-acme-corp",
        name="Acme Corporation",
        tier=TenantTier.ENTERPRISE,
        max_requests_per_minute=500,
        allowed_tools=["calculator", "web_fetch"],
    )
    assert ctx.tenant_id == "org-acme-corp"
    assert ctx.tier == TenantTier.ENTERPRISE
    assert ctx.max_requests_per_minute == 500
    assert "calculator" in ctx.allowed_tools


def test_cross_tenant_cache_isolation():
    """Verify ScanCache partitions entries by tenant, preventing cross-tenant leakage or probing."""
    cache = ScanCache(max_size=100)
    fw = Firewall(cache=cache, enable_cache=True)

    text = "Identical prompt executed by different enterprise tenants."

    # 1. Tenant A executes scan
    res_a1 = fw.scan(text, tenant_id="tenant-alpha")
    assert res_a1.tenant_id == "tenant-alpha"
    assert cache.hits == 0
    assert cache.misses == 1

    # 2. Tenant B executes EXACT SAME text -> MUST BE CACHE MISS due to tenant partition
    res_b1 = fw.scan(text, tenant_id="tenant-beta")
    assert res_b1.tenant_id == "tenant-beta"
    assert cache.hits == 0
    assert cache.misses == 2

    # 3. Tenant A executes scan again -> MUST BE CACHE HIT
    res_a2 = fw.scan(text, tenant_id="tenant-alpha")
    assert cache.hits == 1
    assert res_a2.metadata.get("cached") is True

    # 4. Global scan (no tenant) -> MUST BE CACHE MISS
    res_global = fw.scan(text)
    assert cache.hits == 1
    assert cache.misses == 3


def test_tenant_policy_manager_and_isolation():
    """Verify tenant policy manager overlays tenant rules without weakening baseline."""
    manager = TenantPolicyManager()

    # Tenant with stricter policy: block on custom project attribute
    strict_rule = PolicyRule(
        id="strict-rule-1",
        name="block_on_custom_project",
        action=Action.BLOCK,
        description="Block specific confidential project keyword for this tenant",
        conditions=[RuleCondition(custom_predicates={"project": "ProjectSecretAlpha"})],
    )
    custom_policy = Policy(version="1.0.0", rules=[strict_rule])
    manager.register_tenant_policy("tenant-strict", custom_policy)

    engine_default = manager.get_effective_engine("tenant-regular")
    engine_strict = manager.get_effective_engine("tenant-strict")

    zero_risk = RiskScore(score=0.0, max_severity=Severity.LOW)
    # Regular tenant policy allows 'ProjectSecretAlpha'
    dec_reg = engine_default.decide(
        text="test", findings=[], risk_score=zero_risk, context={"project": "ProjectSecretAlpha"}
    )
    assert dec_reg.action == Action.ALLOW

    # Strict tenant policy blocks 'ProjectSecretAlpha'
    dec_strict = engine_strict.decide(
        text="test", findings=[], risk_score=zero_risk, context={"project": "ProjectSecretAlpha"}
    )
    assert dec_strict.action == Action.BLOCK


def test_tenant_rate_limiter_noisy_neighbor_isolation():
    """Verify TenantRateLimiter throttles abusive tenant without affecting other tenants."""
    limiter = TenantRateLimiter(default_rpm=3, window_seconds=10.0)

    t0 = 2000.0
    # Tenant 1 exhausts limit
    assert limiter.allow_request("tenant-1", now=t0) is True
    assert limiter.allow_request("tenant-1", now=t0 + 0.1) is True
    assert limiter.allow_request("tenant-1", now=t0 + 0.2) is True
    assert limiter.allow_request("tenant-1", now=t0 + 0.3) is False  # Throttled

    # Tenant 2 is completely isolated and allowed
    assert limiter.allow_request("tenant-2", now=t0 + 0.4) is True
    assert limiter.allow_request("tenant-2", now=t0 + 0.5) is True


def test_firewall_scan_request_tenant_propagation():
    """Verify tenant_id propagation through ScanRequest and ScanResult."""
    fw = Firewall()
    req = ScanRequest(
        text="Normal harmless query",
        tenant_id="tenant-acme",
        user_id="user-123",
        session_id="sess-xyz",
    )
    res = fw.scan(req)
    assert res.tenant_id == "tenant-acme"
    assert res.metadata.get("tenant_id") == "tenant-acme"


def test_ambiguous_tenant_context_safely_rejected():
    """Verify that conflicting or ambiguous tenant contexts are rejected with ValueError."""
    fw = Firewall()

    # 1. Conflicting parameter vs ScanRequest.tenant_id
    req_a = ScanRequest(text="Safe input query", tenant_id="tenant-alpha")
    with pytest.raises(ValueError, match="Conflicting tenant context"):
        fw.scan(req_a, tenant_id="tenant-beta")

    # 2. Conflicting metadata['tenant_id'] vs ScanRequest.tenant_id
    req_conflict = ScanRequest(
        text="Safe input query",
        tenant_id="tenant-alpha",
        metadata={"tenant_id": "tenant-gamma"},
    )
    with pytest.raises(ValueError, match="Conflicting tenant context"):
        fw.scan(req_conflict)

    # 3. Conflicting tenant in cache key computation
    cache = ScanCache()
    with pytest.raises(ValueError, match="Conflicting tenant context"):
        cache.compute_key(
            text="Safe input query",
            tenant_id="tenant-alpha",
            context={"tenant_id": "tenant-delta"},
        )


def test_cross_tenant_memory_boundary_enforcement():
    """Verify SessionMemoryBoundary enforces strict tenant isolation on agent memories."""
    from llmfirewall.rag.advanced_memory import MemoryProvenanceRecord, SessionMemoryBoundary

    boundary = SessionMemoryBoundary()
    rec = MemoryProvenanceRecord(
        memory_id="mem-isolated-1",
        session_id="sess-shared",
        tenant_id="tenant-finance",
        content_hash="dummy_hash_123",
    )
    boundary.register_memory(rec)

    # 1. Matching session and matching tenant -> Allowed
    ok, msg = boundary.validate_access("mem-isolated-1", requesting_session_id="sess-shared", requesting_tenant_id="tenant-finance")
    assert ok is True

    # 2. Cross-tenant access attempt -> Denied
    ok_cross, msg_cross = boundary.validate_access("mem-isolated-1", requesting_session_id="sess-shared", requesting_tenant_id="tenant-hr")
    assert ok_cross is False
    assert "Cross-tenant memory access denied" in msg_cross

    # 3. Missing tenant requesting tenant-bound memory -> Denied
    ok_missing, msg_missing = boundary.validate_access("mem-isolated-1", requesting_session_id="sess-shared", requesting_tenant_id=None)
    assert ok_missing is False
    assert "Cross-tenant memory access denied" in msg_missing


def test_cross_tenant_persistence_query_isolation():
    """Verify persistence queries strictly isolate tenant data."""
    from llmfirewall.persistence import InMemoryPersistenceAdapter, PersistenceRecord, StorageFilter

    adapter = InMemoryPersistenceAdapter()
    adapter.save(PersistenceRecord(id="rec-alpha-1", tenant_id="tenant-alpha", record_type="audit", payload={"data": "alpha1"}))
    adapter.save(PersistenceRecord(id="rec-beta-1", tenant_id="tenant-beta", record_type="audit", payload={"data": "beta1"}))

    # Query tenant-alpha
    alpha_records = adapter.query(StorageFilter(tenant_id="tenant-alpha"))
    assert len(alpha_records) == 1
    assert alpha_records[0].id == "rec-alpha-1"
    assert all(r.tenant_id == "tenant-alpha" for r in alpha_records)

    # Query tenant-beta
    beta_records = adapter.query(StorageFilter(tenant_id="tenant-beta"))
    assert len(beta_records) == 1
    assert beta_records[0].id == "rec-beta-1"
    assert all(r.tenant_id == "tenant-beta" for r in beta_records)


def test_tenant_identity_propagation_parallel_batch():
    """Verify tenant context propagates correctly through parallel batch inspection."""
    from llmfirewall.runtime.parallel import ParallelScanPool

    pool = ParallelScanPool(max_workers=2)
    requests = [
        ScanRequest(text="Query alpha 1", tenant_id="tenant-alpha"),
        ScanRequest(text="Query beta 1", tenant_id="tenant-beta"),
        ScanRequest(text="Query alpha 2", tenant_id="tenant-alpha"),
    ]
    results = pool.scan_batch(requests)
    assert len(results) == 3
    assert results[0].tenant_id == "tenant-alpha"
    assert results[1].tenant_id == "tenant-beta"
    assert results[2].tenant_id == "tenant-alpha"

