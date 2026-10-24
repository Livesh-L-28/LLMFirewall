"""Unit, integration, and security tests for Phase 66 — Security Operations Automation."""

import pytest

from llmfirewall import Firewall
from llmfirewall.cache import ScanCache
from llmfirewall.secops import (
    PlaybookActionType,
    PlaybookEngine,
    PlaybookStep,
    SecurityPlaybook,
)


def test_playbook_engine_registration_and_listing():
    """Verify playbook registration, retrieval, and inventory listing."""
    engine = PlaybookEngine()
    playbook = SecurityPlaybook(
        id="pb-isolate-attacker",
        name="Isolate Malicious Attacker",
        description="Quarantines active session and clears contaminated cache",
        steps=[
            PlaybookStep(
                action_type=PlaybookActionType.QUARANTINE_SESSION,
                requires_authorization=False,
            ),
        ],
    )
    engine.register_playbook(playbook)

    assert engine.get_playbook("pb-isolate-attacker") is not None
    assert len(engine.list_playbooks()) == 1
    assert engine.get_playbook("pb-non-existent") is None


def test_playbook_dry_run_simulation():
    """Verify dry-run mode simulates all steps without applying live containment mutations."""
    engine = PlaybookEngine()
    cache = ScanCache(max_size=50)
    fw = Firewall(cache=cache, enable_cache=True)
    fw.scan("hello world")
    assert cache.size == 1

    playbook = SecurityPlaybook(
        id="pb-sim-test",
        name="Simulated Containment",
        steps=[
            PlaybookStep(
                action_type=PlaybookActionType.QUARANTINE_SESSION,
                parameters={"session_id": "sess-attacker-99"},
                requires_authorization=True,
            ),
            PlaybookStep(
                action_type=PlaybookActionType.ROTATE_CACHE,
                requires_authorization=True,
            ),
        ],
    )
    engine.register_playbook(playbook)

    # Execute with dry_run=True (even without authorization)
    result = engine.execute_playbook(
        playbook_id="pb-sim-test",
        context={"cache": cache},
        dry_run=True,
    )

    assert result.dry_run is True
    assert result.status == "SUCCESS"
    assert len(result.step_results) == 2
    assert all(sr.status == "SIMULATED" for sr in result.step_results)

    # Invariants: no actual state mutated
    assert not engine.is_session_quarantined("sess-attacker-99")
    assert cache.size == 1  # cache was NOT rotated


def test_playbook_authorization_gate():
    """Verify consequential actions fail-closed if required authorization is absent."""
    engine = PlaybookEngine()
    playbook = SecurityPlaybook(
        id="pb-consequential",
        name="High Consequence Playbook",
        steps=[
            PlaybookStep(
                action_type=PlaybookActionType.REVOKE_AGENT_CAPABILITY,
                parameters={"agent_id": "agent-007", "capability": "execute_code"},
                requires_authorization=True,
            ),
        ],
    )
    engine.register_playbook(playbook)

    # 1. Attempt execution WITHOUT authorization -> DENIED
    denied_res = engine.execute_playbook(
        playbook_id="pb-consequential",
        dry_run=False,
        authorized_by=None,
    )
    assert denied_res.status == "DENIED"
    assert denied_res.step_results[0].status == "DENIED"

    # 2. Execution WITH authorization -> SUCCESS
    allowed_res = engine.execute_playbook(
        playbook_id="pb-consequential",
        dry_run=False,
        authorized_by="secops-lead@enterprise.corp",
    )
    assert allowed_res.status == "SUCCESS"
    assert allowed_res.step_results[0].status == "SUCCESS"
    assert allowed_res.authorized_by == "secops-lead@enterprise.corp"


def test_playbook_session_quarantine_action():
    """Verify live quarantine locks out designated malicious session and user IDs."""
    engine = PlaybookEngine()
    playbook = SecurityPlaybook(
        id="pb-quarantine",
        name="Quarantine Session",
        steps=[
            PlaybookStep(
                action_type=PlaybookActionType.QUARANTINE_SESSION,
                parameters={"session_id": "sess-malicious-123", "user_id": "usr-bad-actor"},
                requires_authorization=False,
            ),
        ],
    )
    engine.register_playbook(playbook)

    assert not engine.is_session_quarantined("sess-malicious-123")
    assert not engine.is_user_quarantined("usr-bad-actor")

    res = engine.execute_playbook("pb-quarantine")
    assert res.status == "SUCCESS"

    assert engine.is_session_quarantined("sess-malicious-123")
    assert engine.is_user_quarantined("usr-bad-actor")
    assert not engine.is_session_quarantined("sess-innocent-456")


def test_playbook_cache_rotation_action():
    """Verify cache rotation clears active scan cache to prevent poisoned hits."""
    engine = PlaybookEngine()
    cache = ScanCache(max_size=50)
    fw = Firewall(cache=cache, enable_cache=True)
    fw.scan("query 1")
    fw.scan("query 2")
    assert cache.size == 2

    playbook = SecurityPlaybook(
        id="pb-cache-flush",
        name="Purge Contaminated Cache",
        steps=[
            PlaybookStep(
                action_type=PlaybookActionType.ROTATE_CACHE,
                requires_authorization=False,
            ),
        ],
    )
    engine.register_playbook(playbook)

    res = engine.execute_playbook("pb-cache-flush", context={"cache": cache})
    assert res.status == "SUCCESS"
    assert cache.size == 0


def test_playbook_action_ordering_and_partial_failure():
    """Verify ordered execution halts fail-closed on step failure without executing subsequent steps."""
    engine = PlaybookEngine()

    def faulty_handler(params, ctx):
        raise RuntimeError("External network connection timeout during webhook")

    playbook = SecurityPlaybook(
        id="pb-ordering",
        name="Sequential Containment",
        steps=[
            PlaybookStep(
                step_id="step-1",
                action_type=PlaybookActionType.QUARANTINE_SESSION,
                parameters={"session_id": "sess-halt-test"},
                requires_authorization=False,
            ),
            PlaybookStep(
                step_id="step-2",
                action_type=PlaybookActionType.CUSTOM,
                parameters={"handler_key": "custom_fail"},
                requires_authorization=False,
            ),
            PlaybookStep(
                step_id="step-3",
                action_type=PlaybookActionType.REVOKE_AGENT_CAPABILITY,
                parameters={"agent_id": "agent-never-reached"},
                requires_authorization=False,
            ),
        ],
    )
    engine.register_playbook(playbook)

    res = engine.execute_playbook("pb-ordering", context={"custom_fail": faulty_handler})
    assert res.status == "FAILED"
    assert len(res.step_results) == 2  # Step 3 was never executed
    assert res.step_results[0].status == "SUCCESS"
    assert res.step_results[1].status == "FAILED"
    # Step 1 took effect
    assert engine.is_session_quarantined("sess-halt-test")
    # Audit trail contains failure description
    assert any("step-2" in note or "timeout" in note for note in res.audit_notes)


def test_playbook_replay_and_idempotency():
    """Verify repeated execution of playbooks is idempotent and safely logged in audit history."""
    engine = PlaybookEngine()
    playbook = SecurityPlaybook(
        id="pb-idempotent",
        name="Idempotent Quarantine",
        steps=[
            PlaybookStep(
                action_type=PlaybookActionType.QUARANTINE_SESSION,
                parameters={"session_id": "sess-repeated-1"},
                requires_authorization=False,
            ),
        ],
    )
    engine.register_playbook(playbook)

    # First run
    res1 = engine.execute_playbook("pb-idempotent")
    assert res1.status == "SUCCESS"
    assert engine.is_session_quarantined("sess-repeated-1")

    # Second run (replay)
    res2 = engine.execute_playbook("pb-idempotent")
    assert res2.status == "SUCCESS"
    assert engine.is_session_quarantined("sess-repeated-1")

    # Both executions tracked in audit history with distinct execution IDs
    assert len(engine.execution_history) == 2
    assert engine.execution_history[0].execution_id != engine.execution_history[1].execution_id

