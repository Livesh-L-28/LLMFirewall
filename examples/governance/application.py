"""Example demonstration of Phase 31: AI Security Governance & Continuous Release Gates."""

import sys
import time

from llmfirewall import (
    Action,
    AttackCategory,
    Firewall,
    GovernanceDecision,
    GovernancePolicy,
    SecurityBaseline,
    SecurityGateFailure,
    SecurityTestResult,
    Severity,
    TargetType,
    format_governance_human,
)


def main():
    print("=" * 65)
    print(" LLMFirewall Phase 31: Release Governance & Security Gate Demo")
    print("=" * 65)

    # 1. Initialize Firewall and Governance Policy
    firewall = Firewall()
    policy = GovernancePolicy.default_production_policy()
    print(f"Loaded Governance Policy: {policy.name} (v{policy.version}) [Profile: {policy.profile.value}]")

    # 2. Simulate Security Tests execution (Phase 30 integration)
    test_results = [
        SecurityTestResult(
            test_id="PI-001",
            category=AttackCategory.PROMPT_INJECTION,
            target_type=TargetType.PROMPT,
            severity=Severity.HIGH,
            passed=True,
            actual_action=Action.BLOCK,
            expected_action=Action.BLOCK,
        ),
        SecurityTestResult(
            test_id="TOOL-001",
            category=AttackCategory.TOOL_ABUSE,
            target_type=TargetType.TOOL_CALL,
            severity=Severity.HIGH,
            passed=True,
            actual_action=Action.BLOCK,
            expected_action=Action.BLOCK,
        ),
    ]

    # 3. Collect Comprehensive Security Evidence
    evidence = firewall.collect_security_evidence(
        release_id="RELEASE-2026.09-CANDIDATE-01",
        test_results=test_results,
        model_identity={
            "name": "meta-llama/Llama-3-8B-Instruct",
            "version": "1.0",
            "sha256": "8f4e2b01c3d9a7f6e5b4c3d2a1f0e9b8a7f6e5b4c3d2a1f0e9b8a7f6e5b4c3d2",
            "provider": "vllm-local",
        },
        metadata={"app_version": "1.4.0", "environment": "staging"},
    )
    print(f"Collected Security Evidence Envelope: {evidence.release_id}")

    # 4. Evaluate Governance Release Gate
    print("\nEvaluating configured release gates...")
    result = firewall.evaluate_governance(evidence, policy=policy)

    # 5. Output Human-Readable Governance Report
    print("\n" + format_governance_human(result))

    # 6. Programmatic Gate Assertion
    if result.blocked:
        print("\n[BLOCK] Release prohibited by configured security gates!")
        sys.exit(1)
    elif result.decision == GovernanceDecision.REVIEW:
        print("\n[REVIEW] Release requires manual security owner authorization.")
    else:
        print("\n[PASS] All security controls verified. Release candidate approved.")
        print(f"Generated Release Manifest Hash: {result.manifest.manifest_hash[:16]}...")


if __name__ == "__main__":
    main()
