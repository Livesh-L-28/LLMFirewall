"""Runnable demonstration of Phase 30 Continuous AI Security Testing & Red-Team Engine."""

from pathlib import Path

from llmfirewall import (
    Firewall,
    FirewallAdapter,
    PIIGenerator,
    Policy,
    PromptInjectionGenerator,
    SecretGenerator,
    SecurityTestSuite,
    TestOrchestrator,
    format_html_report,
    format_human_report,
    get_agent_capability_suite,
    get_prompt_injection_suite,
    get_tool_security_suite,
)


def main():
    print("=" * 68)
    print("  LLMFirewall Continuous Security Testing & Red-Team Demo")
    print("=" * 68)

    # 1. Load Policy and Initialize Firewall Target
    policy_path = Path(__file__).parent / "policy.json"
    policy = Policy.from_file(str(policy_path))
    fw = Firewall(policy=policy)
    adapter = FirewallAdapter(fw)
    orchestrator = TestOrchestrator(target=adapter)

    # 2. Run Pre-Built Prompt Injection Defense Suite
    print("\n[Step 1] Running Pre-Built Prompt Injection Suite...")
    pi_suite = get_prompt_injection_suite()
    pi_report = orchestrator.run_suite(suite=pi_suite, workers=2)
    print(format_human_report(pi_report))

    # 3. Run Pre-Built Agent Capability Security Suite (Phase 29 Integration)
    print("\n[Step 2] Running Agent Capability Security Suite...")
    agent_suite = get_agent_capability_suite()
    agent_report = orchestrator.run_suite(suite=agent_suite, workers=1)
    print(format_human_report(agent_report))

    # 4. Generate Synthetic Test Cases On-The-Fly with Deterministic Generators
    print("\n[Step 3] Generating Synthetic Test Cases (Deterministic)...")
    pi_gen = PromptInjectionGenerator()
    sec_gen = SecretGenerator()
    pii_gen = PIIGenerator()

    generated_tests = []
    generated_tests.extend(pi_gen.generate(count=3, seed=42))
    generated_tests.extend(sec_gen.generate(count=2, seed=42))
    generated_tests.extend(pii_gen.generate(count=2, seed=42))

    dynamic_suite = SecurityTestSuite(
        name="synthetic-generated-suite",
        version="1.0",
        description="Dynamically generated synthetic attack vectors.",
        tests=generated_tests,
    )
    print(f"Generated {len(dynamic_suite.tests)} synthetic test cases.")

    # 5. Run Synthetic Tests and Export HTML Report
    print("\n[Step 4] Running Synthetic Test Suite & Exporting HTML Report...")
    dyn_report = orchestrator.run_suite(suite=dynamic_suite, workers=2)
    print(format_human_report(dyn_report))

    html_path = Path(__file__).parent / "security_report.html"
    html_content = format_html_report(dyn_report)
    html_path.write_text(html_content, encoding="utf-8")
    print(f"\nHTML Dashboard Report written to: {html_path.resolve()}")
    print("=" * 68)


if __name__ == "__main__":
    main()
