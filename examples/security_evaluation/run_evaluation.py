"""Standalone example script executing a reproducible, local AI security evaluation."""

from llmfirewall import (
    AttackCategory,
    Firewall,
    Policy,
    SecurityEvaluationEngine,
    format_human_report,
    format_json_report,
    get_builtin_security_test_cases,
)


def run_evaluation_demo():
    print("=" * 68)
    print(" LLMFirewall AI Security Evaluation & Red-Team Engine Demo")
    print("=" * 68)

    # 1. Initialize evaluation engine with standard production firewall
    engine = SecurityEvaluationEngine()

    # 2. Retrieve deterministic test suite
    test_cases = get_builtin_security_test_cases()
    print(f"Loaded {len(test_cases)} deterministic security test cases.")

    # 3. Execute evaluation suite
    print("Executing security evaluation against LLMFirewall...")
    report = engine.run_suite(test_cases=test_cases, suite_name="demo-security-suite")

    # 4. Display formatted human report
    print("\n" + format_human_report(report))

    # 5. Demonstrate regression baseline saving
    print("\nSaving evaluation baseline to 'baseline.json'...")
    with open("baseline.json", "w", encoding="utf-8") as f:
        f.write(format_json_report(report) + "\n")
    print("Baseline saved successfully.")

    # 6. Check for regressions
    print(f"Regressions detected: {report.regressions_detected}")


if __name__ == "__main__":
    run_evaluation_demo()
