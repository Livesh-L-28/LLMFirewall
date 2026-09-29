# Continuous AI Security Testing & Red-Team Example

This example demonstrates how to use `LLMFirewall` Phase 30 to continuously test AI systems, run red-team defense suites, generate synthetic attack vectors, and produce static HTML dashboard reports.

---

## What This Example Demonstrates

1. **Pre-Built Security Suites**: Running declarative prompt injection, tool security, and agent capability suites.
2. **Deterministic Generators**: Generating synthetic test cases with seed reproducibility (`PromptInjectionGenerator`, `SecretGenerator`, `PIIGenerator`).
3. **Multi-Worker Execution**: Running tests concurrently across worker threads with strict failure isolation.
4. **Evidence Sanitization**: Automatically redacting sensitive tokens and customer PII from failure evidence.
5. **Standalone HTML Dashboard**: Exporting self-contained, responsive HTML reports with metrics and findings.

---

## Running the Example

```bash
# Execute the Python demonstration script
python3 -m examples.continuous_security_testing.run_tests

# Open the generated HTML report
open examples/continuous_security_testing/security_report.html
```

---

## Running via CLI

You can also run security test suites directly via the `llmfirewall` CLI:

```bash
# Run the prompt injection suite
llmfirewall test security --suite prompt-injection

# Run agent capability tests with parallel workers
llmfirewall test security --suite agent --workers 2

# Export HTML report
llmfirewall test security --suite all --format html --output test_report.html
```
