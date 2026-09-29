# AI Security Evaluation & Red-Team Engine Example

This directory contains a self-contained, 100% local, deterministic security evaluation example demonstrating how `LLMFirewall` evaluates its defenses against adversarial prompts, leaked secrets, PII exposures, SSRF, directory traversal, and indirect prompt injection.

## Invariants

* **100% Local Execution**: Zero external network requests or internet dependency.
* **Zero API Keys**: No paid LLM APIs or credentials required.
* **Deterministic Results**: Reproducible test passes and latency benchmarks.
* **Zero Secret Leakage**: Reports display sanitized metadata and test IDs rather than raw secret payloads.

## Running the Evaluation

Execute the demo script directly:

```bash
python run_evaluation.py
```

Or run via the LLMFirewall CLI:

```bash
# Human-readable report
llmfirewall eval run

# Export as JSON
llmfirewall eval run --format json

# Export as SARIF for GitHub Security tab
llmfirewall eval run --format sarif --output results.sarif

# Export as JUnit XML for CI/CD test reporting
llmfirewall eval run --format junit --output results.xml

# Capture security baseline
llmfirewall eval baseline --output baseline.json

# Check against baseline for security regressions
llmfirewall eval run --baseline baseline.json
```
