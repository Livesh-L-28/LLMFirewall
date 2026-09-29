# Continuous Security Regression Testing

Security guardrails can inadvertently degrade when policies are updated, prompt templates change, or new model versions are deployed.

`LLMFirewall` provides **Continuous Security Regression Testing** to prevent newly introduced false negatives (attacks escaping detection) and false positives (benign inputs rejected).

---

## 1. Stable Test Taxonomy

Regression tests maintain fixed identifiers across versions:

| Identifier Prefix | Focus Area | Example Test ID |
| :--- | :--- | :--- |
| `PI-*` | Prompt Injection & Jailbreaks | `PI-001` (Direct Instruction Override) |
| `PII-*` | PII Masking & Redaction | `PII-001` (Customer Email Address) |
| `SEC-*` | Secret & Credential Exposure | `SEC-001` (OpenAI Project Key) |
| `TOOL-*` | Tool Abuse, SSRF & Paths | `TOOL-001` (Cloud Metadata SSRF) |
| `CAP-*` | Agent Capability Security | `CAP-001` (Ungranted Shell Execution) |
| `RAG-*` | RAG Context Poisoning | `RAG-001` (Document Instruction Override) |
| `MEM-*` | Agent Persistent Memory | `MEM-001` (Persistent Instruction Poisoning) |
| `SUPPLY-*` | AI Supply-Chain Verification | `SUPPLY-001` (Blocked Dependency Check) |
| `CONFIG-*` | Configuration Drift | `CONFIG-001` (Security Configuration Drift) |
| `BENIGN-*` | False Positive Prevention | `BENIGN-001` (Geography Inquiry) |

---

## 2. Baseline Comparison Protocol

A baseline snapshot records the passing and failing state of all tests under an approved policy.

### Creating a Baseline

```bash
# Save approved evaluation baseline
llmfirewall eval baseline --output baseline.json
```

### Comparing Against Baseline

During subsequent CI runs or deployment checks:

```bash
# Compare current execution against baseline
llmfirewall test security --baseline baseline.json --ci
```

### Regression Detection Algorithm

$$\text{Regression} \iff (\text{len}(\text{NewFailures}) > 0) \lor (\Delta\text{FN} > 0) \lor (\Delta\text{FP} > 0)$$

A regression is triggered if:
1. Any test that previously passed in the baseline now fails (`new_failures`).
2. The number of false negatives increases ($\Delta\text{FN} > 0$).
3. The number of false positives increases ($\Delta\text{FP} > 0$).

---

## 3. GitHub Actions CI Example

```yaml
name: Continuous AI Security Regression Gate

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install dependencies
        run: pip install -e .
      - name: Run AI Security Test Suite
        run: llmfirewall test security --suite all --ci --format sarif --output results.sarif
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```
