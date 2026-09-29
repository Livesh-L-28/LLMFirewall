# Contributing to LLMFirewall

Thank you for contributing to LLMFirewall! We welcome contributions that uphold our commitment to security, performance, privacy, and architectural cleanliness.

---

## 1. Core Architectural Governance

Contributors must strictly preserve our separation of concerns:

```text
Detectors detect       -> Emit Finding models (never make policy decisions)
Risk engine scores     -> Quantify composite risk scores & severities
Policy engine decides  -> Maps findings & risk to actions (ALLOW, WARN, BLOCK, REDACT)
Firewall orchestrates  -> Coordinates the end-to-end pipeline & safe processed text
Audit / Telemetry      -> Records measurements & security state without modifying decisions
```

---

## 2. Supply-Chain & Security Standards

To safeguard our users from supply-chain risks, all contributions must adhere to the following security guidelines:

### Dependency Minimization
- **Core Runtime**: Keep the core lightweight with zero mandatory dependencies beyond `pydantic>=2.0.0`.
- Do not introduce external libraries for tasks that the Python standard library accomplishes safely.
- Optional dependencies (e.g. FastAPI) must remain strictly optional and isolated under `[project.optional-dependencies]`.

### Zero Credential / Secret Leakage
- **Never commit real secrets**: Never include live API keys, tokens, passwords, private keys, or actual user PII in test files, examples, benchmarks, or documentation.
- **Use synthetic test tokens**: Always use synthetic identifiers (e.g., `ghp_FAKESECRET1234567890abcdefghijklmnopqrstuv`, `user@example.test`).
- Pre-commit secret scanning: Ensure your working directory is clean of `.env` files or temporary credential dumps before pushing.

### Privacy Invariants in Observability & Logging
- **No prompt or secret logging**: Never write code that logs raw prompts, raw LLM outputs, raw secrets, or unmasked PII to standard loggers, telemetry sinks, or exception messages.
- Always use sanitized summaries, threat category identifiers, or redacted text spans.

### Failure Isolation
- Observability and telemetry components must always fail closed internally (swallowing/logging backend transport errors) to guarantee that telemetry crashes never unblock blocked attacks or crash application pipelines.

### Security Regression Tests
- Whenever a security bypass, parsing flaw, or detection omission is fixed, a corresponding regression test must be added to `tests/` to prevent recurrence.

---

## 3. Development Workflow

1. **Clone the repository:**
   ```bash
   git clone https://github.com/livesh/LLMFirewall.git
   cd LLMFirewall
   ```

2. **Create a virtual environment (Python >= 3.9):**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install editable with dev extras:**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Verify tests and security checks:**
   ```bash
   # Run all tests
   pytest

   # Run dedicated security tests
   pytest -m security

   # Run code linters
   ruff check .
   ```

---

## 4. Reporting Security Vulnerabilities

Please do not report security vulnerabilities through public GitHub issues. Follow the coordinated disclosure instructions outlined in [SECURITY.md](file:///Users/livesh/LLMFirewall/SECURITY.md).
