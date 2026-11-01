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

### Setup Environment
1. **Clone the repository:**
   ```bash
   git clone https://github.com/Livesh-L-28/LLMFirewall.git
   cd LLMFirewall
   ```

2. **Create and activate a virtual environment (Python >= 3.9):**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install in editable mode with development dependencies:**
   ```bash
   pip install --upgrade pip
   pip install -e ".[dev,fastapi]"
   ```

### Quality Assurance & Testing Gates
Run local verification before submitting pull requests:

```bash
# 1. Run full test suite
pytest -q

# 2. Run dedicated security regression test suites
pytest tests/test_sec*.py -v

# 3. Run PII & SSN validation tests
pytest tests/test_pii.py -v

# 4. Run policy & governance tests
pytest tests/test_governance.py -v

# 5. Run static code analysis & linting
ruff check src tests

# 6. Check for git whitespace defects
git diff --check
```

### Protected File Invariant
`tests/test_secrets.py` is a protected baseline test suite. Its SHA-256 hash must remain exactly:
`d5ca47fd85349bf4ef6d7944ab9a9f131aa27877b58bb90b31532203d7420e41`.
Do not modify or replace this file.

### Pull Request Guidelines
1. Create a focused topic branch from `main` (`git checkout -b feature/my-enhancement`).
2. Adhere strictly to the zero-leakage invariant (no live secrets or raw user prompts in tests, logs, or exceptions).
3. Ensure all tests and Ruff checks pass cleanly.
4. Stage only explicitly modified files (never `git add .` or `git add -A`).
5. Open a Pull Request using our [PR Template](.github/pull_request_template.md).

---

## 4. Reporting Security Vulnerabilities

Please do not report security vulnerabilities through public GitHub issues. Follow the coordinated disclosure instructions outlined in [SECURITY.md](SECURITY.md).
