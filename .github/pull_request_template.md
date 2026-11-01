## Description
Briefly describe the change, rationale, and problem it solves.

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding capability)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Security hardening or regression test

## Security & Architectural Checklist
- [ ] **Zero Core Dependencies**: Core runtime does not add dependencies beyond `pydantic>=2.0.0` and `pyyaml>=6.0.0`.
- [ ] **Zero-Leakage Invariant**: Sensitive data, raw prompts, and live secrets are not logged or leaked into exceptions/telemetry.
- [ ] **Synthetic Fixture Safety**: All test fixtures use synthetic tokens and contain zero real credentials or real PII.
- [ ] **Protected Files Intact**: Invariant file `tests/test_secrets.py` remains untouched.
- [ ] **Regression Tests**: Added regression tests for bug fixes or new security detectors.
- [ ] **Local Quality Gates**:
  - [ ] `ruff check src tests` passes cleanly.
  - [ ] `pytest -q` passes without errors.
  - [ ] `git diff --check` passes with zero whitespace defects.
