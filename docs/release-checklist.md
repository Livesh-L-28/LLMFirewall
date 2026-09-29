# LLMFirewall Release Readiness Checklist

This checklist defines the operational and technical criteria required before advancing from `1.0.0rc1` to `v1.0.0` Production.

---

## Technical Gates

- [x] **Version Baseline**: `__version__ = "1.0.0rc1"` confirmed across codebase.
- [x] **CLI Subcommands**: All 11 primary CLI tools operational and verified (`--help`, exit codes).
- [x] **Code Quality & Linting**: `ruff check .` passes with zero errors.
- [x] **Test Suite**: 570+ unit, integration, and security regression tests passing with 100% success rate.
- [x] **Security Invariants**:
  - [x] Epistemic uncertainty enforced (missing evidence $\neq$ safe).
  - [x] Zero raw secrets logged, displayed, or persisted.
  - [x] Containment hooks enforce `dry_run=True` by default.
  - [x] Runtime protection adheres to `FAIL_CLOSED` on unhandled errors.
- [x] **Distribution Build**: Hatchling builds valid wheel (`.whl`) and sdist (`.tar.gz`).
- [x] **Package Metadata**: `twine check dist/*` passes with zero warnings.
- [x] **Clean Installation**: Wheel installs and runs in isolated Python virtual environment.
- [x] **Documentation Integrity**: No absolute or fabricated security claims; all links and examples verified.

---

## Phase 41 Benchmark & Validation Program Gates

- [ ] Security Benchmark Corpus created and versioned (`benchmark dataset v1`).
- [ ] Prompt Injection evaluation completed and report generated.
- [ ] Jailbreak evaluation completed and report generated.
- [ ] RAG Security evaluation completed and report generated.
- [ ] Agent & Tool Abuse evaluation completed and report generated.
- [ ] Memory Security evaluation completed and report generated.
- [ ] Sensitive-Data Leakage evaluation completed and report generated.
- [ ] Runtime Protection Matrix evaluated (Input, Output, Tool, RAG, Memory).
- [ ] False-Positive and False-Negative analyses documented.
- [ ] Performance Benchmarks measured (latency, CPU, memory, P50, P95, P99).
- [ ] Regression suite organized in `tests/regression/`.
- [ ] Integration validation completed across application patterns.
- [ ] Repository-wide security audit completed.
- [ ] Final release report (`docs/v1-release-report.md`) published.
