# Project Governance

This document describes the governance structure, decision-making process, and contributor responsibilities for **LLMFirewall-Core**.

---

## 1. Mission and Core Principles

LLMFirewall-Core is an open-source, community-oriented security framework designed to provide deterministic, in-process defense-in-depth protection for Large Language Model (LLM) applications.

Our development is guided by four non-negotiable principles:

1. **Deterministic, Fail-Closed Security**: Policy decisions follow deterministic precedence (`BLOCK > REDACT > WARN > ALLOW`). When a rule triggers a block, requests are terminated immediately.
2. **Minimal Runtime Footprint**: The core library requires zero mandatory external network or database dependencies and incurs sub-millisecond steady-state inspection latency.
3. **Privacy by Design**: Raw prompts, unmasked credentials, and live user PII must never be stored in telemetry, audit traces, logs, or unhandled exceptions.
4. **Honest & Empirical Verification**: All security claims, latency metrics, and detection benchmarks are backed by repeatable tests and explicitly bounded holdout evaluations (e.g. Holdout v4 60.0% recall). We do not market unverified enterprise deployments or absolute security claims.

---

## 2. Maintainer Roles & Responsibilities

### Maintainers

Current Project Lead & Maintainer:
- **Livesh L** (`@Livesh-L-28`)

Maintainers are responsible for:
- Maintaining repository health, issue triage, and continuous integration pipelines.
- Reviewing and approving pull requests against architectural and security standards.
- Ensuring release integrity, cryptographic provenance, and artifact certification.
- Managing coordinated security vulnerability disclosures under [SECURITY.md](SECURITY.md).
- Upholding the [Code of Conduct](CODE_OF_CONDUCT.md) across all project spaces.

### Becoming a Maintainer

Active contributors who demonstrate sustained technical excellence, security rigor, and empathetic community engagement may be nominated by existing maintainers. Criteria include:
- Authorship of significant, high-quality pull requests (features, bug fixes, or documentation).
- Thorough, constructive code reviews on community contributions.
- Demonstrated commitment to test coverage, zero-leakage logging invariants, and documentation accuracy.

---

## 3. Decision-Making Process

We strive for consensus-driven decision-making in public discussions:

1. **Routine Changes**: Bug fixes, documentation clarifications, performance optimizations, and test additions require review and approval from at least one maintainer.
2. **Substantial Changes (RFCs)**: New threat detectors, breaking API modifications, major policy engine refactorings, or new framework adapters require a formal issue discussion or Request for Comments (RFC) issue before implementation.
3. **Consensus & Resolution**: Discussion remains open for community feedback for at least 5 business days. In rare cases where consensus cannot be reached, the Project Lead makes the final architectural determination.

---

## 4. Quality & Review Gates

Every pull request must pass the following mandatory criteria before being merged into `main`:

1. **Automated CI Suite**: All automated tests (`pytest`) must pass across all supported Python versions (3.9 through 3.13).
2. **Static Analysis & Linting**: Code must pass `ruff check src tests` with zero warnings or errors.
3. **Protected Baseline Invariant**: `tests/test_secrets.py` must retain its exact SHA-256 baseline (`d5ca47fd85349bf4ef6d7944ab9a9f131aa27877b58bb90b31532203d7420e41`).
4. **Zero-Retention Audit**: No raw user prompts, unredacted secrets, or PII may be logged or stored.
5. **Documentation & Tests**: Any new public API or bug fix must include companion documentation and regression unit tests.

---

## 5. Security Vulnerability Governance

Security vulnerability reports are handled under an embargoed coordinated disclosure model as specified in [SECURITY.md](SECURITY.md). Maintainers prioritize security advisories and release hotfixes with dedicated regression tests.

---

## 6. Release Governance

LLMFirewall-Core follows [Semantic Versioning 2.0.0](https://semver.org/):
- **Major (X.0.0)**: Breaking public API changes or fundamental architectural shifts.
- **Minor (1.X.0)**: New backward-compatible detectors, framework adapters, policy features, or CLI commands.
- **Patch (1.4.X)**: Backward-compatible bug fixes, performance improvements, documentation updates, and security patches.

Official releases are tagged via Git (`vX.Y.Z`), certified through isolated virtual environment installation tests, and published to PyPI and GitHub Releases.

