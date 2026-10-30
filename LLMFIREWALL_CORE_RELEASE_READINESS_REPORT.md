# LLMFirewall-Core v1.3.2 — Release Readiness & Production Verification Report

**Document ID**: `READINESS-LLMFIREWALL-1.3.2-20261030`
**Package**: `llmfirewall-core`
**Candidate Version**: `1.3.2`
**Target Release Tag**: `v1.3.2` (Pending PR #1 Merge)
**Evaluated Branch**: `v1.2.0-dev` (Target PR #1 against `main`)
**Evaluated Commit**: `aad745ca9c98fe9542372b64abb1932555789600`
**Evaluated Environment**: macOS 27.0.1 (Darwin arm64 / Apple Silicon), Python 3.12.1, Hatchling 1.33.0
**Audit Date**: October 30, 2026
**Final Verdict**: **CONDITIONAL GO (GO PENDING PR #1 MERGE TO MAIN)**

---

## 1. Executive Release Verdict

| Decision Item | Evaluation Status | Details & Evidence |
|:---|:---:|:---|
| **Security Integrity & Hygiene** | **PASS** | Synthetic fixtures sanitized; zero exposed credentials; zero AST code execution sinks (`eval`, `exec`, `pickle`). |
| **Protected Invariant Preserved** | **PASS** | `tests/test_secrets.py` SHA-256 byte-for-byte identical to required hash: `d5ca47fd85349bf4ef6d7944ab9a9f131aa27877b58bb90b31532203d7420e41`. |
| **Core Detection & SSN Protection** | **PASS** | `SSNSubDetector` enabled by default in `PIIDetector` with SSA structural validation (`is_valid_ssn`) and order-code context suppression. |
| **Policy Validation Semantics** | **PASS** | `validate_gate_references` in `GovernancePolicy` hardened to fail closed (`ValueError`) on missing mandatory gates in `require`. |
| **Release Workflow Governance** | **PASS** | `.github/workflows/release.yml` partitioned into least-privilege `build-and-verify` (`contents: read`) and isolated `publish` (`id-token: write`). Hardened ancestry check `git merge-base --is-ancestor` enforces that release tags must belong to protected `main`. |
| **TestPyPI Workflow Isolation** | **PASS** | `.github/workflows/testpypi.yml` established exclusively on `workflow_dispatch`, requiring explicit `TESTPYPI-UPLOAD` confirmation and dedicated environment isolation. |
| **Automated Test Suite** | **PASS** | **876 Passed, 1 Skipped Optional (`flask`), 0 Failed** in 3.45s across 877 collected tests. |
| **Static Code Quality** | **PASS** | `ruff check src tests` passes cleanly with zero warnings or errors. |
| **Git Diff Whitespace Cleanliness** | **PASS** | `git diff --check` passes with zero trailing whitespace or line-ending defects. |
| **Packaging & Metadata Verification** | **PASS** | Wheel and Sdist pass `twine check`, install cleanly in fresh virtualenvs outside repo checkout, and pass CLI (`llmfirewall 1.3.2`) and API smoke tests. |
| **Release Boundary Invariant** | **PASS** | Zero PR merges, zero commits pushed, zero tags created/moved, zero PyPI/TestPyPI uploads, and zero workflow dispatches performed. |

### Release Recommendation
**CONDITIONAL GO**: The code, packaging artifacts, test suites, and CI workflows are fully production-ready. The **sole operational prerequisite** is merging Pull Request #1 into `main` before pushing tag `v1.3.2`. The automated release ancestry guard will deliberately abort if tag `v1.3.2` is pushed to `v1.2.0-dev` prior to merging into `main`.

---

## 2. Package Metadata Validation

| Field | Expected Value | Actual Configured Value | Status |
|:---|:---|:---|:---:|
| **Package Name** | `llmfirewall-core` | `llmfirewall-core` ([pyproject.toml](file:///Users/livesh/LLMFirewall/pyproject.toml)) | **PASS** |
| **Module Name** | `llmfirewall` | `import llmfirewall` ([src/llmfirewall/__init__.py](file:///Users/livesh/LLMFirewall/src/llmfirewall/__init__.py)) | **PASS** |
| **CLI Binary** | `llmfirewall` | `llmfirewall = "llmfirewall.cli.main:cli"` | **PASS** |
| **Candidate Version** | `1.3.2` | `1.3.2` ([_version.py](file:///Users/livesh/LLMFirewall/src/llmfirewall/_version.py), [pyproject.toml](file:///Users/livesh/LLMFirewall/pyproject.toml)) | **PASS** |
| **Requires-Python** | `>=3.9` | `>=3.9` (Tested 3.9–3.12 compatibility) | **PASS** |
| **License** | Apache-2.0 | Apache-2.0 ([LICENSE](file:///Users/livesh/LLMFirewall/LICENSE)) | **PASS** |
| **Core Dependencies** | Minimal | `pydantic>=2.0.0`, `pyyaml>=6.0.0` (Zero network/DB dependencies) | **PASS** |
| **Optional Extras** | Decoupled | `crypto`, `fastapi`, `flask`, `django`, `langchain`, `llamaindex` | **PASS** |

---

## 3. Production Distribution Artifact Audit

Built into clean directory `dist-v1.3.2-prod/` using `python -m build --outdir dist-v1.3.2-prod`:

| Artifact Filename | Archive Type | Size (Bytes) | SHA-256 Checksum | Twine Check |
|:---|:---|:---:|:---|:---:|
| `llmfirewall_core-1.3.2-py3-none-any.whl` | Built Wheel | 608,319 | `9503a29b432f2cd93d9f0a2658af1f4f809cc429bf9ce83f44193534bb3b3a23` | **PASSED** |
| `llmfirewall_core-1.3.2.tar.gz` | Source Distribution | 694,124 | `405dd08d47b1796b590c4af959c0a971f041b465dbd5fdb1056c29edb13abcdd` | **PASSED** |

### File Exclusion & Hygiene Audit
- **Wheel Exclusion**: Inspected `unzip -l dist-v1.3.2-prod/*.whl`. Confirmed zero test files (`tests/`), zero benchmark scripts (`benchmarks/`), zero documentation drafts, zero `.env` files, and zero Git metadata.
- **Sdist Inclusions**: Inspected `tar -ztvf dist-v1.3.2-prod/*.tar.gz`. Confirmed inclusion of canonical tests, datasets, LICENSE, and README while excluding historical distribution artifacts (`dist-*/`) and caches (`__pycache__`).

---

## 4. Isolated Installation & Smoke Test Verification

Tested from an external working directory (`scratch/`) to ensure no local source tree modules could be inadvertently imported:

### Wheel Installation (`prod_wheel_venv`)
```bash
/scratch/prod_wheel_venv/bin/pip install dist-v1.3.2-prod/llmfirewall_core-1.3.2-py3-none-any.whl
/scratch/prod_wheel_venv/bin/llmfirewall --version
```
- **Observed CLI Version**: `llmfirewall 1.3.2` (Exit code: 0)
- **Benign Input Scan**: `Action.ALLOW` (Exit code: 0)
- **Adversarial Injection**: `Action.BLOCK` (Exit code: 0)
- **Default SSN Scan**: `Action.REDACT` (Original sensitive digits replaced with `[REDACTED_SSN]`)
- **Downstream Leakage Check**: Sensitive SSN digits absent from `processed_text` (Exit code: 0)

### Source Distribution Installation (`prod_sdist_venv`)
```bash
/scratch/prod_sdist_venv/bin/pip install dist-v1.3.2-prod/llmfirewall_core-1.3.2.tar.gz
/scratch/prod_sdist_venv/bin/llmfirewall --version
```
- **Observed CLI Version**: `llmfirewall 1.3.2` (Exit code: 0)
- **Compilation & Build**: Hatchling build backend built wheel from sdist cleanly in isolated sub-environment.
- **Smoke Tests**: 100% parity with wheel tests.

---

## 5. CI/CD Release Workflow Controls

### Production Release Workflow (`.github/workflows/release.yml`)
1. **Least-Privilege Job Splitting**:
   - `build-and-verify`: Permissions strictly limited to `contents: read`. Executes tag ancestry check, SemVer validation, linter (`ruff`), test suite (`pytest`), artifact build, twine check, and isolated virtualenv smoke tests. Uploads `release-distributions` and `SHA256SUMS.txt`.
   - `publish`: Isolated job dependent on `needs: build-and-verify`. Receives `id-token: write` and `environment: pypi`. Downloads distribution artifacts and performs cryptographic hash verification (`sha256sum -c`) prior to invoking `pypa/gh-action-pypi-publish`.
2. **Release Tag Ancestry Guard**:
   - `actions/checkout@v4.2.2` configured with `fetch-depth: 0`.
   - Resolves `${RELEASE_TAG}^{commit}` to peel annotated and lightweight tags to their commit SHA.
   - Executes `git merge-base --is-ancestor "${TAG_COMMIT}" origin/main`.
   - Fails closed with exit code 1 if the tag points to an unmerged development commit.
3. **Action SHA Pinning**:
   - `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` (# v4.2.2)
   - `actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38` (# v5.4.0)
   - `actions/upload-artifact@4cec3d8aa04e39d1a68397de0c4cd6fb9dce8ec1` (# v4.6.1)
   - `actions/download-artifact@cc203385981b70ca67e1cc392babf9cc229d5806` (# v4.1.9)
   - `pypa/gh-action-pypi-publish@7245906fb61fa33a13554f9d5fb856fe61758086` (# v1.14.3)

### Staging TestPyPI Workflow (`.github/workflows/testpypi.yml`)
- Trigger restricted to `workflow_dispatch`.
- Mandatory input `confirm_testpypi_upload` defaulting to `DRY-RUN` (requires typing `TESTPYPI-UPLOAD`).
- Separate environment `testpypi`.
- Target repository restricted to `https://test.pypi.org/legacy/`.

---

## 6. Outstanding Blockers & Operational Checklist

| Item | Action Required | Responsible Party |
|:---|:---|:---|
| **Merge Pull Request #1** | Merge `v1.2.0-dev` into `main` on GitHub | Repository Maintainer |
| **Verify Main Commit** | Run `git checkout main && git pull origin main && git rev-parse HEAD` | Release Engineer |
| **Tag Release v1.3.2** | Run `git tag -a v1.3.2 -m "Release v1.3.2" && git push origin v1.3.2` | Release Engineer |
| **Monitor CI Execution** | Confirm `build-and-verify` passes and `publish` deploys to PyPI | Release Engineer |

---

## 7. Explicit Release Verdict
**CONDITIONAL GO** — All technical remediations, tests, packaging gates, and governance controls have passed. The package is approved for release upon merge of PR #1 into `main`.
