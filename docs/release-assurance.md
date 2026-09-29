# Continuous Release Assurance & Manifests

## 1. Security Release Manifest

The `SecurityReleaseManifest` provides a tamper-evident, machine-readable record of all security controls and evidence evaluated for a release.

Fields:
- `release_id`: Unique release candidate identifier.
- `application_version`: Version of target service.
- `llmfirewall_version`: Package version executing governance.
- `model`: Verified model identity (name, version, sha256, provider).
- `prompt_hash`: SHA-256 digest of system prompts.
- `policy_hash`: SHA-256 digest of governance policy.
- `configuration_hash`: SHA-256 digest of firewall configuration.
- `dependency_hash`: SHA-256 digest of software dependencies.
- `test_suite_version`: Version of evaluated security test suite.
- `baseline_id`: Identifier of compared security baseline.
- `decision`: Overall release gate decision (`PASS`, `FAIL`, `REVIEW`, `BLOCK`).
- `manifest_hash`: Cryptographic SHA-256 digest across all manifest parameters.

---

## 2. Emergency Overrides

If a release must proceed despite a failed gate during an active emergency incident:
- An explicit `GovernanceOverride` must be supplied containing `owner`, `reason`, and `emergency=True`.
- The override sets `passed=True` while **preserving all underlying failed gates and findings**.
- An audit event `override_used` is emitted.
- The override is permanently recorded inside `result.override` and the generated release manifest.

---

## 3. Threat Model for Governance

| Threat | Mitigation |
| :--- | :--- |
| **Governance Bypass** | CLI and API enforce non-zero exit codes and `SecurityGateFailure` exceptions when blocked. |
| **Evidence Tampering** | Evidence artifacts are cryptographically hashed and indexed in `EvidenceManifest`. |
| **Baseline Tampering** | SHA-256 integrity hash detects modifications to stored baseline files. |
| **Waiver Abuse** | Waivers require verified ownership, expiration dates, scoped filters, and checksums. |
| **Secret Leakage** | All fingerprints, reports, manifests, and audit events redact credentials and text spans. |
| **Privilege Expansion** | Agent gate detects additions to granted capabilities compared to baseline. |
