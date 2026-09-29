# Threat Modeling & Attack Graph Example (Phase 33)

This example demonstrates how **LLMFirewall** leverages the underlying Security Knowledge Graph to model multi-step AI attack paths, generate automated threat models, corroborate paths with automated tests, and detect architectural drift.

---

## Running the Example

Run the demonstration script:

```bash
python3 examples/threat_modeling/application.py
```

---

## Key Scenarios Demonstrated

1. **Multi-Step Attack Path Discovery**:
   Identifies the potential chain from external user chat ingress, through prompt injection, to unprotected CRM tool invocation and database exfiltration.
2. **False Positive Prevention**:
   Shows that tools protected by active, verified authorization (`control:rbac_auth`) do **NOT** falsely produce candidate tool-abuse paths.
3. **Automated Threat Modeling**:
   Generates a full AI threat model document including assets, trust boundaries, entry points, candidate paths, and explicit unverified assumptions.
4. **Phase 30 Security Test Corroboration**:
   Ingests automated test results to transition paths from `CANDIDATE` to `TESTED` with high confidence.
5. **Phase 31 Governance Security Gaps**:
   Extracts unmitigated attack paths as `GovernanceFinding` objects ready for release gate evaluation.
6. **Architectural Drift & Baseline Diff**:
   Detects new attack paths when an agent is granted access to a new tool (`tool:admin_shell`).
