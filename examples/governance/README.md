# LLMFirewall Phase 31: AI Security Governance & Continuous Release Gates

This directory demonstrates **evidence-based security assurance and release gating** for AI applications.

---

## Overview

Phase 30 answers:
> "Does the system pass our security tests?"

Phase 31 answers:
> "Should this version be allowed to proceed through the software lifecycle based on configured security requirements?"

Key principles:
1. **Evidence-Based Assurance**: LLMFirewall evaluates configured security controls against verifiable evidence envelopes (test results, model hashes, configuration snapshots, dependency states).
2. **Missing Evidence != PASS**: Missing required test suites or data triggers `REVIEW` or `BLOCK`, never silent `PASS`.
3. **Auditable Risk Acceptance**: Waivers are strictly time-bounded, scoped, and cryptographically verified.
4. **Lineage Preservation**: Emergency overrides authorize release with exceptions while preserving underlying failed gate records in audit logs and manifests.

---

## File Structure

- `policy.yaml`: Declarative governance policy specifying required gates, pass-rate thresholds, and severity block conditions.
- `baseline.json`: Cryptographically anchored security baseline with SHA-256 integrity digest.
- `application.py`: Complete Python code demonstrating evidence collection, release gating, and programmatic enforcement.

---

## Running the Example

Run the Python demonstration:

```bash
python3 examples/governance/application.py
```

Evaluate release gates using the CLI:

```bash
llmfirewall gate --policy examples/governance/policy.yaml
```

Inspect security baseline integrity:

```bash
llmfirewall baseline compare --current examples/governance/baseline.json --baseline examples/governance/baseline.json
```
