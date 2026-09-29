# Security Policy & Vulnerability Reporting

Security and privacy are the foundation of LLMFirewall. We take security vulnerabilities seriously and appreciate the contributions of researchers, developers, and security teams who practice responsible disclosure.

---

## 1. Supported Versions

We provide security patches and updates for the following versions:

| Version | Supported | Status |
|:---|:---:|:---|
| `1.0.x` | :white_check_mark: | Current Stable Release (v1.0.0) |
| `0.1.x` | :white_check_mark: | Legacy Maintenance |
| `< 0.1.0` | :x: | Unsupported / Deprecated Alpha |

---

## 2. Reporting a Vulnerability

**DO NOT file public GitHub issues, discussions, or pull requests for suspected security vulnerabilities.**

If you discover:
- A prompt injection bypass or pattern evasion vulnerability,
- A secret detection omission or unmasked credential leakage,
- Sensitive PII disclosure in telemetry, logs, or exceptions,
- An unhandled crash leading to denial of service,
- A supply-chain or dependency security issue,

Please report it through one of the following private channels:

1. **GitHub Private Security Advisory (Preferred)**:
   Navigate to the repository's **Security** tab -> **Advisories** -> **Report a vulnerability**. This allows secure, private end-to-end communication and collaborative patch drafting.
2. **Security Email**:
   Send an encrypted or standard email to `security@llmfirewall.org`.

### What to Include in Your Report
To help us triage and resolve the issue quickly, please provide:
- A clear description of the vulnerability and its potential impact.
- Minimal reproducible proof-of-concept (prompt snippet, API call, or script).
- Environment details: Python version, operating system, LLMFirewall package version.
- Any suggested mitigations or patches (if available).
- Synthetic test data only (never send real API tokens, credentials, or actual personal data).

---

## 3. Vulnerability Response Timeline

- **Initial Acknowledgment**: Within **48 hours** of report receipt.
- **Triage & Reproduction**: Within **5 business days** with severity rating (CVSS).
- **Fix & Patch Development**: Addressed in a private branch with security regression tests.
- **Coordinated Disclosure**: We aim to release a patched version within **30 days** of initial confirmation, after which public disclosure can proceed.

---

## 4. Security Boundaries & Assumptions

LLMFirewall is designed as an **application-layer AI safety and guardrail system**. Please note the following architectural boundaries:

- **Not an IAM System**: LLMFirewall does not replace authentication, authorization, or role-based access control (RBAC). Applications must authenticate users before calling the firewall.
- **Not a WAF / DDoS Shield**: Network-level protections, rate-limiting, and large-scale transport scrubbing should be implemented at the API Gateway or reverse proxy layer.
- **Rule & Pattern Heuristics**: The core firewall uses high-performance deterministic rules and heuristic analyzers. Adversarial AI attacks evolve rapidly; defense-in-depth (combining input sanitization, output guardrails, and restricted agent permissions) is required for critical production workloads.
