# LLMFirewall-Core: Participant Consent & Governance Checklist

> [!IMPORTANT] Ethical Participation & Privacy Notice
> This document establishes the formal consent terms, privacy guarantees, disclosure channels, and attribution boundaries for participants in the LLMFirewall-Core external developer pilot.
> **Participation consent is strictly separated from permission to quote or attribute feedback publicly.**

---

## 1. Participation Terms & Guarantees

Every pilot evaluator is protected by the following ten core principles:

1. **100% Voluntary**: Participation is completely voluntary. The developer is under no obligation to complete all tasks and may decline or withdraw at any time without penalty or explanation.
2. **Zero Financial Compensation**: The external pilot is an open-source technical evaluation program. There is no monetary fee, stipend, or commercial compensation offered or implied.
3. **Time Commitment Boundary**: Core evaluation tasks are structured to take approximately 30–45 minutes of hands-on time, conducted at the developer's convenience within a flexible 7–14-day window.
4. **Synthetic Data Mandate**: Evaluators are strictly prohibited from submitting proprietary employer code, confidential customer data, live API keys, internal network topologies, or private company information. All exercises execute entirely locally on synthetic mock data.
5. **Responsible Vulnerability Disclosure**:
   - General developer experience, installation issues, documentation friction, and ordinary integration bugs are logged via public GitHub Issues using `.github/ISSUE_TEMPLATE/`.
   - Security vulnerabilities, bypass exploits, or severe logic flaws must be reported privately via GitHub Security Advisories or sent to security maintainers per [`SECURITY.md`](../../security.md).
6. **No Implied Endorsement**: Participating in this evaluation does **not** constitute an endorsement of LLMFirewall-Core, its maintainers, or its security guarantees. LLMFirewall-Core will never represent an evaluator or their employer as an "endorser", "sponsor", or "customer" without separate, explicit written agreement.
7. **Right of Immediate Withdrawal**: An evaluator may pause, suspend, or permanently withdraw from the pilot at any point by notifying the maintainer.
8. **Right of Data Erasure**: Upon request, an evaluator's pseudonymous tracking entries or unmerged feedback may be permanently deleted from pilot tracking documents.
9. **Zero Telemetry / Zero Tracking**: The `llmfirewall-core` SDK contains zero network beacons, phone-home mechanisms, analytics telemetry, or remote logging. All execution remains 100% in-process.
10. **Separation of Consent and Public Attribution**: Granting consent to test the software does **not** automatically grant permission to publish the evaluator's name, GitHub handle, or verbatim quotes in public marketing, READMEs, or release announcements. Attribution requires a separate, explicit checkbox.

---

## 2. Formal Participant Consent Checklist

Before onboarding or logging feedback, each participant completes or confirms the following checklist:

### Section A: Core Evaluation Agreement (Required for Participation)
- [ ] **Voluntary Participation**: I confirm that I am participating voluntarily in this open-source technical evaluation.
- [ ] **Environment Autonomy**: I confirm that I have an independent Python development environment (Python 3.9–3.12) to test the package safely.
- [ ] **No Confidential Information**: I agree not to share, submit, or paste any proprietary corporate secrets, production API keys, or confidential customer data in bug reports or feedback questionnaires.
- [ ] **Local Synthetic Testing**: I understand that all pilot tasks are designed to be run against local mock transports or synthetic prompt strings.
- [ ] **Responsible Security Disclosure**: I agree that if I discover an unhandled security vulnerability or bypass technique, I will report it responsibly via GitHub Private Security Advisories rather than publishing an uncoordinated public exploit.
- [ ] **Understanding of Version Scope**: I understand that I am testing the published stable PyPI package `llmfirewall-core==1.4.0`, and that architectural threat boundaries and limitations are documented transparently in [`docs/external-pilot/KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md).
- [ ] **Right to Withdraw**: I understand that I may withdraw from the evaluation at any time without providing any reason.

---

### Section B: Feedback Usage & Public Attribution (Granular Permissions)

Participants choose their preferred level of visibility for their feedback:

- [ ] **Option 1: Public Open-Source Issue Feedback (Standard)**
  > *"I am comfortable submitting technical feedback, reproduction steps, and bug reports publicly via GitHub Issues on `Livesh-L-28/LLMFirewall` under my public GitHub handle."*

- [ ] **Option 2: Private / Pseudonymous Attribution Only**
  > *"I prefer that my feedback be aggregated pseudonymously (e.g., as `Participant PILOT-00X: Python Backend Developer`) in public release summaries and changelogs. Please do not display my real name or GitHub handle in public adoption reports."*

- [ ] **Option 3: Permission for Verbatim Quotation in Release Notes**
  > *"I permit the maintainers to quote my non-confidential technical observations verbatim (e.g. 'Installation took 3 minutes and ASGI middleware dropped in cleanly') in public release documentation or post-pilot retrospectives."*
  > *Preferred Attribution Display*: `___________________________` *(e.g., GitHub handle, full name, or 'Anonymous Backend Engineer')*

---

## 3. Maintainer Verification & Recordkeeping

Maintainers must verify and log the participant's consent selections in the private tracking ledger:

| Verification Checkpoint | Maintainer Initial | Date Confirmed |
|---|:---:|:---:|
| 1. Confirmed Section A (Core Agreement) received | `[  ]` | `YYYY-MM-DD` |
| 2. Confirmed Section B (Attribution preference) noted | `[  ]` | `YYYY-MM-DD` |
| 3. Verified zero confidential data in submitted logs | `[  ]` | `YYYY-MM-DD` |
| 4. Verified issues routed to correct public/private channels | `[  ]` | `YYYY-MM-DD` |
