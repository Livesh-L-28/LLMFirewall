# LLMFirewall-Core: External Pilot Participant Tracking Ledger

This document maintains the privacy-conscious tracking ledger for the 10-developer external pilot cohort.

> [!IMPORTANT] Privacy & Audit Compliance
> - **Pseudonymous IDs**: Evaluators are identified strictly by pseudonymous reference IDs (`PILOT-001` through `PILOT-010`).
> - **Zero Personal Data Storage**: No personal names, employer names, private email addresses, or IP addresses are stored in this repository file.
> - **No Fabricated Entries**: All rows below are staged as unassigned slots awaiting explicit maintainer authorization and voluntary developer onboarding.

---

## 1. Cohort Configuration Overview

- **Cohort Target**: 10 Independent Developers (2 per persona)
- **Target Distribution**:
  - `PILOT-001`, `PILOT-002`: Python Backend Developers
  - `PILOT-003`, `PILOT-004`: Generative AI Application Developers
  - `PILOT-005`, `PILOT-006`: RAG Systems Developers
  - `PILOT-007`, `PILOT-008`: AI Agent Developers
  - `PILOT-009`, `PILOT-010`: Application Security Engineers
- **Intake Mechanism**: GitHub Issues via `.github/ISSUE_TEMPLATE/`
- **Package Version**: `llmfirewall-core==1.4.0`
- **Evaluation Window**: 7–14 days per participant

---

## 2. Participant Lifecycle Tracking Ledger

| Reference ID | Engineering Persona | Invitation Status | Acceptance Status | Installation Status | Evaluation Status | Feedback Status | Linked GitHub Issues | Completion Date |
|---|---|:---:|:---:|:---:|:---:|:---:|---|:---:|
| `PILOT-001` | Python Backend | *Pending Launch* | — | — | — | — | — | — |
| `PILOT-002` | Python Backend | *Pending Launch* | — | — | — | — | — | — |
| `PILOT-003` | Generative AI | *Pending Launch* | — | — | — | — | — | — |
| `PILOT-004` | Generative AI | *Pending Launch* | — | — | — | — | — | — |
| `PILOT-005` | RAG Systems | *Pending Launch* | — | — | — | — | — | — |
| `PILOT-006` | RAG Systems | *Pending Launch* | — | — | — | — | — | — |
| `PILOT-007` | AI Agents | *Pending Launch* | — | — | — | — | — | — |
| `PILOT-008` | AI Agents | *Pending Launch* | — | — | — | — | — | — |
| `PILOT-009` | Application Security | *Pending Launch* | — | — | — | — | — | — |
| `PILOT-010` | Application Security | *Pending Launch* | — | — | — | — | — | — |

---

## 3. Allowed Status Transition Values

To maintain programmatic consistency, entries in this ledger must use the following standard states:

- **Invitation Status**: `Pending Launch` | `Invited` | `Declined` | `No Response`
- **Acceptance Status**: `Pending` | `Accepted` | `Declined`
- **Installation Status**: `Pending` | `Succeeded` | `Failed` (see linked issue)
- **Evaluation Status**: `Not Started` | `In Progress` | `Completed` | `Abandoned`
- **Feedback Status**: `Awaiting` | `Feedback Received` | `Issues Logged`
- **Linked GitHub Issues**: `#<issue_number>` (e.g. `#104`, `#107`)
- **Completion Date**: `YYYY-MM-DD` (when `FEEDBACK_TEMPLATE.md` is received)
