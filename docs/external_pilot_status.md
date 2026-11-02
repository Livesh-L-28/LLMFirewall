# External Developer Pilot Status & Onboarding Framework

**Package**: `llmfirewall-core`
**Evaluation Target**: v1.4.0 Testing Release
**Status Date**: October 31, 2026
**Governance Principle**: **Strict Evidence-Based Reporting** (Zero Fabricated Metrics)

---

## 1. Pilot Cohort Tracking Table

To ensure complete transparency, targets are maintained strictly separate from verified achievements:

| Metric Indicator | Target Goal | Current Actual | Status Category | Verification Notes |
|---|---:|---:|---|---|
| **Candidate Profiles Prepared** | 5 | **5** | Achieved | Profiled across 5 target specializations |
| **Invitations Sent** | 5 | **0** | Pre-Launch | Held pending explicit maintainer approval |
| **Responses Received** | 5 | **0** | Pre-Launch | No fabricated responses |
| **Successful Installations** | 5 | **0** | Pre-Launch | Verified clean on internal testbed |
| **Independent Integrations Completed** | 3 | **0** | Pre-Launch | 5 internal reference integrations built |
| **Reported External Defects** | 0 critical | **0** | Clean | Internal defects resolved in regression suites |
| **Confirmed Security Findings** | 0 unpatched | **0** | Clean | All confirmed false negatives addressed |

---

## 2. Target Participant Profiles

We have designed structured evaluation tracks for five distinct developer profiles:

1. **Python Backend Engineer (FastAPI / Starlette)**
   - *Scope*: Deploying `LLMFirewallASGIMiddleware` or `examples/secure_chat_api/`.
   - *Key Evaluation*: Request body interception, HTTP 403 handling, response body latency.
2. **AI Application Developer (OpenAI / Anthropic SDKs)**
   - *Scope*: Integrating `wrap_openai()` or `wrap_anthropic()` into conversational endpoints.
   - *Key Evaluation*: Seamless drop-in client wrapping, PII redaction propagation, streaming guardrails.
3. **RAG & Knowledge Engineer**
   - *Scope*: Evaluating `examples/secure_rag/` with enterprise documents.
   - *Key Evaluation*: Pre-indexing scanner false positives on domain jargon, quarantine reliability.
4. **Autonomous Agent Developer (LangGraph / MCP)**
   - *Scope*: Deploying `@guard_node` or `MCPToolGuard` on agent tool dispatch loops.
   - *Key Evaluation*: Sandboxing dangerous tool parameters, state dictionary inspection.
5. **Principal Application Security (AppSec) Engineer**
   - *Scope*: Auditing Policy-as-Code engine, zero-retention logging, and benchmark reproducibility.
   - *Key Evaluation*: Verification that raw sensitive prompts are scrubbed from SIEM audit events.

---

## 3. Four Structured Integration Challenges

Participants in the pilot are requested to attempt one or more challenges:

### Challenge 1: The Five-Minute First Scan
- Follow [`docs/quickstart.md`](file:///Users/livesh/LLMFirewall/docs/quickstart.md).
- Measure elapsed time from `pip install llmfirewall-core` to seeing your first `Action.BLOCK` and `Action.REDACT` decision.
- Target: Under 5 minutes.

### Challenge 2: Direct Model SDK Wrapping
- Wrap an existing OpenAI or Anthropic script:
  ```python
  from openai import OpenAI
  from llmfirewall.integrations.openai import wrap_openai

  client = wrap_openai(OpenAI())
  ```
- Send a prompt with synthetic PII (`alice@example.com`) and verify that sanitized tokens reach model completions.

### Challenge 3: FastAPI Web Service Protection
- Mount `LLMFirewallASGIMiddleware` in a FastAPI app or run [`examples/secure_chat_api/app.py`](file:///Users/livesh/LLMFirewall/examples/secure_chat_api/app.py).
- Verify that adversarial prompt injections return clean HTTP 403 responses without worker crashes.

### Challenge 4: Knowledge Ingestion & Context Isolation
- Run [`examples/secure_rag/app.py`](file:///Users/livesh/LLMFirewall/examples/secure_rag/app.py).
- Ingest a sample corporate markdown document and confirm that benign text is approved while indirect injections are quarantined.

---

## 4. Reproducible Bug-Report Template

Testers encountering unexpected behavior should file issues using this format:

```markdown
### Bug Description
[Clear, concise description of the unexpected behavior]

### Environment
- OS: [e.g. macOS 14.4 / Ubuntu 22.04 / Windows WSL2]
- Python Version: [e.g. 3.12.1]
- Package Version: [e.g. llmfirewall-core 1.4.0]
- Integration Used: [e.g. wrap_openai / FastAPI ASGI / MCPToolGuard]

### Minimal Reproducible Example
```python
from llmfirewall import Firewall
fw = Firewall()
result = fw.scan("...")
```

### Expected Behavior
[What should have happened according to docs/api.md]

### Actual Behavior / Error Traceback
[Paste exact console output or stack trace]
```

---

## 5. Security Vulnerability Reporting Instructions

If you discover a security vulnerability, prompt-injection bypass, or credential exposure defect:

> [!CAUTION]
> **Responsible Disclosure**: Do **NOT** file a public GitHub issue for sensitive security vulnerabilities.
>
> Please email the maintainers directly at:
> **`security@llmfirewall.dev`** (or open a private GitHub Security Advisory at [github.com/Livesh-L-28/LLMFirewall/security/advisories/new](https://github.com/Livesh-L-28/LLMFirewall/security/advisories/new)).
>
> Include:
> 1. Exact bypass payload or exploit sequence.
> 2. Affected detector rule or integration adapter.
> 3. Impact assessment and potential remediation.
>
> We acknowledge all security reports within 24 hours and provide patched hotfixes before public disclosure.
