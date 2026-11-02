# LLMFirewall-Core: Independent Developer Feedback Template

> [!IMPORTANT] Confidentiality & Ground Rules
> **Never include proprietary prompts, confidential enterprise data, production API keys, or internal network hostnames in this report.** All exercises should be run using synthetic or sanitized sample data.

---

## Part 1: Participant & Environment Profile

| Field | Developer Input |
|---|---|
| **Evaluator ID / Handle** | *(Optional GitHub handle or alias)* |
| **Primary Engineering Persona** | [ ] Python Backend Developer <br> [ ] GenAI / Prompt Engineer <br> [ ] RAG Systems Developer <br> [ ] AI Agent Developer <br> [ ] Application Security / DevSecOps Engineer |
| **Operating System & Architecture** | *(e.g. macOS Sonoma 14.5 arm64, Ubuntu 22.04 LTS x86_64, Windows 11 WSL2)* |
| **Python Runtime Version** | *(e.g. Python 3.9.18, 3.10.12, 3.11.8, 3.12.2)* |
| **Package Version Evaluated** | *(e.g. llmfirewall-core 1.4.0)* |
| **Frameworks Tested** | *(e.g. FastAPI 0.111.0, OpenAI 1.35.0, Anthropic 0.28.0, LangChain 0.2.5, LangGraph 0.1.0)* |

---

## Part 2: Task Execution & Outcome Checklist

Please record the outcome, time taken, and any blockers encountered across the 10 evaluation tasks:

| Evaluation Task | Outcome | Duration (min) | Notes / Blockers Encountered |
|---|:---:|:---:|---|
| **Task 1: Clean Installation & Footprint** | [ ] Pass <br> [ ] Fail | | *(Did pip install cleanly? Any C-extension issues?)* |
| **Task 2: Basic Prompt Scan & Trace** | [ ] Pass <br> [ ] Fail | | *(Did benign pass? Did injection block? Did trace explain?)* |
| **Task 3: Policy-as-Code Configuration** | [ ] Pass <br> [ ] Fail | | *(Did custom YAML policy parse and apply rules?)* |
| **Task 4: PII Redaction & Safe Audit** | [ ] Pass <br> [ ] Fail | | *(Did processed_text scrub PII? Did safe_dict omit raw text?)* |
| **Task 5: Web API & Middleware Defense** | [ ] Pass <br> [ ] Fail | | *(Did middleware drop attack with HTTP 403 before route execution?)* |
| **Task 6: Streaming Token Guardrail** | [ ] Pass <br> [ ] Fail | | *(Did StreamingTextGuard intercept split-token secrets?)* |
| **Task 7: Agent Tool Authorization** | [ ] Pass <br> [ ] Fail | | *(Were SSRF 169.254.169.254, command injection & traversal blocked?)* |
| **Task 8: Multi-Turn Conversation State**| [ ] Pass <br> [ ] Fail | | *(Did ConversationState accumulate and catch multi-turn probes?)* |
| **Task 9: Error Handling & Resilience** | [ ] Pass <br> [ ] Fail | | *(Did @protect raise SecurityBlockError? Did breaker isolate?)* |
| **Task 10: Documentation & Overall DX** | [ ] Pass <br> [ ] Fail | | *(Rate clarity 1–5; record Time to First Scan)* |

---

## Part 3: Qualitative Developer Experience (DX) Assessment

### 3.1 Friction Points & Usability
1. **Time to First Scan (TTFS)**: Approximately how many minutes elapsed between `pip install` and your first successful scan?
   - `[ ] < 5 min` | `[ ] 5–10 min` | `[ ] 10–20 min` | `[ ] > 20 min`
2. **Import Paths & API Design**:
   - Were the canonical imports (`from llmfirewall import Firewall, Action, SecurityBlockError`) intuitive?
   - Did any function signatures behave unexpectedly?
3. **Documentation Clarity**:
   - Were code snippets copy-pasteable without missing imports or undocumented prerequisites?
   - Which guides were most or least useful?

### 3.2 False-Positive / False-Negative Observations
- Did you observe any legitimate, benign application queries falsely blocked?
- Did you observe any adversarial jailbreak or prompt injection bypass?
*(If yes, please provide a minimal reproducible example using `BUG_REPORT_TEMPLATE.md`)*

### 3.3 Production Feasibility
- Would you feel comfortable deploying this SDK into your development or production stack?
  - `[ ] Yes, ready for production`
  - `[ ] Yes, but need additional framework adapters (specify below)`
  - `[ ] Maybe, pending external certification or security review`
  - `[ ] No, encountered blockers (specify below)`
- What additional features or integrations are essential for your use case?

---

## Part 4: Consent & Public Attribution Preferences

In accordance with our privacy principles, participation is voluntary and personal details are never published without explicit consent:

- [ ] **I agree to have my technical feedback triaged anonymously to improve LLMFirewall-Core.**
- [ ] *(Optional)* **I permit attributing this feedback to my public GitHub handle:** `@___________`
- [ ] *(Optional)* **I permit referencing my project / employer name:** `_______________________`
