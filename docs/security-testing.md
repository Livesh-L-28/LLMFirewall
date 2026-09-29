# Continuous AI Security Testing Engine

`LLMFirewall` Phase 30 introduces a unified **Continuous AI Security Testing + Red-Team + Regression Validation Engine**.

---

## The Core Principle

```text
A SECURITY CONTROL IS NOT TRUSTED
UNTIL IT HAS BEEN TESTED.

TEST ERROR    ≠  TEST PASS
SKIPPED TEST  ≠  SECURE
MODEL OUTPUT  ≠  TEST AUTHORIZATION
TEST RESULT   ≠  SECURITY SCORE
RED-TEAM      =  DEFENSE VALIDATION
```

---

## 1. Architecture

```text
                    TARGET AI SYSTEM
                           │
                    TargetAdapter (Firewall, Mock, HTTP, Agent, RAG)
                           │
                    TestOrchestrator
              ┌────────────┼────────────┐
              ↓            ↓            ↓
        Prompt Tests    Tool Tests   Agent & RAG Tests
              │            │            │
              └────────────┼────────────┘
                           ↓
                    Security Policies
                           ↓
                    Execute Target
                           ↓
                    SecurityObservation
                           ↓
                    Declarative Assertions (Safe, No Eval)
                           ↓
                    Evidence Sanitization (PII & Secret Scrubbing)
                           ↓
                    SecurityFindings & Metrics
                           ↓
              ┌────────────┼────────────┐
              ↓            ↓            ↓
         CLI Report    HTML Report   CI / SARIF / JUnit
```

---

## 2. Test Execution Lifecycle

Every security test executes through an isolated 7-stage lifecycle:
1. **Prepare**: Initialize pseudo-random seeds (`--seed`), reset in-memory sandbox state, emit `security_test_started` audit event.
2. **Execute**: Submit payload to the `TargetAdapter` with strict timeout enforcement (`timeout_seconds`), retry budgets (`retries`), and multiple probabilistic iterations (`runs`).
3. **Observe**: Capture raw output, latency, tool calls, and error codes into an immutable `SecurityObservation`.
4. **Evaluate**: Run declarative assertions without arbitrary code execution. Check policy action matching, false positive (benign blocked), and false negative (attack allowed).
5. **Redact Evidence**: Sanitize error messages and observed outputs with `PIIDetector` and `SecretDetector` before storing in `SecurityFinding`.
6. **Record**: Compute metrics, update detector trigger coverage, evaluate baseline deltas.
7. **Cleanup**: Guarantee execution of cleanup hooks in `finally:` blocks to prevent cross-test state leakage.

---

## 3. Target Adapters

| Adapter | Description | Intended Environment |
| :--- | :--- | :--- |
| `FirewallAdapter` | Evaluates prompt, output, tool call, agent action, and RAG context against local `Firewall` | Local Development, CI/CD |
| `MockAdapter` | Deterministic, offline mock with keyword matching; requires no API key or network | Offline CI Pipelines |
| `HTTPTargetAdapter` | Invokes remote REST/JSON endpoint via HTTP POST with automatic header credential masking | Staging / Pre-Production API Testing |
| `CallableAdapter` | Wraps any Python callable `(prompt: str) -> str` | Custom Frameworks, LangChain, LlamaIndex |
| `AgentAdapter` | Wraps autonomous agent functions and captures requested tool calls | Agentic Workflow Testing |
| `RAGAdapter` | Wraps RAG retrieval and generation functions | RAG Pipeline Validation |

---

## 4. Declarative Assertion Operators

To prevent code injection, assertions are evaluated declaratively without Python `eval(...)`:

* `ACTION_BLOCKED`: Confirms that policy action evaluated to `BLOCK`.
* `ACTION_ALLOWED`: Confirms that benign input was permitted without alarm.
* `ACTION_REDACTED`: Confirms that sensitive text was masked with replacement tokens.
* `THREAT_DETECTED`: Confirms expected `ThreatType` (e.g. `PROMPT_INJECTION`, `PII`) was flagged.
* `TOOL_NOT_CALLED`: Confirms that unauthorized external tools were not invoked.
* `CAPABILITY_DENIED`: Confirms that an ungranted capability was denied.
* `SECRET_NOT_EXPOSED`: Confirms that private credentials do not appear in the response.
* `OUTPUT_CONTAINS` / `OUTPUT_NOT_CONTAINS`: Text substring assertions.
* `OUTPUT_REGEX`: Safe compiled regex pattern verification.
* `STRUCTURED_FIELD`: Dot-delimited JSON field lookup.

---

## 5. Security Test Suites

The framework provides 11 pre-built test suites:

1. **Core Firewall Suite** (`core`): Comprehensive prompt, generation, and tool security.
2. **Prompt Injection Suite** (`prompt-injection`): Instruction overrides, DAN jailbreaks, system prompt extraction, delimiter escaping.
3. **PII Suite** (`pii`): Verification of email, phone, credit card, and SSN detection and redaction.
4. **Secret Suite** (`secrets`): Detection and blocking of OpenAI keys, GitHub PATs, AWS keys, and database connection URIs.
5. **Tool Security Suite** (`tool`): Cloud metadata SSRF, localhost SSRF, directory traversal, and destructive command injection.
6. **Agent Capability Suite** (`agent`): Least-privilege capability enforcement, delegation escalation, and action budgets (Phase 29).
7. **RAG Security Suite** (`rag`): Retrieved document poisoning and indirect prompt injection (Phase 27).
8. **Memory Security Suite** (`memory`): Cross-session persistent instruction poisoning.
9. **Supply-Chain Suite** (`supply-chain`): Model hash verification and dependency policy checks (Phase 28).
10. **Configuration Integrity Suite** (`config`): Policy-as-code and runtime configuration drift detection.
11. **Regression Suite** (`regression`): Historical security regression benchmark.
12. **Full Red-Team Suite** (`all`): Composed union of all 11 suites.

---

## 6. CLI Usage

```bash
# Execute standard core firewall test suite
llmfirewall test security

# Run agent capability security suite with 4 worker threads
llmfirewall test security --suite agent --workers 4

# Run prompt injection tests in CI mode with JSON output
llmfirewall test security --suite prompt-injection --ci --format json

# Export standalone HTML dashboard report
llmfirewall test security --suite all --format html --output report.html

# Discover available security tests
llmfirewall test list --suite prompt-injection

# Discover available pre-built suites
llmfirewall test suites

# Run a single targeted test case
llmfirewall test run PI-001
```

---

## 7. CI/CD Exit Code Contract

| Exit Code | Meaning | Action in Pipeline |
| :--- | :--- | :--- |
| `0` | All required security tests passed | Build succeeds |
| `1` | Security test failure or regression detected | Block pipeline deployment |
| `2` | Configuration, syntax, or usage error | Fix command arguments |
| `3` | Runtime, execution, or I/O error | Investigate test target |
