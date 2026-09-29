# AI Red-Team & Defense Validation Engine

`LLMFirewall` includes a controlled, deterministic **Red-Team Engine** designed to validate and stress-test defenses before deployment.

---

## Threat Model & Attack Vectors

The Red-Team Engine evaluates defenses across five primary threat surfaces:

### 1. Adversarial Prompt Injections & Jailbreaks
* **Direct Instruction Overrides**: Payloads explicitly commanding the model to ignore safety rules.
* **Persona Hijacking (DAN Mode)**: Prompting the model into unconstrained or developer personas.
* **Delimiter & Control Tag Injection**: Exploiting `<|im_start|>`, `<|im_end|>`, and markdown wrappers to forge system messages.
* **System Prompt Leaks**: Coercing the agent to dump developer instructions or internal secrets.

### 2. Tool & Infrastructure Abuse
* **Server-Side Request Forgery (SSRF)**: Directing web-fetch tools toward cloud metadata (`169.254.169.254`) or loopback services (`127.0.0.1`).
* **Path Traversal & Credential Theft**: Instructing file readers to open `../../etc/passwd` or `/etc/shadow`.
* **Destructive Command Execution**: Attempting destructive operations (`rm -rf /`, `DROP TABLE`).
* **Indirect Prompt Injection in Tool Results**: Malicious external websites embedding instruction overrides that hijack the agent upon reading tool output.

### 3. Agent Capability & Delegation Escalation
* **Least-Privilege Violations**: Autonomous agents attempting to execute ungranted capabilities (`shell.execute`).
* **Delegation Escalation**: Parent agents attempting to grant child agents capabilities they do not possess.
* **Action Budget Exhaustion**: Forcing runaway tool execution loops past configured thresholds.
* **Approval Replay Attacks**: Attempting to reuse an approval token on differing resources.

### 4. RAG Context Poisoning
* **Untrusted Document Ingestion**: Documents embedding instruction-bearing overrides designed to take over the generation chain.
* **Citation & Provenance Confusion**: Forging document metadata to bypass trust boundaries.

### 5. Supply-Chain & Integrity Failures
* **Model Weight Tampering**: Corrupting model hash digests.
* **Malicious Dependency Ingestion**: Introducing blacklisted Python dependencies.
* **Configuration Drift**: Tampering with production firewall thresholds.

---

## Deterministic Generators & Fuzzing

The engine provides reproducible, seedable synthetic generators:

```python
from llmfirewall import (
    PromptInjectionGenerator,
    PIIGenerator,
    SecretGenerator,
    ToolSecurityGenerator,
    AgentCapabilityGenerator,
    RAGPoisoningGenerator,
    BoundedFuzzer,
)

# Seedable prompt injection generator
gen = PromptInjectionGenerator()
tests = gen.generate(count=5, seed=42)

# Bounded syntactic fuzzer
fuzzer = BoundedFuzzer(max_cases=10, max_input_size=2048, seed=42)
mutations = fuzzer.fuzz("Ignore all previous instructions")
```

---

## Zero Side-Effect Mock Sandbox

During red-team simulations, test executions must never alter real infrastructure:

* **Mock Filesystem**: In-memory read/write sandbox without disk mutations.
* **Mock Outbox**: In-memory email queue without network connections.
* **Mock Database**: In-memory table store without DBMS modifications.
* **Mock Shell**: Simulated stdout output without `subprocess` calls.

---

## Explicit Non-Goals

The Red-Team Engine strictly exists to **validate defenses safely**. It does NOT implement:
* Autonomous real-world attacks
* Credential theft or exploitation
* Real-world data exfiltration
* Malware generation
* Internet-wide vulnerability scanning
