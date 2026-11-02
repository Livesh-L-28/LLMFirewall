# LLMFirewall-Core: External Pilot Invitation Drafts

> [!CAUTION] Authorization Guardrail
> **THESE INVITATION DRAFTS ARE FOR REVIEW ONLY.**
> Do **NOT** send, email, post, or distribute these drafts without explicit, written maintainer authorization.
> All ten candidate outreach slots remain uncontacted and unsent.

---

## 1. Invitation Draft: Python Backend Developers

**Subject**: Invitation: Evaluating zero-dependency ASGI security guardrails for Python LLM APIs
**Audience**: Backend engineers building FastAPI, Starlette, Flask, or Django APIs integrated with LLMs.

Hi [Developer Name],

I'm reaching out from the open-source **LLMFirewall-Core** project (`llmfirewall-core`). We are building an in-process, deterministic security guardrail library for Python services calling Large Language Models.

We are launching a controlled external evaluation pilot and would value your feedback as a Python backend engineer.

### What LLMFirewall-Core Does
LLMFirewall provides high-performance, in-process security enforcement with zero external database or network dependencies:
- Intercepts malicious prompt injections at the perimeter using `LLMFirewallASGIMiddleware` (returns `HTTP 403 Forbidden` before your worker or endpoint executes).
- In-memory execution with median scan latency of ~0.037 ms for standard queries on benchmark test hardware (scaling with payload size).
- Safe local serialization (`result.safe_dict()`) ensuring local application audit dictionaries scrub cleartext prompts and detected secrets (note: this does not govern upstream third-party cloud LLM retention policies).

### Why Your Evaluation Matters
Backend engineers care deeply about request latency, worker stability, error handling, and avoiding framework bloat. We want to verify that `LLMFirewallASGIMiddleware` drops cleanly into standard ASGI services without breaking route contracts or adding unexpected latency.

### What You Would Test
1. Clean installation from PyPI in an isolated virtual environment (`pip install llmfirewall-core==1.4.0`).
2. Adding `LLMFirewallASGIMiddleware` to a small FastAPI or Starlette test app.
3. Verifying that benign traffic passes with 200 OK and prompt injection attempts return 403 Forbidden.

### Time Commitment & Participation Expectations
- **Participation**: 100% voluntary, unpaid, free, and open-source.
- **Evaluation Window**: Flexible 7–14-day window (core exercises take approximately 30–45 minutes).
- **Feedback Process**: Submitted directly via public GitHub Issues using our `.github/ISSUE_TEMPLATE/` forms.
- **Privacy & Security Guarantee**: All exercises run entirely locally with mock synthetic inputs. Never share real production credentials or customer data. Private security vulnerabilities should be disclosed privately via GitHub Security Advisories per `SECURITY.md`.

### Known Architectural Limitations
- Static pre-execution inspection cannot detect 100% of adversarial semantic evasions (Holdout v4 recall: 60.0% / 40% false-negative rate on unseen attacks with 0% false positives).
- Application-level tool parameter validation does not replace operating system containers or kernel sandboxing.
- Static URL inspection cannot prevent DNS rebinding TOCTOU without an egress proxy or socket pinning.

If you are open to reviewing the evaluation guide, please reply and I will share the walkthrough: [`docs/external-pilot/DEVELOPER_EVALUATION_GUIDE.md`](DEVELOPER_EVALUATION_GUIDE.md).

Best regards,
[Maintainer Name / LLMFirewall Team]

---

## 2. Invitation Draft: Generative AI Application Developers

**Subject**: Invitation: Technical evaluation of in-process prompt & streaming guardrails
**Audience**: Developers building applications directly on OpenAI, Anthropic, Ollama, or LiteLLM.

Hi [Developer Name],

I follow your work in Generative AI application development and would value your perspective on **LLMFirewall-Core** (`llmfirewall-core`).

We are conducting a small, controlled developer evaluation focused on real-world developer experience, streaming protection, and prompt sanitization.

### What LLMFirewall-Core Does
- **Inbound Prompt Inspection**: Detects system prompt overrides and redacts PII before sending queries to upstream model APIs.
- **Sliding-Window Streaming Guard** (`StreamingTextGuard`): Prevents token-split injection evasions across chunk boundaries in real-time streams.
- **Outbound Completion Defense**: Inspects model completions before delivery to users, preventing accidental credential leaks (AWS keys, GitHub tokens).

### Why Your Evaluation Matters
LLM application developers often struggle with heavy guardrail frameworks that introduce complex async abstractions, network dependencies, or high latency. We designed LLMFirewall to be lightweight, deterministic, and modular. We want to know if it fits naturally into your LLM calling workflows.

### What You Would Test
1. Clean installation from PyPI (`pip install llmfirewall-core==1.4.0`).
2. Scanning inbound user prompts and inspecting PII redaction (`result.processed_text`).
3. Wrapping streaming tokens with `StreamingTextGuard`.
4. Intercepting model completions containing accidental secrets.
*(Runnable standalone examples for OpenAI and Anthropic Claude are provided).*

### Time Commitment & Participation Expectations
- **Participation**: 100% voluntary, free, and open-source.
- **Evaluation Window**: 7–14-day window (core exercises take ~30–45 minutes).
- **Feedback Process**: Submitted via GitHub Issues using structured templates.
- **Zero Real Credentials**: Exercises run against mock transports; no live API credits, customer data, or proprietary prompts required.

### Known Architectural Limitations
- Pre-execution heuristics cannot guarantee 100% recall on novel linguistic metaphors or deeply nested roleplay (Holdout v4 recall: 60.0%).
- Anthropic SDK $\ge 2.0.0$ requires `httpx2` transport when injecting mock clients.
- Streaming sliding window buffers emitted chunks; flushed tokens cannot be retroactively recalled if an attack triggers mid-stream.

If you are interested in trying the evaluation guide, let me know and I'll send over the walkthrough: [`docs/external-pilot/DEVELOPER_EVALUATION_GUIDE.md`](DEVELOPER_EVALUATION_GUIDE.md).

Best regards,
[Maintainer Name / LLMFirewall Team]

---

## 3. Invitation Draft: RAG & AI Agent Developers

**Subject**: Invitation: Testing tool sandboxing (SSRF/Command) & RAG context quarantine
**Audience**: Engineers building autonomous agents (LangGraph, AutoGen, CrewAI, MCP) or RAG pipelines.

Hi [Developer Name],

I'm reaching out from the open-source **LLMFirewall-Core** team (`llmfirewall-core`). We are building deterministic guardrails for AI agents and RAG pipelines.

We are organizing an external developer evaluation pilot to test tool call authorization and context quarantine in real agent stacks.

### What LLMFirewall-Core Does
- **Agent Tool Sandboxing** (`fw.check_tool_call`): Validates tool names and parameters prior to execution, intercepting SSRF attempts (e.g. AWS/GCP metadata service `169.254.169.254`), directory traversal, and destructive shell commands.
- **RAG Context Quarantine** (`fw.context_orchestrator`): Scans retrieved document chunks from vector search, quarantining poisoned indirect injection directives before prompt assembly.
- **Runtime Tool Decorator** (`@fw.protect_tool`): Automatically enforces tool parameter boundaries on tool functions.

### Why Your Evaluation Matters
Securing autonomous agents is one of the hardest challenges in AI security. As an agent/RAG developer, your feedback on tool argument validation ergonomics and context quarantine reliability is essential for our upcoming `v1.4.0` release.

### What You Would Test
1. Clean installation in a virtual environment (`pip install llmfirewall-core==1.4.0`).
2. Tool parameter validation against SSRF and shell injection using `fw.check_tool_call()`.
3. Inspecting context chunk quarantine using `fw.context_orchestrator.filter_and_secure()`.
4. Verifying explainable decision traces on blocked tool calls.

### Time Commitment & Participation Expectations
- **Participation**: 100% voluntary, free, and open-source.
- **Evaluation Window**: 7–14-day window (30–45 minutes active time).
- **Feedback Process**: Submitted via GitHub Issues using structured pilot templates.
- **No Production Secrets Needed**: All exercises use synthetic tool inputs and mock vector chunks.

### Known Architectural Limitations
- Static URL inspection cannot prevent TOCTOU DNS rebinding without an egress proxy or socket pinning.
- Filesystem path traversal checking cannot prevent runtime symlink swaps without OS-level `O_NOFOLLOW` / namespaces.
- Tool parameter inspection is an application guardrail, not an operating system container or sandbox (Docker, gVisor).

Please let me know if you are open to reviewing the evaluation guide: [`docs/external-pilot/DEVELOPER_EVALUATION_GUIDE.md`](DEVELOPER_EVALUATION_GUIDE.md).

Best regards,
[Maintainer Name / LLMFirewall Team]

---

## 4. Invitation Draft: Application Security Engineers

**Subject**: Invitation: Independent security evaluation of LLMFirewall-Core policy engine & guardrails
**Audience**: Security engineers, DevSecOps leads, and red teamers evaluating LLM security defenses.

Hi [Security Engineer Name],

I'm reaching out from the open-source **LLMFirewall-Core** project (`llmfirewall-core`). We are developing an open-source, in-process security SDK designed to mitigate prompt injection, PII leakage, and unauthorized tool calls in Python AI applications.

We are launching an evidence-based developer pilot and are seeking rigorous review from Application Security and DevSecOps practitioners.

### What LLMFirewall-Core Does
- **Deterministic Policy-as-Code**: Evaluates security findings with strict mathematical precedence (`BLOCK > REDACT > WARN > ALLOW`).
- **Explainable Audit Tracing**: Generates comprehensive decision traces detailing contributing detectors, risk scores, and matched rules.
- **Local Audit Log Sanitization**: Scrubbing serializations (`result.safe_dict()`) that scrub cleartext prompts and detected credentials from local application dictionaries (note: this does not govern upstream SaaS cloud model data retention).
- **In-Process Boundary Control**: Enforces checks before model invocation and before tool execution.

### Why Your Evaluation Matters
We need AppSec professionals to test our threat model boundaries, audit our policy semantics, inspect our local safe logging scrubbing, and attempt edge-case evasions against our deterministic rules.

### What You Would Test
1. Clean installation in a virtual environment (`pip install llmfirewall-core==1.4.0`).
2. Verifying policy precedence and custom rule configuration using `PolicyConfig`.
3. Auditing safe dictionary serialization (`result.safe_dict()`) for secret scrubbing.
4. Testing tool call sandboxing against metadata SSRF and path traversal patterns.
5. Assessing detection edge cases and identifying false positives or evasion vectors.

### Time Commitment & Participation Expectations
- **Participation**: 100% voluntary, unpaid, free, and open-source.
- **Evaluation Window**: 7–14-day window (30–45 minutes active time).
- **Feedback Process**: General feedback and minor edge-case issues filed via GitHub Issues; zero-day vulnerabilities or high-impact bypasses reported privately via GitHub Security Advisories or `security@llmfirewall.org` per `SECURITY.md`.
- **Zero Confidential Data**: Evaluators must use synthetic test data; no proprietary exploit payloads or employer IP.

### Known Architectural Limitations
- Pre-execution regex detection achieves 100% precision on benchmark datasets but does not guarantee 100% recall against novel, deeply nested semantic evasions (Holdout v4 empirical recall: 60.0% / 40% false-negative rate on unseen attacks).
- Static parameter inspection does not replace operating system containerization or network egress filtering.

If you are interested in auditing the SDK, please reply and I will provide the evaluation package: [`docs/external-pilot/DEVELOPER_EVALUATION_GUIDE.md`](DEVELOPER_EVALUATION_GUIDE.md).

Best regards,
[Maintainer Name / LLMFirewall Team]

---

## 5. Candidate Distribution Checklist (10 Developers)

This checklist ensures two independent evaluators are recruited per persona once launch authorization is granted:

| Persona Category | Participant Reference IDs | Target Stack | Invitation Draft Template | Status |
|---|:---:|---|---|:---:|
| **Python Backend** | `PILOT-001`, `PILOT-002` | FastAPI / Starlette / Uvicorn | Section 1 (Backend Draft) | *Unsent* |
| **Generative AI** | `PILOT-003`, `PILOT-004` | OpenAI SDK / Anthropic SDK / Streaming | Section 2 (GenAI Draft) | *Unsent* |
| **RAG Systems** | `PILOT-005`, `PILOT-006` | LangChain / LlamaIndex / Vector DBs | Section 3 (RAG / Agent Draft) | *Unsent* |
| **AI Agents** | `PILOT-007`, `PILOT-008` | Tool calling / MCP / LangGraph | Section 3 (RAG / Agent Draft) | *Unsent* |
| **Application Security** | `PILOT-009`, `PILOT-010` | Policy-as-Code / Threat Modeling / Red Team | Section 4 (AppSec Draft) | *Unsent* |
