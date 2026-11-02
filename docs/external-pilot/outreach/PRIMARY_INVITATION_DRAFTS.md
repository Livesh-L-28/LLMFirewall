# LLMFirewall-Core: Individualized Primary Pilot Invitation Drafts

> [!CAUTION] Authorization Guardrail
> **THESE INVITATION DRAFTS ARE PREPARED FOR MAINTAINER REVIEW ONLY.**
> **DO NOT SEND, EMAIL, POST, OR DISTRIBUTE WITHOUT EXPLICIT WRITTEN MAINTAINER AUTHORIZATION.**
> No outreach has been conducted. All eight primary slots remain in `Candidate Proposed` status pending maintainer execution of publication gates.

---

## Overview & Standard Operational Constraints

These personalized invitation drafts are prepared for the **eight primary technical candidates** (`PILOT-001` through `PILOT-008`) who have been verified as strong fits with zero commercial guardrail product conflicts.

### Mandatory Standards Across All Drafts:
1. **Repository & Registry Links**: Every message links to GitHub (`https://github.com/Livesh-L-28/LLMFirewall`) and PyPI (`https://pypi.org/project/llmfirewall-core/`).
2. **Accurate Package Pinning**: Every invitation explicitly references `pip install llmfirewall-core==1.4.0`.
3. **Empirical Security Disclosure**: Explicitly discloses that frozen Holdout v4 evaluation achieved **60.0% empirical recall** (24/40 True Positives, 16/40 False Negatives on unseen adversarial attacks, with 0 False Positives across the 40 tested benign developer queries). Pre-execution static heuristics cannot guarantee universal prevention of novel semantic evasions.
4. **Architectural Boundary Transparency**: Explicitly explains that in-process parameter inspection is an application-level guardrail, not an operating-system container or network egress proxy.
5. **No Zero-Retention Overclaims**: Accurately describes `result.safe_dict()` as local scrubbing of application logs and dictionaries, explicitly noting that it does not govern upstream third-party cloud LLM retention policies.
6. **No Production Adoption Overclaims**: Transparently discloses that LLMFirewall-Core currently has 0 verified external third-party production deployments.
7. **Accurate Latency Framing**: Notes benchmark median latency (~0.037 ms on standard prompts on tested Apple Silicon / x86 hardware) and notes that latency scales with payload length and active detector rules.
8. **Strict Confidentiality & Synthetic Data**: All exercises run locally with synthetic mock data. Evaluators are explicitly instructed never to disclose employer IP, production prompts, API keys, or private customer data.
9. **Voluntary & Non-Endorsement**: Participation is 100% voluntary, unpaid, free, and open-source. We explicitly seek honest technical critique, bug reports, and ergonomic friction logs rather than endorsements or partnerships.

---

## 1. Candidate PILOT-001: Sondre Lillebø Gundersen (`@sondrelg`)

- **Assigned Persona**: Python Backend Developer
- **Verified Public Project**: [`snok/asgi-correlation-id`](https://github.com/snok/asgi-correlation-id), [`snok/django-guid`](https://github.com/snok/django-guid)
- **Technical Relevance**: Lead author of foundational ASGI correlation ID middleware; deep understanding of ASGI `scope`, `receive`, `send` request lifecycles, `contextvars`, and Starlette/FastAPI request pipelines.
- **Audited Public Route**: Public GitHub profile (`https://github.com/sondrelg`) / personal site in bio.

### Draft Invitation Copy

```text
Subject: Technical evaluation: In-process ASGI security guardrails for Python LLM APIs

Hi Sondre,

I’m reaching out from the open-source LLMFirewall-Core project (GitHub: https://github.com/Livesh-L-28/LLMFirewall | PyPI: https://pypi.org/project/llmfirewall-core/). We are building an in-process, deterministic security guardrail library for Python backend services calling Large Language Models.

I’m familiar with your work maintaining `snok/asgi-correlation-id` and your focus on ASGI request lifecycles, contextvars, and middleware chains across Starlette and FastAPI. Because backend engineers care deeply about request latency, middleware execution order, clean error propagation, and avoiding heavyweight runtime dependencies, your perspective on our ASGI middleware design would be invaluable.

We are organizing a small, controlled external developer pilot (7–14 days, approximately 30–45 minutes total time) to gather unfiltered technical feedback on our stable release:
`pip install llmfirewall-core==1.4.0`

What LLMFirewall-Core provides:
- In-process prompt scanning with `LLMFirewallASGIMiddleware` (returns HTTP 403 Forbidden before downstream endpoints or workers execute).
- In-memory deterministic scanning with median latency of ~0.037 ms for standard queries on benchmark test hardware (with zero external network or database dependencies).
- Local audit log sanitization (`result.safe_dict()`) ensuring cleartext prompts and detected secrets are scrubbed from application telemetry dictionaries (note: this does not govern upstream cloud LLM provider retention policies).

Transparent Technical Disclosures:
- Empirical Threat Baseline: In frozen Holdout v4 benchmark evaluation against 80 diverse test prompts, LLMFirewall-Core achieved 60.0% recall (24 TP, 16 FN on unseen adversarial attacks, with 0 false alarms across the 40 benign developer prompts in the test set). Static heuristics cannot guarantee universal prevention of novel semantic evasions.
- Architectural Boundaries: LLMFirewall operates strictly as an in-process application guardrail, not as an OS container or network firewall. URL checks cannot mitigate socket-level TOCTOU DNS rebinding without an egress forward proxy.
- Adoption Status: LLMFirewall-Core currently has 0 verified external production deployments and 0 verified external third-party evaluations. This pilot is our first structured peer review.

Expected evaluation exercises:
1. Installing the package in a clean virtual environment and running a basic scan.
2. Dropping `LLMFirewallASGIMiddleware` into a small Starlette or FastAPI test app.
3. Evaluating request lifecycle handling, middleware ordering, and HTTP 403 status contracts.
4. Measuring local scan overhead and reviewing error message ergonomics (`SecurityBlockError`).

Participation principles:
- 100% voluntary, unpaid, free, and open-source.
- All testing runs locally using synthetic mock inputs. We never ask for or collect proprietary employer code, confidential customer data, or production credentials.
- We request honest technical critique and defect reports, not public endorsements or partnerships. You may decline or withdraw at any point without explanation.
- Feedback is submitted via public GitHub Issues using our structured templates.

If you are open to reviewing the evaluation walkthrough, please let me know and I will share the guide (docs/external-pilot/DEVELOPER_EVALUATION_GUIDE.md). If you are unavailable or prefer not to participate, no worries at all.

Best regards,
[Maintainer Name / LLMFirewall Team]
Repository: https://github.com/Livesh-L-28/LLMFirewall
PyPI: https://pypi.org/project/llmfirewall-core/
```

---

## 2. Candidate PILOT-002: Laurent Savaete (`@laurentS`)

- **Assigned Persona**: Python Backend Developer
- **Verified Public Project**: [`laurentS/slowapi`](https://github.com/laurentS/slowapi)
- **Technical Relevance**: Creator of `slowapi`, the standard rate-limiting middleware for Starlette and FastAPI; expert in ASGI request inspection, client IP resolution, and HTTP error code injection (429/403).
- **Audited Public Route**: Public GitHub profile (`https://github.com/laurentS`) / `openfindata.org`.

### Draft Invitation Copy

```text
Subject: Technical evaluation: Zero-dependency ASGI perimeter guardrails for FastAPI / Starlette

Hi Laurent,

I’m reaching out from the open-source LLMFirewall-Core project (GitHub: https://github.com/Livesh-L-28/LLMFirewall | PyPI: https://pypi.org/project/llmfirewall-core/). We are developing an in-process, deterministic security guardrail library for Python services integrating LLMs.

I follow your work on `slowapi`, which has set the standard for rate-limiting middleware in the Starlette and FastAPI ecosystem. Because you have deep, practical experience intercepting ASGI requests, injecting error responses (HTTP 429/403), and handling client request states cleanly, your feedback on our ASGI perimeter architecture would be extraordinarily helpful.

We are launching an independent developer pilot (7–14 days, ~30–45 minutes of hands-on evaluation) targeting our published stable release:
`pip install llmfirewall-core==1.4.0`

What LLMFirewall-Core does:
- Intercepts malicious prompt injection attempts at the ASGI layer via `LLMFirewallASGIMiddleware` with zero external network or database dependencies.
- Executes deterministic in-memory scans with sub-millisecond median latency on standard queries (~0.037 ms in local benchmarks).
- Enforces local audit log sanitization (`result.safe_dict()`) to scrub sensitive prompts and secrets from application dictionaries.

Transparent Technical Disclosures:
- Empirical Detection Boundaries: On our frozen Holdout v4 evaluation dataset, LLMFirewall-Core achieved 60.0% adversarial recall (24 True Positives, 16 False Negatives on unseen adversarial evasions, with 0 False Positives across the 40 benign developer queries in the test set). Static regex and token heuristics provide fast pre-execution gating, but cannot catch 100% of semantic evasions.
- Architectural Boundaries: Tool and parameter inspection operate at the Python application layer and do not replace OS-level cgroups, containers, or egress firewalls.
- Adoption Status: Reflects 0 verified external third-party production deployments. All performance and threat figures represent internal and synthetic benchmarks.

What you would evaluate:
1. Clean installation in an isolated virtual environment (`pip install llmfirewall-core==1.4.0`).
2. Integrating `LLMFirewallASGIMiddleware` into a minimal FastAPI/Starlette application alongside other ASGI middleware.
3. Testing perimeter rejection semantics (verifying clean HTTP 403 Forbidden handling).
4. Reviewing error ergonomics, exception hierarchies, and ASGI pipeline latency overhead.

Participation details:
- 100% voluntary, unpaid, free, and open-source.
- All testing runs entirely locally against synthetic test endpoints. No proprietary code, production API keys, or confidential employer data are requested or collected.
- We seek candid defect discovery and architectural critique rather than promotional endorsement. You are completely free to decline without explanation.
- Feedback is reported via public GitHub issue templates on our repository.

If you are open to taking a look, please reply and I’ll send over the walkthrough guide (docs/external-pilot/DEVELOPER_EVALUATION_GUIDE.md).

Best regards,
[Maintainer Name / LLMFirewall Team]
Repository: https://github.com/Livesh-L-28/LLMFirewall
PyPI: https://pypi.org/project/llmfirewall-core/
```

---

## 3. Candidate PILOT-003: Yaacov Zamir (`@yaacov`)

- **Assigned Persona**: Generative AI Application Developer
- **Verified Public Project**: [`yaacov/claude-openai-proxy`](https://github.com/yaacov/claude-openai-proxy)
- **Technical Relevance**: Author of a Python translation proxy bridging OpenAI chat completions payloads with Anthropic Vertex AI SDK with Server-Sent Events (SSE) streaming token conversion.
- **Audited Public Route**: Public GitHub profile (`https://github.com/yaacov`).

### Draft Invitation Copy

```text
Subject: Technical evaluation: Streaming token guardrails & client adapters for LLM APIs

Hi Yaacov,

I’m reaching out from the open-source LLMFirewall-Core project (GitHub: https://github.com/Livesh-L-28/LLMFirewall | PyPI: https://pypi.org/project/llmfirewall-core/). We are building an in-process, deterministic guardrail library designed to protect Python applications interacting directly with LLMs.

I came across your work on `yaacov/claude-openai-proxy` and your experience bridging OpenAI message schemas with Anthropic Vertex AI and managing real-time Server-Sent Events (SSE) token streams. Developers working directly with LLM SDKs and streaming chunk handlers face distinct challenges around token boundaries and split-token evasions, making your perspective particularly valuable.

We are conducting a controlled external evaluation pilot (7–14 days, approximately 30–45 minutes total time) on our published stable package:
`pip install llmfirewall-core==1.4.0`

Core capabilities you would test:
- Inbound prompt sanitization and outbound generation inspection using canonical `fw.scan()`.
- Token-boundary protection via `StreamingTextGuard` (protecting sliding-window token streams against split-token bypasses).
- PII and secret redaction invariants (ensuring `result.processed_text` is consumed downstream rather than raw inputs).
- Developer experience with client adapters (`OpenAIGuard`, `AnthropicGuard`).

Transparent Technical Disclosures:
- Empirical Detection Scope: In Holdout v4 benchmark tests against unseen adversarial attacks, LLMFirewall achieves 60.0% recall (24 TP, 16 FN) with zero false positives across the 40 tested benign developer prompts. Pre-execution static scanning cannot guarantee 100% recall on novel semantic attacks.
- Streaming Boundary: `StreamingTextGuard` buffers tokens across sliding character windows; chunks already transmitted to the client before mid-stream attack detection cannot be retroactively recalled.
- Adoption Disclosure: The library has 0 external third-party production deployments; all data reflects synthetic in-process test fixtures.

Participation terms:
- Entirely voluntary, unpaid, and open-source.
- Exercises use synthetic benchmark prompts and mock transports; no live API credits, proprietary customer prompts, or production credentials are required.
- We request honest feedback, edge-case discoveries, and bug reports rather than endorsements. You may decline or stop at any time.
- Feedback is submitted directly through public GitHub Issues.

If you are interested in reviewing the evaluation walkthrough, let me know and I will provide the link (docs/external-pilot/DEVELOPER_EVALUATION_GUIDE.md).

Best regards,
[Maintainer Name / LLMFirewall Team]
Repository: https://github.com/Livesh-L-28/LLMFirewall
PyPI: https://pypi.org/project/llmfirewall-core/
```

---

## 4. Candidate PILOT-004: Vitalii Stepanenko (`@Nayjest`)

- **Assigned Persona**: Generative AI Application Developer
- **Verified Public Project**: [`Nayjest/lm-proxy`](https://github.com/Nayjest/lm-proxy), [`Nayjest/ai-microcore`](https://github.com/Nayjest/ai-microcore), [`Nayjest/Gito`](https://github.com/Nayjest/Gito)
- **Technical Relevance**: Creator of `lm-proxy`, an OpenAI-compatible multi-provider gateway in Python/FastAPI supporting OpenAI, Anthropic, Google, and local models with real-time streaming; author of AI code review tools for vulnerability detection.
- **Audited Public Route**: Public GitHub profile (`https://github.com/Nayjest`).

### Draft Invitation Copy

```text
Subject: Technical evaluation: Multi-provider LLM client guardrails & streaming protection

Hi Vitalii,

I’m reaching out from the open-source LLMFirewall-Core project (GitHub: https://github.com/Livesh-L-28/LLMFirewall | PyPI: https://pypi.org/project/llmfirewall-core/). We are building an in-process Python guardrail engine for applications calling Large Language Models.

I’ve followed your open-source work on `lm-proxy` and `ai-microcore`, particularly your approach to unifying multi-provider LLM access (OpenAI, Anthropic, Google) with real-time token streaming and code security inspection in `Gito`. Because you design multi-model client architectures and streaming pipelines, your feedback on our in-process client adapters and streaming token guardrails would be immensely helpful.

We are organizing an external developer pilot (7–14 days, ~30–45 minutes hands-on) focusing on our published stable release:
`pip install llmfirewall-core==1.4.0`

Key areas for evaluation:
- Pre-execution input validation and outbound completion inspection with `fw.scan()`.
- In-flight token streaming protection using `StreamingTextGuard`.
- Verification of the Redaction Invariant (`result.processed_text`) to sanitize secret and PII leakage across provider boundaries.
- General developer ergonomics, latency overhead, and exception handling (`SecurityBlockError`).

Transparent Technical Disclosures:
- Empirical Detection Boundaries: In frozen Holdout v4 testing against 80 diverse samples, LLMFirewall achieved 60.0% recall on unseen injection attacks with 0% false positives on tested benign developer queries. Static heuristics do not catch 100% of complex semantic evasions.
- Boundary Limitations: In-process scanning provides fast pre-execution gating, but operates strictly as an application guardrail without operating-system isolation.
- Adoption Disclosure: LLMFirewall-Core currently has 0 verified external production deployments.

Participation framework:
- 100% voluntary, unpaid, free, and open-source.
- Evaluators test using local mock models or synthetic prompts. No production API keys, confidential company data, or proprietary prompts are requested.
- We seek objective technical critiques and defect reports rather than endorsements. You are welcome to decline without reason.
- Feedback is collected transparently via structured GitHub Issues.

If you have 30–45 minutes to evaluate the package and share your perspective, please let me know and I will share the evaluation guide (docs/external-pilot/DEVELOPER_EVALUATION_GUIDE.md).

Best regards,
[Maintainer Name / LLMFirewall Team]
Repository: https://github.com/Livesh-L-28/LLMFirewall
PyPI: https://pypi.org/project/llmfirewall-core/
```

---

## 5. Candidate PILOT-005: Bhavnick Minhas (`@bhavnicksm`)

- **Assigned Persona**: RAG Systems Developer
- **Verified Public Project**: [`bhavnicksm/chonkie`](https://github.com/bhavnicksm/chonkie)
- **Technical Relevance**: Creator of `chonkie`, a fast, lightweight text chunking library designed specifically for RAG pipelines; author of recursive, sentence, word, token, and semantic chunking algorithms.
- **Audited Public Route**: Public GitHub profile (`https://github.com/bhavnicksm`) / `docs.chonkie.ai`.

### Draft Invitation Copy

```text
Subject: Technical evaluation: Ingestion guardrails & chunk boundary security for RAG

Hi Bhavnick,

I’m reaching out from the open-source LLMFirewall-Core project (GitHub: https://github.com/Livesh-L-28/LLMFirewall | PyPI: https://pypi.org/project/llmfirewall-core/). We are building an in-process, deterministic security library for Python applications and RAG pipelines.

I’m familiar with your work creating `chonkie` and your deep focus on text chunking architectures (token, recursive, and semantic chunking) optimized for RAG. In RAG pipelines, untrusted external documents introduce indirect prompt injection threats and delimiter disruption at chunk boundaries. Given your expertise in chunking ergonomics and token-level boundaries, your perspective on our RAG context quarantine tools would be invaluable.

We are running a controlled external developer pilot (7–14 days, approximately 30–45 minutes of testing) focusing on our published stable release:
`pip install llmfirewall-core==1.4.0`

What you would evaluate:
1. Clean virtualenv installation and first scan execution.
2. Ingesting partitioned text chunks through LLMFirewall's context quarantine hooks (`fw.context_orchestrator` and `fw.rag`).
3. Testing indirect prompt injection defenses on synthetic document chunks and delimiter escaping.
4. Evaluating library ergonomics, false-positive rates on technical text, and chunk inspection throughput.

Transparent Technical Disclosures:
- Empirical Detection Boundaries: In our Holdout v4 benchmark, heuristic pattern matching achieved 60.0% recall on novel adversarial injections (40% false-negative rate) with zero false positives across 40 benign developer prompts. Complex narrative context smuggling may evade static rules.
- Operational Boundary: In-process scanning filters document chunks in memory, but does not replace vector database access controls or underlying infrastructure security.
- Adoption Disclosure: LLMFirewall-Core reflects 0 verified third-party production deployments.

Participation terms:
- 100% voluntary, unpaid, free, and open-source.
- Testing is performed entirely on synthetic text or open documentation chunks. No proprietary company data or private documents are requested or needed.
- We request honest feedback on performance and usability, not marketing endorsements. You may decline or withdraw at any point without explanation.
- Feedback is submitted via public GitHub Issue forms.

If you are open to reviewing the evaluation walkthrough, please let me know and I will share the guide (docs/external-pilot/DEVELOPER_EVALUATION_GUIDE.md).

Best regards,
[Maintainer Name / LLMFirewall Team]
Repository: https://github.com/Livesh-L-28/LLMFirewall
PyPI: https://pypi.org/project/llmfirewall-core/
```

---

## 6. Candidate PILOT-006: David Mezzetti (`@davidmezzetti`)

- **Assigned Persona**: RAG Systems Developer
- **Verified Public Project**: [`neuml/txtai`](https://github.com/neuml/txtai)
- **Technical Relevance**: Founder of NeuML and creator of `txtai`, an industry-standard all-in-one embeddings database and RAG orchestration framework in Python. Extensive experience with vector indexing, semantic search, and document ingestion.
- **Audited Public Route**: Public GitHub profile (`https://github.com/davidmezzetti`) / `neuml.com`.

### Draft Invitation Copy

```text
Subject: Technical evaluation: In-process security guardrails for Python RAG pipelines

Hi David,

I’m reaching out from the open-source LLMFirewall-Core project (GitHub: https://github.com/Livesh-L-28/LLMFirewall | PyPI: https://pypi.org/project/llmfirewall-core/). We are developing an in-process, zero-dependency Python guardrail engine to protect LLM pipelines against prompt injection, document poisoning, and data leakage.

I’ve long admired your open-source work on `txtai` and your comprehensive approach to semantic search, vector indexing, and RAG orchestration in Python. As RAG pipelines increasingly ingest untrusted third-party documents, securing retrieval context against indirect prompt injection without adding heavy network overhead is a critical challenge. Your perspective as a vector search and RAG framework architect would be tremendously valuable.

We are organizing an external developer pilot (7–14 days, ~30–45 minutes total time) on our published PyPI release:
`pip install llmfirewall-core==1.4.0`

Evaluation scope:
- Scanning retrieved context chunks for indirect prompt injections before passing them to prompt templates.
- Evaluating context quarantine tools (`fw.context_orchestrator`) and delimiter sanitization.
- Measuring in-process scan latency overhead against document chunks.
- Providing feedback on API ergonomics, false positive rates on benign documentation, and integration flexibility.

Transparent Technical Disclosures:
- Empirical Detection Scope: Holdout v4 benchmark measurements reflect 60.0% recall on unseen adversarial prompts (24 TP, 16 FN) with 100% precision (0 false alarms on the 40 tested benign queries). Static heuristic rules provide fast sub-millisecond filtering, but cannot guarantee universal defense against novel semantic evasion strategies.
- Architectural Boundary: Application-layer inspection does not replace OS sandboxing, database security, or egress firewalls.
- Adoption Disclosure: Reflects 0 verified external production deployments.

Participation terms:
- 100% voluntary, unpaid, free, and open-source.
- Evaluators test using synthetic open datasets or public documentation. No confidential enterprise documents or production credentials are requested.
- We seek candid architectural critiques and bug reports, not commercial endorsements. You are free to decline without reason.
- Feedback is reported via public GitHub Issues.

If you are open to taking a look at the evaluation guide, please reply and I’ll send the link (docs/external-pilot/DEVELOPER_EVALUATION_GUIDE.md).

Best regards,
[Maintainer Name / LLMFirewall Team]
Repository: https://github.com/Livesh-L-28/LLMFirewall
PyPI: https://pypi.org/project/llmfirewall-core/
```

---

## 7. Candidate PILOT-007: Aymeric Roucher (`@aymeric-roucher`)

- **Assigned Persona**: AI Agent Developer
- **Verified Public Project**: [`huggingface/smolagents`](https://github.com/huggingface/smolagents)
- **Technical Relevance**: Core creator of `smolagents` at Hugging Face; expert in code-execution agent architectures, tool execution sandboxes, AST inspection, and dangerous action mitigation.
- **Audited Public Route**: Public GitHub profile (`https://github.com/aymeric-roucher`) / portfolio `m-ric.com`.

### Draft Invitation Copy

```text
Subject: Technical evaluation: Pre-execution tool parameter validation & sandboxing for AI agents

Hi Aymeric,

I’m reaching out from the open-source LLMFirewall-Core project (GitHub: https://github.com/Livesh-L-28/LLMFirewall | PyPI: https://pypi.org/project/llmfirewall-core/). We are building an in-process, deterministic security guardrail library for Python LLM applications and autonomous agents.

I follow your work on `smolagents` at Hugging Face and have learned a great deal from your approach to code-execution agents, AST safety checks, and tool-use boundaries. Autonomous agents face substantial operational threats when executing tool calls—particularly SSRF attacks against internal metadata services and destructive shell or filesystem commands. Your perspective on our tool parameter inspection engine would be extraordinarily valuable.

We are launching an external developer pilot (7–14 days, approximately 30–45 minutes total) focusing on our published stable package:
`pip install llmfirewall-core==1.4.0`

Key tasks to evaluate:
- Inspecting tool call parameters using `fw.check_tool_call()` and the `@fw.protect_tool` decorator.
- Pre-execution blocking of SSRF targets (e.g. cloud metadata IP `169.254.169.254`, loopback addresses, internal subnets).
- Intercepting dangerous command injections and path traversal attempts before tool execution.
- Reviewing developer ergonomics and error clarity (`SecurityBlockError`).

Transparent Technical Disclosures:
- Empirical Detection Baseline: In Holdout v4 evaluation on 80 frozen samples, LLMFirewall achieved 60.0% recall on unseen injection attacks with 0% false positives on standard developer prompts in the test set.
- Security Model Boundaries: Application-level parameter inspection is not an OS sandbox (Docker, gVisor). Static URL checks cannot prevent Time-Of-Check to Time-Of-Use (TOCTOU) DNS rebinding without an egress proxy or socket pinning.
- Adoption Disclosure: Currently reflects 0 verified third-party production deployments.

Participation framework:
- Completely voluntary, unpaid, free, and open-source.
- All testing runs locally using synthetic mock tool definitions. No proprietary code, confidential datasets, or API keys are requested.
- We explicitly seek candid technical feedback and edge-case reports rather than endorsements. You may decline or withdraw at any time without explanation.
- Feedback is submitted via public GitHub Issue templates on our repository.

If you are open to reviewing the evaluation guide, let me know and I will provide the walkthrough (docs/external-pilot/DEVELOPER_EVALUATION_GUIDE.md).

Best regards,
[Maintainer Name / LLMFirewall Team]
Repository: https://github.com/Livesh-L-28/LLMFirewall
PyPI: https://pypi.org/project/llmfirewall-core/
```

---

## 8. Candidate PILOT-008: Stefan (`@amidabuddha`)

- **Assigned Persona**: AI Agent Developer
- **Verified Public Project**: [`amidabuddha/unichat-mcp-server`](https://github.com/amidabuddha/unichat-mcp-server), [`amidabuddha/console-chat-gpt`](https://github.com/amidabuddha/console-chat-gpt)
- **Technical Relevance**: Developer of open-source Python Model Context Protocol (MCP) servers and multi-model CLI tools with agent tool-use capabilities.
- **Audited Public Route**: Public GitHub profile (`https://github.com/amidabuddha`).

### Draft Invitation Copy

```text
Subject: Technical evaluation: Model Context Protocol (MCP) tool parameter guardrails

Hi Stefan,

I’m reaching out from the open-source LLMFirewall-Core project (GitHub: https://github.com/Livesh-L-28/LLMFirewall | PyPI: https://pypi.org/project/llmfirewall-core/). We are developing an in-process Python guardrail library designed to protect applications calling LLMs and executing agent tools.

I came across your open-source work on `unichat-mcp-server` and your implementations of Python Model Context Protocol (MCP) servers. When AI agents invoke tools across MCP or custom schemas, inspecting tool arguments before execution is essential to prevent SSRF, unauthorized network calls, and command injections. Your hands-on experience building Python MCP tools would provide valuable practical feedback on our tool validation API (`MCPToolGuard`).

We are organizing an external developer evaluation pilot (7–14 days, ~30–45 minutes of hands-on testing) for our published stable release:
`pip install llmfirewall-core==1.4.0`

Evaluation scope:
1. Clean package installation in an isolated virtual environment.
2. Integrating pre-execution tool parameter validation (`MCPToolGuard` / `fw.check_tool_call`) into a small Python tool-calling workflow.
3. Testing deterministic blocking of SSRF URLs and dangerous command arguments.
4. Reviewing library naming, documentation clarity, and exception handling (`SecurityBlockError`).

Transparent Technical Disclosures:
- Empirical Detection Scope: In frozen Holdout v4 benchmark tests, LLMFirewall achieved 60.0% recall on unseen injection attacks with 0% false positives on benign developer queries in the test set. Heuristics provide rapid sub-millisecond filtering, but do not guarantee 100% detection of novel adversarial evasions.
- Boundary Limitations: Tool parameter validation operates at the application layer and does not substitute for OS-level sandboxes or network egress firewalls.
- Adoption Disclosure: Reflects 0 verified external production deployments.

Participation details:
- 100% voluntary, unpaid, free, and open-source.
- Exercises use synthetic mock tools; no production credentials, proprietary schemas, or live API keys are required.
- We request honest feedback on usability and edge-case behavior, not commercial endorsements. You are completely free to decline without reason.
- Feedback is submitted directly through public GitHub Issues.

If you are interested in trying out the exercises, let me know and I’ll send over the evaluation guide (docs/external-pilot/DEVELOPER_EVALUATION_GUIDE.md).

Best regards,
[Maintainer Name / LLMFirewall Team]
Repository: https://github.com/Livesh-L-28/LLMFirewall
PyPI: https://pypi.org/project/llmfirewall-core/
```
