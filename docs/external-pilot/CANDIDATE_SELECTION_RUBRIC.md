# LLMFirewall-Core: Candidate Selection Rubric

This document defines the objective, evidence-based qualification rubric for selecting candidate participants for the external developer pilot.

> [!IMPORTANT] Non-Outreach Notice
> This rubric is a candidate evaluation framework.
> **No actual individuals have been searched for, selected, contacted, or invited in this phase.**
> Candidate outreach requires explicit maintainer review and authorization.

---

## 1. Selection Principles & Eligibility Guardrails

To ensure that evaluation feedback is technically rigorous, reproducible, and safe, candidate developers must meet five non-negotiable qualification criteria:

1. **Relevant Technical Experience**: Demonstrated hands-on experience developing Python applications in production, open-source, or active research environments.
2. **Environment Autonomy**: Demonstrated capability to create isolated Python virtual environments (`venv`, `conda`, `uv`, `poetry`) and install PyPI packages independently.
3. **Integration Competence**: Demonstrated familiarity with target architecture boundaries (ASGI middleware, function decorators, tool calling, or vector search pipelines).
4. **Reproducible Feedback Willingness**: Willingness to document environment specs, capture execution outputs, provide Minimal Reproducible Examples (MREs) for encountered issues, and complete the feedback questionnaire.
5. **Strict IP & Confidentiality Boundaries**: The participant must **never** be required or requested to disclose proprietary employer IP, confidential customer data, or internal infrastructure topologies. All evaluations must be executable on synthetic test data.

---

## 2. Five Developer Profile Rubrics

Candidates are evaluated against one of five specialized persona profiles on a 1–5 scoring scale per dimension (Maximum Score: 25 points, Minimum Qualification Threshold: 20 points).

### Profile 1: Python Backend Developer
- **Primary Domain**: Web APIs, microservices, asynchronous execution.
- **Tech Stack**: FastAPI, Starlette, Flask, Django, Uvicorn, Gunicorn.
- **Evaluation Rubric**:

| Dimension | Weight | Low Qualification (1–2) | High Qualification (4–5) |
|---|:---:|---|---|
| **Python & ASGI Depth** | 25% | Basic script authoring; limited async experience. | Production FastAPI/Starlette experience; understands ASGI request lifecycles and middleware chains. |
| **Operational Discipline** | 20% | Relies on global python; lacks virtualenv fluency. | Proficient with clean virtualenvs, dependency pinning, and environment isolation. |
| **API Contract Focus** | 20% | Ignores HTTP status codes and response headers. | Rigorous about HTTP status contracts (e.g. 403 Forbidden semantics), error handling, and latency. |
| **Feedback Quality** | 20% | Provides vague comments ("doesn't work"). | Provides exact tracebacks, HTTP request/response payloads, and latency observations. |
| **Confidentiality Autonomy** | 15% | Can only test in locked-down corporate repositories. | Fully able to test in personal or synthetic open-source sandboxes without employer IP constraints. |

---

### Profile 2: Generative AI Application Developer
- **Primary Domain**: Direct LLM provider integration, streaming interfaces, token safety.
- **Tech Stack**: OpenAI SDK (`openai>=1.0.0`), Anthropic Claude SDK (`anthropic>=0.18.0`), LiteLLM, Ollama.
- **Evaluation Rubric**:

| Dimension | Weight | Low Qualification (1–2) | High Qualification (4–5) |
|---|:---:|---|---|
| **LLM SDK Fluency** | 25% | Uses high-level web UIs; limited Python SDK experience. | Hands-on experience calling OpenAI/Anthropic SDKs in Python; understands streaming chunk handlers. |
| **Prompt Engineering & Sanitization** | 20% | Unfamiliar with prompt injection or PII risks. | Experienced in system prompt design, PII masking, and output safety boundaries. |
| **Mocking & Transport Competence** | 20% | Requires live API keys to run any script. | Understands in-memory mock transports (`httpx.MockTransport`) and test harness design. |
| **Feedback Quality** | 20% | Subjective ratings without technical detail. | Reports concrete token boundaries, redaction edge cases, and streaming chunk anomalies. |
| **Confidentiality Autonomy** | 15% | Requires production prompts to evaluate. | Completely comfortable testing against synthetic benchmark prompts. |

---

### Profile 3: RAG Systems Developer
- **Primary Domain**: Retrieval-augmented generation, vector search, document ingestion security.
- **Tech Stack**: LangChain, LlamaIndex, Chroma, Qdrant, Pinecone, FAISS.
- **Evaluation Rubric**:

| Dimension | Weight | Low Qualification (1–2) | High Qualification (4–5) |
|---|:---:|---|---|
| **RAG Pipeline Depth** | 25% | Basic tutorial user; no production retrieval experience. | Designs end-to-end RAG pipelines; understands chunking, embedding, and vector metadata. |
| **Indirect Injection Awareness** | 20% | Unaware of document poisoning threats. | Understands indirect prompt injection via retrieved context chunks and document delimiters. |
| **Pipeline Integration Skills** | 20% | Relies entirely on black-box framework abstractions. | Capable of inserting context quarantine hooks (`context_orchestrator`) into ingestion flows. |
| **Feedback Quality** | 20% | Binary feedback without chunk data. | Documents chunk formatting, false positive rates on benign documentation, and delimiter issues. |
| **Confidentiality Autonomy** | 15% | Dependent on proprietary internal enterprise docs. | Uses public open-source technical documentation chunks for testing. |

---

### Profile 4: AI Agent Developer
- **Primary Domain**: Autonomous agents, tool routing, action sandboxing, Model Context Protocol.
- **Tech Stack**: LangGraph, AutoGen, CrewAI, MCP, Pydantic tools.
- **Evaluation Rubric**:

| Dimension | Weight | Low Qualification (1–2) | High Qualification (4–5) |
|---|:---:|---|---|
| **Agent Tool Calling Fluency** | 25% | Basic single-step completions; no tool calling. | Builds multi-step autonomous agents with structured JSON tool schemas and routers. |
| **Tool Threat Awareness** | 20% | Grants agents unrestricted shell/network access. | Understands SSRF risks (metadata endpoints), path traversal (`../`), and command injection. |
| **Security Gating Skills** | 20% | Unfamiliar with pre-execution authorization hooks. | Easily integrates parameter inspection (`check_tool_call`) before tool dispatch. |
| **Feedback Quality** | 20% | Unreproducible tool failures reported. | Provides exact JSON-RPC payloads, tool parameter dicts, and expected block reasons. |
| **Confidentiality Autonomy** | 15% | Requires live enterprise database connections. | Uses mock database tools and synthetic URL targets (`169.254.169.254`). |

---

### Profile 5: Application Security Engineer
- **Primary Domain**: DevSecOps, policy-as-code, adversarial threat modeling, audit logging.
- **Tech Stack**: Policy engines, Semgrep, SIEM log aggregators, OWASP LLM Top 10 harnesses.
- **Evaluation Rubric**:

| Dimension | Weight | Low Qualification (1–2) | High Qualification (4–5) |
|---|:---:|---|---|
| **Threat Modeling Rigor** | 25% | Generic security knowledge; unfamiliar with LLMs. | Deep understanding of OWASP LLM Top 10, jailbreak taxonomies, and defense-in-depth layers. |
| **Policy Engine Audit Skills** | 20% | Struggles with declarative YAML/JSON policies. | Fluent in Policy-as-Code, precedence rules (`BLOCK > REDACT > WARN > ALLOW`), and rule prioritization. |
| **Safe Logging & Privacy Audit** | 20% | Overlooks credential leakage in log streams. | Audits log dictionaries (`safe_dict()`) for secret scrubbing and data retention violations. |
| **Feedback Quality** | 20% | Vague vulnerability claims without PoCs. | Provides minimal proof-of-concept injection strings, detailed evasion classifications, and traces. |
| **Confidentiality Autonomy** | 15% | Relies on proprietary internal exploit corpora. | Uses standardized public adversarial techniques and synthetic attack patterns. |

---

## 3. Disqualification & Exclusion Criteria

Candidates must be disqualified if any of the following apply:
1. **Confidentiality Conflict**: Candidate indicates that evaluation requires running proprietary customer data or corporate secrets through the library.
2. **Environment Inability**: Candidate cannot independently create a Python 3.9–3.12 virtual environment on their machine.
3. **Commercial / Quid-Pro-Quo Conflict**: Candidate demands commercial consulting fees or vendor sponsorship as a condition of evaluation.
4. **Hostile or Unconstructive Engagement**: History of unconstructive, non-reproducible bug reports on open-source repositories.
5. **Affiliation Conflation**: Candidate is an internal contributor, repository collaborator, or co-maintainer (all testers must be strictly independent).

