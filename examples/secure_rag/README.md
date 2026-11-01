# Secure RAG Application Example

A complete, production-grade reference implementation demonstrating how to secure Retrieval-Augmented Generation (RAG) pipelines against indirect prompt injection, data poisoning, and credential exposure using **LLMFirewall-Core**.

## Features Demonstrated

1. **Pre-Ingestion Document Scanning**: Inspects incoming documents before they are embedded or indexed into the vector store.
2. **Logical Quarantine Isolation**: Malicious documents with embedded jailbreaks or indirect injections are quarantined in `fw.rag_quarantine` and never stored.
3. **Retrieval Boundary Filtering**: Even if an attacker injects content directly into the database, `fw.context_orchestrator.filter_and_secure()` isolates untrusted chunks during retrieval.
4. **The Redaction Invariant**: Sensitive PII (emails, phone numbers) within approved chunks is redacted into sanitized tokens (`[REDACTED_EMAIL]`) before prompt assembly.
5. **XML Isolation Delimiters**: Formats prompt assembly with explicit `<reference_context warning="...">` tags so models treat retrieved chunks strictly as passive evidence, never as authoritative instructions.
6. **Zero External Vector DB Dependencies**: Uses an in-memory knowledge base by default for immediate local execution.

---

## Architecture & Trust Boundaries

```text
1. Document Ingestion
   External Docs ──► [BOUNDARY 1: Ingestion Scan] ──► Quarantined if malicious!
                           fw.ingestion_scanner       Approved stored in KnowledgeBase.

2. User Query & Retrieval
   User Query ────► [BOUNDARY 2: Query Scan] ───────► Drop if direct injection!
                           fw.scan_prompt
                           │
                           ▼
                   Retrieve Candidate Chunks
                           │
                           ▼
                    [BOUNDARY 3: Retrieval Filter]
                    fw.context_orchestrator
                           │
         ┌─────────────────┴─────────────────┐
         ▼                                   ▼
   Quarantine Store                  Approved Chunks
  (Poisoned dropped)                (PII Redacted)
                                             │
                                             ▼
                                     [BOUNDARY 4: Delimiter Isolation]
                                     fw.context_orchestrator.assemble_prompt
                                             │
                                             ▼
                                     Downstream LLM
```

---

## Quickstart

### 1. Installation

Create and activate a virtual environment, then install requirements:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e ../../
```

### 2. Run the Application

Execute the runnable demonstration:

```bash
python examples/secure_rag/app.py
```

### 3. Expected Output

```text
=== Initializing Secure RAG Pipeline ===
Ingestion results: {'doc-hr-leave': True, 'doc-benefits-pii': True, 'doc-it-poisoned': False}

--- Test Query 1: Benign Leave Policy ---
Status: success
Response: Based on verified company records: Enterprise Leave Policy: Internal Benefits Contact List:
Quarantined Chunks: 0

--- Test Query 2: PII Redaction Verification ---
Status: success
Approved Context: ['Internal Benefits Contact List:\nFor urgent healthcare questions, contact coordinator Alice Smith at [REDACTED_EMAIL] or call +1-555-0199.', 'Enterprise Leave Policy:\nFull-time employees receive 20 days paid annual leave. Leave requests exceeding 5 consecutive days require manager approval.']
Response: Based on verified company records: Internal Benefits Contact List: Enterprise Leave Policy:
```

Notice:
- `doc-it-poisoned` was rejected during ingestion (`False`).
- Sensitive email in `doc-benefits-pii` was sanitized to `[REDACTED_EMAIL]`.

---

## Running Automated Tests

Run the companion test suite with `pytest`:

```bash
pytest examples/secure_rag/test_secure_rag.py -v
```

All 6 test cases verify:
- Benign documents are approved and indexed.
- Malicious documents with indirect prompt injections are quarantined.
- Context orchestrator quarantines adversarial chunks even if retrieval returns them.
- PII is redacted in assembled prompts, ensuring raw emails never leak downstream.
- Malicious user queries are blocked at the input boundary.
- XML delimiters isolate untrusted context from system instructions.

---

## Security Limitations & Production Considerations

1. **In-Memory Store**: This example uses an in-memory keyword store for zero-dependency execution. In production, connect `fw.ingestion_scanner` directly to your vector ingestion pipeline (e.g., Chroma, Pinecone, Qdrant, or LangChain/LlamaIndex vectorstores).
2. **Chunking Granularity**: Scan both full documents at ingestion time and individual chunks at retrieval time for maximum defense-in-depth.
3. **Quarantine Persistence**: By default, `QuarantineStore` is in-memory. In enterprise deployments, back it with a distributed key-value store or database so quarantined documents persist across worker restarts.
