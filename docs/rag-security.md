# Advanced RAG & Context Security (Phase 27)

LLMFirewall provides comprehensive security for Retrieval-Augmented Generation (RAG) pipelines, context construction, and agent memory.

---

## 1. Core Security Principle

```text
RETRIEVED CONTENT ≠ INSTRUCTIONS
```

A document or web page may contain imperative sentences that look like developer or system instructions. LLMFirewall preserves the strict boundary between instructions, user queries, retrieved reference knowledge, and tool outputs:

```text
System / Developer Instructions (Instruction Authority: FULL)
  > User Query (Instruction Authority: LIMITED)
    > Retrieved Evidence / Chunks (Instruction Authority: NONE)
      > External Tool Results (Instruction Authority: NONE)
```

---

## 2. Ingestion Security & Quarantine

Documents scanned prior to indexing or embedding are checked for indirect prompt injection, sensitive credentials, and PII:

```python
from llmfirewall import Firewall

fw = Firewall()
result = fw.ingestion_scanner.scan_document(
    content="Normal document...",
    document_id="doc-hr-01",
)

if not result.is_safe:
    print(f"Document quarantined: {result.quarantine_reason}")
```

Flagged documents are segregated into the `QuarantineStore`, preventing them from ever leaking into active vector retrieval results.

---

## 3. Dynamic Context Orchestration

During retrieval, `ContextOrchestrator` filters chunks, removes exact duplicates, flags contradictory instructions, and enforces token/item budgets:

```python
decision = fw.context_orchestrator.filter_and_secure(retrieved_chunks)
print(f"Approved: {len(decision.approved_items)}")
print(f"Quarantined: {len(decision.quarantined_items)}")
print(f"Conflict Detected: {decision.conflict_detected}")
```

### Prompt Assembly:
```python
prompt = fw.context_orchestrator.assemble_prompt(
    system_instruction="You are a support bot.",
    user_query="Can I return an item?",
    retrieved_items=decision.approved_items,
)
```

---

## 4. Agent Memory Protection

Prevents long-term memory poisoning:

```python
from llmfirewall import MemorySecurityGuard

mem_guard = MemorySecurityGuard(fw)

# Scans before persisting
mem_guard.guard_write("User prefers dark mode.", memory_id="pref-01")

# Malicious memory writes trigger RuntimeSecurityError
```

---

## 5. Citation Validation

Validates that model citations map to actual retrieved chunks:

```python
from llmfirewall import CitationValidator

validator = CitationValidator()
report = validator.validate_citations(llm_response_text, decision.approved_items)
if not report["is_valid"]:
    print(f"Hallucinated citations: {report['hallucinated_citations']}")
```

---

## 6. Threat Model & Limitations

### Threats Addressed:
- Indirect prompt injection via external documents
- Document & metadata poisoning
- Persistent agent memory injection
- Context flooding & budget exhaustion
- Citation hallucination

### Non-Goals & Limitations:
Phase 27 provides semantic, policy-driven inspection and provenance tracking. It **does NOT**:
- Guarantee semantic factual correctness or truth verification.
- Provide binary malware scanning (e.g. ClamAV, executable analysis).
- Replace external vector search indexing algorithms.
- Provide OS-level or container-level isolation.
