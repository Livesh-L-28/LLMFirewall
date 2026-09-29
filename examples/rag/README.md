# LLMFirewall Advanced RAG & Context Security Example

Demonstrates end-to-end RAG security:
1. Ingestion scanning & Quarantine of poisoned knowledge documents
2. Dynamic context orchestration: filtering, deduplication, conflict checking, and budgeting
3. Strict context isolation: Framing retrieved evidence as untrusted references rather than instructions
4. Agent memory protection: Prevention of persistent memory poisoning
5. Citation validation: Verification of LLM citation mappings to retrieved chunks

## Running the Example

```bash
python examples/rag/secure_rag.py
```

No external API keys or vector databases required. Runs fully deterministic in-memory.
