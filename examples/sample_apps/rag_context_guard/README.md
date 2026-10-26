# RAG Context Security Sample

This sample application demonstrates document ingestion scanning and context orchestration using `llmfirewall-core`.

## Structure
- `app.py`: Ingestion scanner (`fw.ingestion_scanner`) and context orchestrator (`fw.context_orchestrator`).
- `test_app.py`: Verification tests asserting document quarantine and context filtering.

## Running Tests
```bash
pytest examples/sample_apps/rag_context_guard/test_app.py -v
```
