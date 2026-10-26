"""Isolated RAG Ingestion & Context Security sample application with LLMFirewall."""

from typing import List
from llmfirewall import Firewall
from llmfirewall.rag.models import DocumentSecurityStatus

fw = Firewall()


def ingest_document(content: str, doc_id: str) -> bool:
    """Scan document before embedding; quarantines poisoned documents."""
    result = fw.ingestion_scanner.scan_document(content=content, document_id=doc_id)
    if result.status == DocumentSecurityStatus.BLOCKED or fw.rag_quarantine.is_quarantined(doc_id):
        return False
    return True


def assemble_context(query: str, retrieved_chunks: List[str]) -> str:
    """Filter retrieved chunks and enforce context budget before prompt assembly."""
    decision = fw.context_orchestrator.filter_and_secure(retrieved_chunks)
    safe_chunks = [item.content for item in decision.approved_items]
    context_block = "\n---\n".join(safe_chunks)
    return f"Context:\n{context_block}\n\nQuestion: {query}\nAnswer:"
