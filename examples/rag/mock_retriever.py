"""Mock Vector Retriever for RAG pipeline demonstration.

Phase 27: Advanced RAG & Context Security.
"""

from typing import List
from llmfirewall import ContextItem, SourceProvenance, TrustLevel


class MockRetriever:
    """Deterministic in-memory document retriever."""

    def __init__(self, documents: List[dict]) -> None:
        self.documents = documents

    def retrieve(self, query: str, top_k: int = 3) -> List[ContextItem]:
        # Return mock matching items
        items = []
        for i, doc in enumerate(self.documents[:top_k]):
            items.append(
                ContextItem(
                    content=doc["text"],
                    provenance=SourceProvenance(
                        document_id=doc.get("id", f"doc-{i}"),
                        source_id=doc.get("source_id", f"src-{i}"),
                        author=doc.get("author", "acme_corp"),
                    ),
                    trust_level=TrustLevel.RETRIEVED,
                )
            )
        return items
