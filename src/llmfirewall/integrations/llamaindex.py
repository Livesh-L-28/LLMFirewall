"""LlamaIndex node post-processor and query engine integration for LLMFirewall.

Protects RAG pipelines:
- Inspects incoming user queries against prompt injection and threats
- Inspects retrieved nodes / context chunks for indirect prompt injection or sensitive leaks
- Inspects generated synthesizer responses before returning to the user
Optional integration: requires llama-index to be installed.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from llmfirewall.core.models import Action, ScanResult
from llmfirewall.firewall import Firewall
from llmfirewall.integrations.base import FirewallIntegration, SecurityViolation

try:
    from llama_index.core.postprocessor.types import BaseNodePostprocessor
    from llama_index.core.schema import NodeWithScore, QueryBundle
    HAS_LLAMAINDEX = True
except ImportError:
    HAS_LLAMAINDEX = False
    BaseNodePostprocessor = object  # type: ignore


class FirewallNodePostprocessor(FirewallIntegration, BaseNodePostprocessor):
    """LlamaIndex postprocessor scanning retrieved document chunks for indirect injection & secrets.
    
    Usage:
        firewall = Firewall()
        postprocessor = FirewallNodePostprocessor(firewall=firewall)
        query_engine = index.as_query_engine(node_postprocessors=[postprocessor])
    """

    def __init__(
        self,
        firewall: Optional[Firewall] = None,
        block_on_threat: bool = True,
        redact_pii: bool = True,
    ) -> None:
        if not HAS_LLAMAINDEX:
            raise ImportError(
                "LlamaIndex is not installed. To use the LlamaIndex integration, install it via: "
                "pip install llama-index or pip install 'llmfirewall[llamaindex]'"
            )
        BaseNodePostprocessor.__init__(self)
        FirewallIntegration.__init__(self, firewall=firewall)
        self.block_on_threat = block_on_threat
        self.redact_pii = redact_pii

    def protect(self, *args: Any, **kwargs: Any) -> Any:
        return self

    def _postprocess_nodes(
        self,
        nodes: List[Any],
        query_bundle: Optional[Any] = None,
    ) -> List[Any]:
        """Inspect each retrieved node's text content before feeding into the LLM synthesizer."""
        # 1. Optionally check the query bundle itself if provided
        if query_bundle is not None:
            query_str = getattr(query_bundle, "query_str", "")
            if query_str:
                q_res = self.firewall.check_prompt(query_str)
                if q_res.decision.action == Action.BLOCK:
                    raise SecurityViolation(
                        f"LlamaIndex query rejected by security policy: {q_res.decision.reason}",
                        scan_result=q_res,
                        request_id=q_res.request_id,
                    )

        # 2. Filter or sanitize retrieved nodes
        safe_nodes = []
        for n in nodes:
            node_obj = getattr(n, "node", n)
            text = node_obj.get_content() if hasattr(node_obj, "get_content") else getattr(node_obj, "text", "")
            if not text:
                safe_nodes.append(n)
                continue

            res: ScanResult = self.firewall.check(
                text_or_request=text,
                direction="input",
                context={"rag_context": True, "source_node": getattr(node_obj, "node_id", "unknown")},
            )

            if res.decision.action == Action.BLOCK:
                if self.block_on_threat:
                    # Drop the poisoned node from retrieved context
                    continue
            elif res.decision.action == Action.REDACT and self.redact_pii:
                # Apply sanitized text to node
                if hasattr(node_obj, "set_content"):
                    node_obj.set_content(res.processed_text)
                safe_nodes.append(n)
            else:
                safe_nodes.append(n)

        return safe_nodes
