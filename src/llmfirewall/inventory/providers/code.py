"""Static source code AI Asset Discovery provider using conservative AST inspection."""

import ast
from pathlib import Path
import time
from typing import List, Optional, Set

from llmfirewall.inventory.models import (
    Asset,
    AssetProvenance,
    AssetSource,
    AssetStatus,
    AssetType,
    DiscoveryConfidence,
)
from llmfirewall.inventory.providers.base import DiscoveryProvider

# Recognized SDK call signatures
RECOGNIZED_CALLS = {
    "OpenAI": ("provider:openai", AssetType.MODEL_PROVIDER.value, "OpenAI SDK Client"),
    "AsyncOpenAI": ("provider:openai", AssetType.MODEL_PROVIDER.value, "OpenAI Async Client"),
    "ChatOpenAI": ("provider:openai", AssetType.MODEL_PROVIDER.value, "LangChain ChatOpenAI Client"),
    "Anthropic": ("provider:anthropic", AssetType.MODEL_PROVIDER.value, "Anthropic SDK Client"),
    "AsyncAnthropic": ("provider:anthropic", AssetType.MODEL_PROVIDER.value, "Anthropic Async Client"),
    "AutoModel": ("package:transformers", AssetType.PACKAGE.value, "HuggingFace Transformers Model"),
    "AutoModelForCausalLM": ("package:transformers", AssetType.PACKAGE.value, "HuggingFace CausalLM Model"),
    "FastAPI": ("api:fastapi_app", AssetType.API.value, "FastAPI Service Application"),
    "Agent": ("agent:static_agent", AssetType.AGENT.value, "Autonomous Agent Class"),
}


class CodeDiscoveryVisitor(ast.NodeVisitor):
    """AST visitor extracting recognizable AI SDK initializations and model references."""

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.found: Set[str] = set()
        self.models: Set[str] = set()

    def visit_Call(self, node: ast.Call) -> None:
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name and func_name in RECOGNIZED_CALLS:
            self.found.add(func_name)

        # Check for model identifier keyword arguments or arguments
        for kw in node.keywords:
            if kw.arg in ("model", "model_name") and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                self.models.add(kw.value.value)

        if func_name in ("from_pretrained", "AutoModel", "AutoModelForCausalLM"):
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                self.models.add(node.args[0].value)

        self.generic_visit(node)


class CodeDiscoveryProvider(DiscoveryProvider):
    """Conservative, non-executing static discovery analyzing Python source ASTs for AI SDK patterns."""

    name: str = "code_discovery"
    source_type: AssetSource = AssetSource.CODE

    def __init__(
        self,
        target_path: Optional[str] = None,
        max_files: int = 100,
        root_dir: Optional[str] = None,
    ) -> None:
        chosen = target_path or root_dir
        self.target_path = Path(chosen) if chosen else None
        self.max_files = max_files

    def discover(self) -> List[Asset]:
        if not self.target_path or not self.target_path.exists():
            return []

        assets: List[Asset] = []
        now = time.time()
        files_scanned = 0

        # Scan python files
        py_files = (
            [self.target_path]
            if self.target_path.is_file()
            else list(self.target_path.rglob("*.py"))
        )

        for file_path in py_files[: self.max_files]:
            files_scanned += 1
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(content, filename=str(file_path))
                visitor = CodeDiscoveryVisitor(str(file_path))
                visitor.visit(tree)

                for call_sig in visitor.found:
                    asset_id, asset_type, asset_name = RECOGNIZED_CALLS[call_sig]
                    prov = AssetProvenance(
                        source=AssetSource.CODE,
                        provider_name=self.name,
                        reference=f"{file_path.name}:{call_sig}",
                        observed_at=now,
                        details={"file": str(file_path), "signature": call_sig},
                    )

                    assets.append(
                        Asset.create(
                            asset_id=asset_id,
                            asset_type=asset_type,
                            name=asset_name,
                            source=AssetSource.CODE,
                            status=AssetStatus.ACTIVE,
                            metadata={"detected_signature": call_sig, "file_path": str(file_path)},
                            tags=["code", "static_analysis", call_sig.lower()],
                            confidence=DiscoveryConfidence.MEDIUM,
                            provenance=[prov],
                        )
                    )

                for m_name in visitor.models:
                    clean_m = m_name.replace("/", "_").replace(".", "_").strip().lower()
                    m_id = f"model:{clean_m}"
                    prov_m = AssetProvenance(
                        source=AssetSource.CODE,
                        provider_name=self.name,
                        reference=f"{file_path.name}:model:{m_name}",
                        observed_at=now,
                        details={"file": str(file_path), "model_string": m_name},
                    )
                    assets.append(
                        Asset.create(
                            asset_id=m_id,
                            asset_type=AssetType.MODEL.value,
                            name=m_name,
                            source=AssetSource.CODE,
                            status=AssetStatus.ACTIVE,
                            metadata={"model_identifier": m_name, "file_path": str(file_path)},
                            tags=["code", "static_analysis", "model"],
                            confidence=DiscoveryConfidence.MEDIUM,
                            provenance=[prov_m],
                        )
                    )
            except Exception:
                continue

        return assets
