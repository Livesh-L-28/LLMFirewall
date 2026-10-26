"""Framework and Trust Boundary Detector for LLMFirewall.

Analyzes application codebases and dependency manifests to determine the host
architecture, trust boundaries, and recommended LLMFirewall recipes.
"""

from __future__ import annotations

import ast
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


@dataclass
class TrustBoundary:
    """Represents an identified trust boundary in the application code."""

    boundary_type: str  # 'input', 'output', 'streaming', 'tool', 'rag'
    file_path: str
    line_number: int
    snippet: str
    description: str


@dataclass
class RecipeRecommendation:
    """Recommended LLMFirewall integration recipe."""

    framework: str
    recipe_name: str
    recipe_doc: str
    install_command: str
    canonical_imports: List[str]
    description: str


@dataclass
class DetectionResult:
    """Complete framework and architecture detection report."""

    target_path: str
    detected_frameworks: List[str] = field(default_factory=list)
    manifest_dependencies: List[str] = field(default_factory=list)
    trust_boundaries: List[TrustBoundary] = field(default_factory=list)
    recommendations: List[RecipeRecommendation] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert detection result to serializable dictionary."""
        return {
            "target_path": self.target_path,
            "detected_frameworks": self.detected_frameworks,
            "manifest_dependencies": self.manifest_dependencies,
            "trust_boundaries": [asdict(b) for b in self.trust_boundaries],
            "recommendations": [asdict(r) for r in self.recommendations],
        }


RECIPE_CATALOG: Dict[str, RecipeRecommendation] = {
    "fastapi": RecipeRecommendation(
        framework="FastAPI",
        recipe_name="fastapi",
        recipe_doc="docs/integrations/fastapi_endpoint.md",
        install_command='pip install "llmfirewall-core[fastapi]"',
        canonical_imports=[
            "from llmfirewall import Firewall, Action",
            "from llmfirewall.integrations.fastapi import FirewallMiddleware, get_scan_result",
        ],
        description="Attach FirewallMiddleware to automatically inspect HTTP request bodies and inject sanitized prompts.",
    ),
    "flask": RecipeRecommendation(
        framework="Flask",
        recipe_name="flask",
        recipe_doc="docs/integrations/flask_endpoint.md",
        install_command='pip install "llmfirewall-core[flask]"',
        canonical_imports=[
            "from llmfirewall import Firewall, Action",
            "from llmfirewall.integrations.flask import FirewallExtension",
        ],
        description="Attach FirewallExtension with before_request lifecycle hooks and Flask context (g) integration.",
    ),
    "django": RecipeRecommendation(
        framework="Django",
        recipe_name="django",
        recipe_doc="docs/api.md#framework-integrations",
        install_command='pip install "llmfirewall-core[django]"',
        canonical_imports=[
            "from llmfirewall import Firewall, Action",
            "from llmfirewall.integrations.django import FirewallMiddleware",
        ],
        description="Add FirewallMiddleware to MIDDLEWARE in settings.py.",
    ),
    "asgi": RecipeRecommendation(
        framework="Pure ASGI 3.0",
        recipe_name="asgi",
        recipe_doc="docs/integrations/asgi_middleware.md",
        install_command="pip install llmfirewall-core",
        canonical_imports=[
            "from llmfirewall import Firewall, Action",
            "from llmfirewall.integrations import LLMFirewallASGIMiddleware",
        ],
        description="Pure ASGI 3.0 middleware with zero external framework dependencies; compatible with FastAPI, Starlette, Quart.",
    ),
    "streaming": RecipeRecommendation(
        framework="Streaming Generations",
        recipe_name="streaming",
        recipe_doc="docs/integrations/streaming_guard.md",
        install_command="pip install llmfirewall-core",
        canonical_imports=[
            "from llmfirewall import Firewall",
            "from llmfirewall.integrations import StreamingTextGuard, SecurityViolation",
        ],
        description="Sliding-window stream protection intercepting split-token jailbreaks and data leakage across chunks.",
    ),
    "tools": RecipeRecommendation(
        framework="Agent Tool Calling",
        recipe_name="tools",
        recipe_doc="docs/integrations/agent_tool_calling.md",
        install_command="pip install llmfirewall-core",
        canonical_imports=[
            "from llmfirewall import Firewall, SecurityBlockError",
        ],
        description="Pre-execution parameter inspection sandboxing agent functions against SSRF, SQL injection, and path traversal.",
    ),
    "rag": RecipeRecommendation(
        framework="RAG Vector Pipelines",
        recipe_name="rag",
        recipe_doc="docs/integrations/rag_context_guard.md",
        install_command="pip install llmfirewall-core",
        canonical_imports=[
            "from llmfirewall import Firewall",
            "from llmfirewall.rag.models import DocumentSecurityStatus",
        ],
        description="Pre-ingestion document scanner, logical quarantine segregation, and post-retrieval context budgeting.",
    ),
}


class FrameworkDetector:
    """Detects frameworks, package dependencies, and trust boundaries in code."""

    def __init__(self, target_path: str = ".") -> None:
        self.target_path = Path(target_path).resolve()

    def detect(self) -> DetectionResult:
        result = DetectionResult(target_path=str(self.target_path))
        manifest_deps = self._scan_manifests()
        result.manifest_dependencies = sorted(list(manifest_deps))

        frameworks: Set[str] = set()
        boundaries: List[TrustBoundary] = []

        # Analyze files
        if self.target_path.is_file():
            if self.target_path.suffix == ".py":
                self._inspect_python_file(self.target_path, frameworks, boundaries)
        else:
            for root, dirs, files in os.walk(self.target_path):
                # Skip virtual environments and hidden directories
                dirs[:] = [
                    d
                    for d in dirs
                    if not d.startswith(".")
                    and d not in ("venv", ".venv", "env", "node_modules", "__pycache__", "dist", "build")
                ]
                for file_name in files:
                    if file_name.endswith(".py"):
                        file_path = Path(root) / file_name
                        self._inspect_python_file(file_path, frameworks, boundaries)

        # Merge manifest hints
        for dep in manifest_deps:
            dep_lower = dep.lower()
            if "fastapi" in dep_lower:
                frameworks.add("fastapi")
            elif "flask" in dep_lower:
                frameworks.add("flask")
            elif "django" in dep_lower:
                frameworks.add("django")
            elif any(k in dep_lower for k in ("langchain", "llamaindex", "llama-index")):
                frameworks.add("tools")
            elif any(k in dep_lower for k in ("pinecone", "chromadb", "qdrant", "weaviate")):
                frameworks.add("rag")

        result.detected_frameworks = sorted(list(frameworks))
        result.trust_boundaries = boundaries

        # Build recommendations
        recs: List[RecipeRecommendation] = []
        for fw in result.detected_frameworks:
            if fw in RECIPE_CATALOG:
                recs.append(RECIPE_CATALOG[fw])

        # If no specific web framework detected but Python code exists, suggest pure ASGI / in-process scan
        if not recs:
            recs.append(RECIPE_CATALOG["asgi"])

        result.recommendations = recs
        return result

    def _scan_manifests(self) -> Set[str]:
        deps: Set[str] = set()
        base = self.target_path if self.target_path.is_dir() else self.target_path.parent

        # 1. pyproject.toml
        pyproject = base / "pyproject.toml"
        if pyproject.exists():
            try:
                content = pyproject.read_text(encoding="utf-8")
                for match in re.finditer(r'["\']([a-zA-Z0-9_\-]+)(?:[><=~!^0-9.* ]*)["\']', content):
                    deps.add(match.group(1).lower())
            except Exception:
                pass

        # 2. requirements.txt
        reqs = base / "requirements.txt"
        if reqs.exists():
            try:
                content = reqs.read_text(encoding="utf-8")
                for line in content.splitlines():
                    clean = line.strip().split(";")[0].split("#")[0].strip()
                    m = re.match(r"^([a-zA-Z0-9_\-]+)", clean)
                    if m:
                        deps.add(m.group(1).lower())
            except Exception:
                pass

        return deps

    def _inspect_python_file(
        self,
        file_path: Path,
        frameworks: Set[str],
        boundaries: List[TrustBoundary],
    ) -> None:
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:
            return

        rel_path = str(file_path.relative_to(self.target_path)) if file_path != self.target_path else file_path.name

        # Text-based heuristic scans for boundaries and frameworks
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            sline = line.strip()

            # Framework detection
            if "import fastapi" in sline or "from fastapi" in sline:
                frameworks.add("fastapi")
            elif "import flask" in sline or "from flask" in sline:
                frameworks.add("flask")
            elif "import django" in sline or "from django" in sline:
                frameworks.add("django")

            # Boundary 1: Web Route / Input Boundary
            if any(p in sline for p in ("@app.post(", "@app.route(", "@router.post(")):
                boundaries.append(
                    TrustBoundary(
                        boundary_type="input",
                        file_path=rel_path,
                        line_number=idx,
                        snippet=sline[:80],
                        description="HTTP endpoint accepting external user prompt payloads.",
                    )
                )

            # Boundary 2: Streaming Output
            if any(p in sline for p in ("stream=True", "StreamingResponse(", "EventSourceResponse(", "StreamingTextGuard", "protect_stream", "stream(")):
                frameworks.add("streaming")
                boundaries.append(
                    TrustBoundary(
                        boundary_type="streaming",
                        file_path=rel_path,
                        line_number=idx,
                        snippet=sline[:80],
                        description="Streaming LLM completion chunks; requires boundary-aware token guard.",
                    )
                )

            # Boundary 3: Tool / Capability Execution
            if any(p in sline for p in ("execute(", "cursor.execute(", "requests.get(", "httpx.get(", "subprocess.run(", "check_tool_call", "protect_tool", "@fw.protect", "tool_name")):
                frameworks.add("tools")
                boundaries.append(
                    TrustBoundary(
                        boundary_type="tool",
                        file_path=rel_path,
                        line_number=idx,
                        snippet=sline[:80],
                        description="Privileged tool execution (network/DB/OS); requires argument sandboxing.",
                    )
                )

            # Boundary 4: RAG Ingestion / Retrieval
            if any(p in sline for p in ("similarity_search(", "vectorstore", "add_documents(", "embed_query(", "ingestion_scanner", "rag_quarantine", "context_orchestrator", "assemble_context")):
                frameworks.add("rag")
                boundaries.append(
                    TrustBoundary(
                        boundary_type="rag",
                        file_path=rel_path,
                        line_number=idx,
                        snippet=sline[:80],
                        description="RAG vector ingestion or context retrieval; requires ingestion scanner & quarantine.",
                    )
                )


def detect_project_frameworks(path: str = ".") -> DetectionResult:
    """Convenience function to inspect a path and return detection report."""
    detector = FrameworkDetector(path)
    return detector.detect()
