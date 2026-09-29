"""Registry for authorized tools, explicit permissions, and schemas."""

from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field, field_validator

from llmfirewall.tools.models import ToolPermission


class ToolDefinition(BaseModel):
    """Specification of an authorized agent tool under least-privilege principles."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(..., min_length=1, max_length=128, description="Unique normalized tool identifier")
    description: str = Field(default="", description="Human-readable description of tool capability")
    permissions: Set[ToolPermission] = Field(
        default_factory=set,
        description="Explicit granular permissions granted to this tool",
    )
    parameters_schema: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional JSON Schema definition for tool arguments",
    )

    @property
    def schema(self) -> Optional[Dict[str, Any]]:
        """Convenience property for accessing parameters_schema."""
        return self.parameters_schema
    allowed_domains: Optional[Set[str]] = Field(
        default=None,
        description="Optional allowlist of network domains or hostnames this tool may contact",
    )
    allowed_paths: Optional[List[str]] = Field(
        default=None,
        description="Optional list of filesystem base directories this tool may access",
    )
    requires_approval: bool = Field(
        default=False,
        description="Whether invocations of this tool require human-in-the-loop approval",
    )
    is_dangerous: bool = Field(
        default=False,
        description="Flag marking tools that execute code, shell commands, or write to external systems",
    )

    @field_validator("name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        clean = v.strip().lower()
        if not clean:
            raise ValueError("Tool name cannot be empty")
        return clean


class ToolRegistry:
    """Thread-safe, deterministic in-memory registry of authorized tools."""

    def __init__(self) -> None:
        self._tools: Dict[str, ToolDefinition] = {}

    def register(self, tool: ToolDefinition) -> None:
        """Register a tool definition. Overwrites existing registration for the normalized name."""
        self._tools[tool.name] = tool

    def register_tool(
        self,
        name: str,
        description: str = "",
        permissions: Optional[Set[ToolPermission]] = None,
        schema: Optional[Dict[str, Any]] = None,
        allowed_domains: Optional[Set[str]] = None,
        allowed_paths: Optional[List[str]] = None,
        requires_approval: bool = False,
        is_dangerous: bool = False,
    ) -> ToolDefinition:
        """Convenience factory method to register a tool."""
        tool = ToolDefinition(
            name=name,
            description=description,
            permissions=permissions or set(),
            parameters_schema=schema,
            allowed_domains=allowed_domains,
            allowed_paths=allowed_paths,
            requires_approval=requires_approval,
            is_dangerous=is_dangerous,
        )
        self.register(tool)
        return tool

    def get(self, name: str) -> Optional[ToolDefinition]:
        """Retrieve tool definition by normalized name."""
        return self._tools.get(name.strip().lower())

    def contains(self, name: str) -> bool:
        """Check if tool is registered."""
        return name.strip().lower() in self._tools

    def list_tools(self) -> List[ToolDefinition]:
        """Return list of all registered tools sorted by name."""
        return sorted(list(self._tools.values()), key=lambda t: t.name)

    def unregister(self, name: str) -> bool:
        """Remove a tool definition."""
        return self._tools.pop(name.strip().lower(), None) is not None

    def clear(self) -> None:
        """Clear all registered tools."""
        self._tools.clear()


# Default global tool registry
default_tool_registry = ToolRegistry()
