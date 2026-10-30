"""Isolated Agent Tool Sandboxing sample application with LLMFirewall."""

from typing import Any, Dict
from llmfirewall import Firewall, SecurityBlockError

fw = Firewall()


def fetch_url(url: str) -> Dict[str, Any]:
    """Protected web tool checking for SSRF and private IPs before execution."""
    decision = fw.check_tool_call("fetch_url", arguments={"url": url})
    if decision.is_blocked:
        raise PermissionError(f"Tool call blocked: {decision.reason}")
    return {"url": url, "status": "fetched"}


def execute_sql(query: str) -> str:
    """Raw database operation."""
    return f"DB Query Executed: {query}"


# Sandboxed tool wrapper
protected_db = fw.protect_tool(
    execute_sql,
    tool_name="database",
    raise_on_block=True,
)


@fw.protect(agent_id="copilot_assistant")
def run_copilot(prompt: str) -> str:
    """Protected agent function."""
    return f"Copilot execution for: {prompt}"
