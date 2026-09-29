"""Agent and tool abuse security regression tests."""

import pytest
from llmfirewall import Firewall, PolicyDecision
from llmfirewall.protection import RuntimeRequest

def test_regression_database_tool_requires_review() -> None:
    """Verifies that privileged database tools trigger REVIEW policy."""
    fw = Firewall()
    req = RuntimeRequest(
        input="Query database",
        tool={"name": "database_sql_executor", "arguments": {"query": "DROP TABLE users;"}},
    )
    dec = fw.protection.inspect(req)
    assert dec.decision == PolicyDecision.REVIEW

def test_regression_dangerous_shell_tool_blocked() -> None:
    """Verifies that arbitrary bash execution tool is blocked."""
    fw = Firewall()
    req = RuntimeRequest(
        input="Run command",
        tool={"name": "bash_executor", "arguments": {"cmd": "rm -rf /var/log"}},
    )
    dec = fw.protection.inspect(req)
    assert dec.decision == PolicyDecision.BLOCK

def test_regression_tool_path_traversal_blocked() -> None:
    """Verifies that path traversal sequences in tool parameters are blocked."""
    fw = Firewall()
    req = RuntimeRequest(
        input="Read file",
        tool={"name": "filesystem_reader", "arguments": {"path": "../../../../etc/passwd"}},
    )
    dec = fw.protection.inspect(req)
    assert dec.decision == PolicyDecision.BLOCK

def test_regression_benign_text_formatter_allowed() -> None:
    """Ensures benign tools containing substrings like 'rm' (e.g. text_formatter) are NOT falsely blocked."""
    fw = Firewall()
    req = RuntimeRequest(
        input="Format output",
        tool={"name": "text_formatter", "arguments": {"format": "markdown"}},
    )
    dec = fw.protection.inspect(req)
    assert dec.decision == PolicyDecision.ALLOW
