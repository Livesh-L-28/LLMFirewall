"""LLMFirewall-Core — Model Context Protocol (MCP) Tool Guard Example.

Demonstrates:
1. Intercepting MCP JSON-RPC 2.0 `tools/call` requests.
2. Sandboxing tool arguments against SSRF, cloud metadata access, and path traversal.
3. Sanitizing tool execution output before returning to models.

Execution:
    python examples/mcp/mcp_tool_guard_example.py
"""

from llmfirewall import Firewall
from llmfirewall.integrations import SecurityViolation
from llmfirewall.integrations.mcp import MCPToolGuard


def main():
    print("=== Model Context Protocol (MCP) Tool Guard Demo ===")

    # 1. Initialize firewall and MCP tool guard
    fw = Firewall()
    mcp_guard = MCPToolGuard(firewall=fw, fail_closed=True)

    # 2. Benign Tool Invocation
    print("\n1. Testing Benign Tool Call:")
    benign_call = {
        "name": "calculate_statistics",
        "arguments": {"numbers": [10, 20, 30, 40]},
    }
    decision = mcp_guard.intercept_tool_call(
        name=benign_call["name"],
        arguments=benign_call["arguments"],
        session_id="session-user-1",
    )
    print(f"Tool: {benign_call['name']} -> Decision: {decision.action} (Allowed: {decision.is_allowed})")
    assert decision.is_allowed is True

    # 3. Malicious SSRF Tool Invocation (Blocked)
    print("\n2. Testing Malicious SSRF Tool Call:")
    ssrf_call = {
        "name": "fetch_webpage",
        "arguments": {"url": "http://169.254.169.254/latest/meta-data"},
    }
    try:
        mcp_guard.intercept_tool_call(
            name=ssrf_call["name"],
            arguments=ssrf_call["arguments"],
            session_id="session-user-1",
        )
        assert False, "Expected SecurityViolation"
    except SecurityViolation as exc:
        print(f"Safely blocked SSRF attempt: {exc.message}")

    # 4. Path Traversal Tool Invocation (Blocked)
    print("\n3. Testing Path Traversal Tool Call:")
    traversal_call = {
        "name": "read_workspace_file",
        "arguments": {"path": "../../../etc/shadow"},
    }
    try:
        mcp_guard.intercept_tool_call(
            name=traversal_call["name"],
            arguments=traversal_call["arguments"],
            session_id="session-user-1",
        )
        assert False, "Expected SecurityViolation"
    except SecurityViolation as exc:
        print(f"Safely blocked traversal attempt: {exc.message}")

    # 5. Tool Output Content Redaction
    print("\n4. Testing Tool Output Redaction:")
    raw_output = "Server database query returned email: admin@internal.corp and phone: 555-123-4567"
    safe_output = mcp_guard.intercept_tool_result("database_query", raw_output)
    print(f"Sanitized Tool Output: {safe_output}")
    assert "admin@internal.corp" not in safe_output
    assert "[REDACTED_EMAIL]" in safe_output

    print("\n[SUCCESS] MCP Tool Guard demo completed successfully!")


if __name__ == "__main__":
    main()
