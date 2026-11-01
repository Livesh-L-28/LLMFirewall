# Evaluation Scenario: Model Context Protocol (MCP) Server

## 1. Application Architecture

```
Host LLM Client (Claude Desktop / Cursor)
                  │
                  ▼ (JSON-RPC)
     ┌────────────────────────┐
     │ MCP Server Gateway     │
     └────────────┬───────────┘
                  │
                  ▼
     ┌────────────────────────┐
     │ MCPToolGuard Router    │ ──► (Dangerous Tool Args? Drop & Return Error)
     └────────────┬───────────┘
                  │
                  ▼ (Validated Call)
     ┌────────────────────────┐
     │ Local Tool Execution   │
     │ (DB, Filesystem, HTTP) │
     └────────────────────────┘
```

This scenario models Model Context Protocol (MCP) servers exposing local system tools (databases, command execution, APIs) to remote AI clients.

---

## 2. Integration Steps

```python
from llmfirewall import Firewall, Action
from llmfirewall.integrations.mcp import MCPToolGuard

# 1. Initialize firewall & MCP router guard
fw = Firewall()
guard = MCPToolGuard(firewall=fw)

# 2. Intercept incoming MCP 'tools/call' JSON-RPC payload
mcp_request = {
    "method": "tools/call",
    "params": {
        "name": "read_file",
        "arguments": {"path": "/etc/passwd"}
    }
}

decision = guard.inspect_call(
    tool_name=mcp_request["params"]["name"],
    tool_args=mcp_request["params"]["arguments"]
)

if not decision.is_allowed:
    # Return standard MCP JSON-RPC error response
    error_response = {
        "isError": True,
        "content": [{"type": "text", "text": f"Tool execution blocked by security policy: {decision.reason}"}]
    }
```

---

## 3. Expected Security Behavior

1. **Protocol-Compliant Errors**: Blocked calls return formatted JSON-RPC error objects compatible with Claude Desktop and Cursor without crashing the server process.
2. **SSRF Blocking**: URL fetching tools attempting to access `169.254.169.254`, `127.0.0.1`, or internal subnets (`10.0.0.0/8`, `192.168.0.0/16`) are blocked.
3. **Path Traversal Sandboxing**: File operations are restricted from traversing root directory structures.

---

## 4. Failure Cases & Attack Vectors

| Test Attack Payload | Expected Action | Failure Condition (Bug) |
|---|---|---|
| `fetch_url({"url": "http://169.254.169.254/latest/meta-data/"})` | `Action.BLOCK` | Server queries metadata |
| `read_file({"path": "../../etc/shadow"})` | `Action.BLOCK` | Server reads file |
| `execute_sql({"query": "DROP TABLE users;"})` | `Action.BLOCK` (High risk) | Database modified |

---

## 5. Evaluation Criteria

- **Protocol Compatibility**: Fully compliant with MCP JSON-RPC 2.0 specification.
- **Latency**: Interception overhead `< 1.5ms`.

---

## 6. Known Limitations

- **Custom Schema Wrappers**: Non-standard argument nesting requires specifying the argument key in tool configuration.
