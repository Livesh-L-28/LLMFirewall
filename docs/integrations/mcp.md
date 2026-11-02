# Model Context Protocol (MCP) Integration Recipe

Enforce protocol-level security guardrails for Model Context Protocol (MCP) servers and clients.

---

## 1. Overview & Capabilities

Anthropic and the Linux Foundation's **Model Context Protocol (MCP)** standardizes how AI applications connect to external tools, local files, and data resources.

The `MCPToolGuard` adapter enforces:
- **Pre-execution Sandboxing**: Intercepts `tools/call` JSON-RPC requests before tool execution.
- **SSRF Prevention**: Blocks private IP addresses (e.g. `127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`) and cloud metadata endpoints (`169.254.169.254`).
- **Path Traversal Defense**: Validates directory parameters against allowed workspace roots.
- **Dangerous Command Interception**: Blocks shell delimiter chaining (`;`, `&&`, `|`, `` ` ``).
- **Output Leak Scrubbing**: Intercepts tool execution outputs to redact sensitive credentials before returning to models.

---

## 2. Installation

```bash
# Minimal installation requires only the core package
python -m pip install llmfirewall-core
```

---

## 3. Quick Integration: `MCPToolGuard`

Incorporate `MCPToolGuard` into your MCP server's request dispatcher:

```python
from llmfirewall import Firewall
from llmfirewall.integrations.mcp import MCPToolGuard
from llmfirewall.integrations import SecurityViolation

# 1. Initialize firewall and MCP guard
fw = Firewall()
guard = MCPToolGuard(firewall=fw, fail_closed=True)

# 2. Intercept an incoming tools/call JSON-RPC request:
def handle_mcp_tool_call(tool_name: str, arguments: dict, session_id: str = "sess-123"):
    # Step A: Validate arguments before dispatch
    try:
        decision = guard.intercept_tool_call(
            name=tool_name,
            arguments=arguments,
            session_id=session_id,
        )
    except SecurityViolation as exc:
        # Return standardized JSON-RPC 2.0 error
        return {
            "jsonrpc": "2.0",
            "error": {"code": -32602, "message": exc.message},
            "id": session_id,
        }

    # Step B: Execute approved tool
    raw_result = dispatch_local_tool(tool_name, arguments)

    # Step C: Sanitize output before returning to model
    safe_result = guard.intercept_tool_result(tool_name, raw_result)
    return {"jsonrpc": "2.0", "result": safe_result, "id": session_id}

def dispatch_local_tool(name: str, args: dict) -> str:
    return f"Tool {name} result: executed with {args}"
```

---

## 4. Demonstrating Security Interceptions

### A. SSRF Attack Blocked
```python
# Malicious attempt to read cloud metadata via MCP tool:
call_payload = {
    "name": "fetch_url",
    "arguments": {"url": "http://169.254.169.254/latest/meta-data"},
}

try:
    guard.intercept_tool_call(name=call_payload["name"], arguments=call_payload["arguments"])
except SecurityViolation as exc:
    print(f"Blocked SSRF: {exc.message}")
    # -> MCP tool 'fetch_url' invocation rejected by security policy
```

### B. Path Traversal Blocked
```python
# Malicious attempt to escape allowed directory:
call_payload = {
    "name": "read_file",
    "arguments": {"path": "../../../etc/passwd"},
}

try:
    guard.intercept_tool_call(name=call_payload["name"], arguments=call_payload["arguments"])
except SecurityViolation as exc:
    print(f"Blocked Traversal: {exc.message}")
```

---

## 5. Offline Testing

See the standalone runnable example at [`examples/mcp/mcp_tool_guard_example.py`](https://github.com/Livesh-L-28/LLMFirewall/blob/main/examples/mcp/mcp_tool_guard_example.py).
