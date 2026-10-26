# Agent Tool Calling Security Recipe

This recipe demonstrates securing autonomous AI agent tool calls against Server-Side Request Forgery (SSRF), SQL injection, path traversal, and unauthorized tool arguments using LLMFirewall.

---

## 1. When to Use It

- You are building multi-step tool-using agents (e.g. with LangChain, LlamaIndex, AutoGen, CrewAI, or custom OpenAI function calling).
- An LLM generates arguments to invoke functions that interact with the local filesystem, shell, database, or external network.
- You must prevent adversarial models from reaching cloud metadata services (`169.254.169.254`), reading local files (`/etc/passwd`), or executing destructive queries.

---

## 2. Prerequisites

Requires only the base `llmfirewall-core` package:

```bash
pip install llmfirewall-core
```

---

## 3. Minimal Complete Example

```python
from llmfirewall import Firewall, SecurityBlockError, Action

fw = Firewall()

# Method A: Manual Tool Call Inspection
def execute_web_request(url: str):
    # Inspect arguments before executing network call
    decision = fw.check_tool_call("fetch_url", arguments={"url": url})
    if decision.is_blocked:
        raise PermissionError(f"Tool call blocked: {decision.reason}")
    
    return f"Fetched content from {url}"

# Method B: Function Wrapper Decorator
def run_database_query(query: str):
    return f"Queried: {query}"

# Automatically inspects tool parameters and raises SecurityBlockError if blocked
protected_db = fw.protect_tool(
    run_database_query,
    tool_name="database",
    raise_on_block=True
)

# Usage Example:
# 1. Benign tool call passes
content = execute_web_request("https://api.github.com/repos")
print("Allowed:", content)

# 2. SSRF attack blocked
try:
    execute_web_request("http://169.254.169.254/latest/meta-data")
except PermissionError as err:
    print("Blocked SSRF:", err)

# 3. Privileged tool call intercepted
try:
    protected_db(query="DROP TABLE users; --")
except SecurityBlockError as err:
    print("Blocked Database Abuse:", err.reason)
```

---

## 4. Security Boundary & Inspection Mechanics

1. **Pre-Execution Boundary**: Inspection happens strictly *before* the function executes. If the tool call is malicious, zero network packets or database queries are issued.
2. **SSRF & Network Defense**:
   - Detects AWS/GCP/Azure instance metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
   - Validates URL schemes (blocking `file://`, `gopher://`, `dict://`).
   - Blocks private IP ranges (RFC 1918) unless explicitly allowlisted.
3. **Filesystem Defense**: Detects directory traversal sequences (`../`, `..\`) and sensitive OS file paths (`/etc/passwd`, `/etc/shadow`, Windows SAM).
4. **Tool Result Inspection**: After a tool completes, scan its output with `fw.check_tool_result(tool_name, output)` to prevent indirect injection hidden in tool responses.

---

## 5. Automated Verification Test

Save as `test_tool_calling_recipe.py` and run with `pytest`:

```python
import pytest
from llmfirewall import Firewall, SecurityBlockError

@pytest.fixture
def firewall():
    return Firewall()

def test_benign_url_tool_allowed(firewall):
    decision = firewall.check_tool_call("fetch_url", {"url": "https://example.com/api"})
    assert decision.is_allowed
    assert not decision.is_blocked

def test_ssrf_metadata_tool_blocked(firewall):
    decision = firewall.check_tool_call("fetch_url", {"url": "http://169.254.169.254/latest/meta-data"})
    assert decision.is_blocked
    assert decision.action.value == "block"

def test_path_traversal_tool_blocked(firewall):
    decision = firewall.check_tool_call("read_file", {"path": "../../etc/passwd"})
    assert decision.is_blocked

def test_protect_tool_wrapper_raises_security_block(firewall):
    def raw_tool(query: str):
        return f"result of {query}"

    guarded_tool = firewall.protect_tool(raw_tool, tool_name="database")
    with pytest.raises(SecurityBlockError) as exc_info:
        guarded_tool(query="DROP TABLE accounts;")
    assert "Privileged database capability access" in exc_info.value.reason
```

---

## 6. Troubleshooting

- **Issue**: An internal API endpoint like `https://internal.mycompany.corp` is being blocked.
  - **Fix**: Configure an allowed domain list or custom policy in `ToolRegistry`:
    ```python
    from llmfirewall.tools import ToolDefinition, ArgumentLimits
    firewall.tool_registry.register(
        ToolDefinition(name="fetch_url", allowed_domains=["internal.mycompany.corp"])
    )
    ```
