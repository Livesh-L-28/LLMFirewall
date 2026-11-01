# LLMFirewall-Core Troubleshooting Guide

A practical troubleshooting manual for diagnosing and resolving common installation, configuration, and runtime issues.

---

## 1. Installation & Import Failures

### Issue 1.1: `ModuleNotFoundError: No module named 'llmfirewall'`
- **Symptom**: `import llmfirewall` raises `ModuleNotFoundError`.
- **Root Cause**: The package was installed using the wrong name (e.g. `pip install llmfirewall` which does not match or points elsewhere). The distribution on PyPI is `llmfirewall-core`.
- **Solution**:
  ```bash
  python -m pip install llmfirewall-core
  ```
  Ensure your active shell is using the intended virtual environment:
  ```bash
  which python
  python -c "import llmfirewall; print(llmfirewall.__version__)"
  ```

### Issue 1.2: `ImportError: The '<framework>' integration requires the optional '<extra>' extra.`
- **Symptom**: Attempting to import framework adapters raises an `ImportError` directing you to install an extra.
- **Root Cause**: Optional framework integrations (FastAPI, Flask, Django, LangChain, LlamaIndex) require optional dependencies to keep the minimal core runtime lightweight (`pydantic` and `pyyaml` only).
- **Solution**: Install the required extra using the exact distribution name:
  ```bash
  # For FastAPI / Starlette
  python -m pip install "llmfirewall-core[fastapi]"

  # For Flask
  python -m pip install "llmfirewall-core[flask]"

  # For Django
  python -m pip install "llmfirewall-core[django]"

  # For LangChain
  python -m pip install "llmfirewall-core[langchain]"

  # For LlamaIndex
  python -m pip install "llmfirewall-core[llamaindex]"
  ```
  *Tip*: For FastAPI, Starlette, or Quart, you can alternatively use the zero-dependency pure ASGI middleware:
  ```python
  from llmfirewall.integrations import LLMFirewallASGIMiddleware
  ```

### Issue 1.3: `AttributeError: type object 'Config' has no attribute ...` (Pydantic Conflict)
- **Symptom**: Pydantic models crash on initialization with config errors.
- **Root Cause**: An older Pydantic v1.x installation exists in your environment.
- **Solution**: Upgrade to Pydantic v2:
  ```bash
  python -m pip install --upgrade "pydantic>=2.0.0"
  ```

---

## 2. Runtime Scanning & Decision Troubleshooting

### Issue 2.1: Downstream Model Still Receives Sensitive PII or Credentials
- **Symptom**: You see `Action.REDACT` in logs, but the LLM still receives sensitive data.
- **Root Cause**: Forwarding the original prompt variable (`prompt`) instead of `result.processed_text`.
- **Correction**:
  ```python
  result = fw.scan(prompt)

  # ALWAYS consume result.processed_text when Action.REDACT!
  safe_prompt = result.processed_text if result.action == Action.REDACT else prompt
  llm.generate(safe_prompt)
  ```

### Issue 2.2: Unexpected `SecurityBlockError` or `SecurityViolation` in Application
- **Symptom**: Your API endpoint returns an unhandled 500 error instead of a clean 403.
- **Root Cause**: Decorators (`@fw.protect`) raise `SecurityBlockError`, while client adapters (`wrap_openai`, `wrap_anthropic`, `StreamingTextGuard`) raise `SecurityViolation`. Both inherit from `LLMFirewallError`.
- **Correction**: Catch security exceptions explicitly at your API boundary:
  ```python
  from llmfirewall import SecurityBlockError
  from llmfirewall.integrations import SecurityViolation
  from fastapi import HTTPException

  try:
      return guarded_function(prompt)
  except (SecurityBlockError, SecurityViolation) as exc:
      raise HTTPException(status_code=403, detail=f"Request blocked by policy: {exc.reason}")
  ```

---

## 3. Tool Sandboxing & SSRF Issues

### Issue 3.1: Tool Call Blocked for Internal URLs
- **Symptom**: Calling `fw.check_tool_call()` blocks a tool fetching internal network data.
- **Root Cause**: By default, `ToolSecurityEngine` and `validate_url_safety()` block private IP ranges (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.1`), and cloud metadata (`169.254.169.254`) to prevent SSRF.
- **Correction**: If your tool genuinely requires private network access, specify explicit allowed domains or configure `allow_private_network`:
  ```python
  from llmfirewall.tools import ToolDefinition, ToolRegistry, ToolSecurityEngine

  registry = ToolRegistry()
  registry.register(
      ToolDefinition(
          name="fetch_internal_wiki",
          allowed_domains={"wiki.internal.corp"},
      )
  )
  engine = ToolSecurityEngine(registry=registry, enforce_registry=True)
  ```

---

## 4. Multi-Turn Session Behavior

### Issue 4.1: Does `Firewall.scan()` Retain Conversation History?
- **Answer**: No. The core `Firewall` orchestrator is intentionally **stateless by design**. It evaluates each input deterministically without maintaining ambient global state.
- **Solution**: To track cumulative threat scores and suspicious session behavior across multi-turn dialogs:
  - Use `from llmfirewall import MultiTurnSecurityState`.
  - Or use `client = LLMFirewallClient(); session = client.create_session(session_id="user-123")`.
  - Or use `LangGraphStateGuard` for multi-agent graph workflows.

---

## 5. CLI Execution Troubleshooting

### Issue 5.1: `command not found: llmfirewall`
- **Root Cause**: Python's `bin/` directory is not included in `$PATH`.
- **Solution**:
  1. Activate your virtual environment: `source .venv/bin/activate`
  2. Or invoke using Python module syntax:
     ```bash
     python -m llmfirewall.cli.main --help
     ```
