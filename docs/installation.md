# LLMFirewall-Core Installation Guide

A comprehensive guide for installing, configuring, verifying, and troubleshooting **LLMFirewall-Core**.

---

## 1. Version Overview

| Distribution | Version | Status | PyPI Package | Python Import | CLI Command |
|:---|:---|:---:|:---|:---|:---|
| **Stable Release** | `v1.4.0` | Production / Published | `pip install llmfirewall-core` | `import llmfirewall` | `llmfirewall` |
| **Maintenance Release** | `v1.3.2` | Active Maintenance | `pip install llmfirewall-core==1.3.2` | `import llmfirewall` | `llmfirewall` |

> [!IMPORTANT]
> **Package Name vs. Python Import**:
> - The package distribution name on PyPI is **`llmfirewall-core`** (`pip install llmfirewall-core`).
> - The Python module import name is **`llmfirewall`** (`import llmfirewall`).
> - The CLI binary name is **`llmfirewall`** (`llmfirewall --version`).

---

## 2. System Requirements & Compatibility

- **Python Versions**:
  - `Python 3.9` (Verified minimum supported version)
  - `Python 3.10` (Verified via CI matrix)
  - `Python 3.11` (Verified via CI matrix)
  - `Python 3.12` (Verified primary development version)
- **Operating Systems**:
  - Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+, Alpine with Python)
  - macOS (Apple Silicon M1/M2/M3/M4 & Intel x86_64)
  - Windows (10/11, Server 2019/2022, x86_64)
- **Minimal Core Dependencies**:
  - `pydantic >= 2.0.0` (Validation, models, and safe serialization)
  - `pyyaml >= 6.0.0` (Policy-as-Code parsing)
- **Zero Mandatory External Services**:
  - Executes **100% in-process**.
  - No external database (PostgreSQL, Redis, Vector DB) required.
  - No cloud network connection required for inspection.

---

## 3. Virtual Environment Setup

Always install LLMFirewall-Core in an isolated virtual environment to prevent dependency conflicts with other AI packages:

### macOS / Linux

```bash
# 1. Create a virtual environment
python3 -m venv .venv

# 2. Activate the environment
source .venv/bin/activate

# 3. Upgrade pip
python -m pip install --upgrade pip
```

### Windows (PowerShell)

```powershell
# 1. Create a virtual environment
python -m venv .venv

# 2. Activate the environment
.venv\Scripts\Activate.ps1

# 3. Upgrade pip
python -m pip install --upgrade pip
```

---

## 4. Installation Methods

### Method 1: Standard Core Installation (Recommended)

Install the minimal core library from PyPI:

```bash
python -m pip install llmfirewall-core
```

This installation provides:
- Core `Firewall` orchestrator.
- Deterministic heuristic threat detectors (Prompt Injection, PII, High-Entropy Secrets).
- Policy-as-Code engine with built-in presets (`default`, `privacy`, `strict`).
- Tool security engine (SSRF, path traversal, dangerous command inspection).
- `StreamingTextGuard` (in-memory sliding-window token analysis).
- Pure ASGI 3.0 middleware (`LLMFirewallASGIMiddleware`, zero external web dependencies).
- Native SDK wrappers for OpenAI (`wrap_openai`), Anthropic (`wrap_anthropic`), LangGraph (`guard_node`), and MCP (`MCPToolGuard`).
- CLI utility (`llmfirewall`).

---

### Method 2: Optional Framework Extras

When deploying with specific Python web frameworks or agent ecosystems, install the corresponding optional extras defined in `pyproject.toml`:

```bash
# FastAPI middleware, route dependencies, and response scanners
python -m pip install "llmfirewall-core[fastapi]"

# Flask application extension and context hooks
python -m pip install "llmfirewall-core[flask]"

# Django security middleware
python -m pip install "llmfirewall-core[django]"

# LangChain callback handler
python -m pip install "llmfirewall-core[langchain]"

# LlamaIndex node postprocessor
python -m pip install "llmfirewall-core[llamaindex]"

# Cryptographic state persistence (AES-256-GCM / SHA-256)
python -m pip install "llmfirewall-core[crypto]"

# All framework integrations in one command
python -m pip install "llmfirewall-core[all-integrations]"
```

> [!TIP]
> **Zero-Dependency ASGI Alternative**: If you are using FastAPI, Starlette, or Quart, you can avoid installing extra dependencies by using the built-in pure ASGI middleware:
> ```python
> from llmfirewall.integrations import LLMFirewallASGIMiddleware
> app = LLMFirewallASGIMiddleware(your_asgi_app)
> ```

---

### Method 3: Developer & Contributor Installation

To run test suites, benchmarks, or contribute to LLMFirewall-Core:

```bash
# 1. Clone repository
git clone https://github.com/Livesh-L-28/LLMFirewall.git
cd LLMFirewall

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Upgrade pip and install in editable mode with development tooling
python -m pip install --upgrade pip
python -m pip install -e ".[dev,fastapi]"
```

---

## 5. Verifying Installation

Verify that the library and CLI are operational in your environment:

### Step 1: Verify Python Import & Version

```bash
python -c "import llmfirewall; print('LLMFirewall Version:', llmfirewall.__version__)"
```
*Expected Output:*
```text
LLMFirewall Version: 1.4.0
```

### Step 2: Verify CLI Binary

```bash
llmfirewall --version
```
*Expected Output:*
```text
llmfirewall 1.4.0
```

### Step 3: Execute a Live Sanity Scan

```bash
llmfirewall scan "Hello, world!"
```
*Expected Output:*
```text
LLMFirewall Scan Summary
────────────────────────────────────────
Status       : ALLOW
Risk Score   : 0.00
Risk Level   : INFO
Action       : ALLOW
Policy       : default_ai_security_policy (v1.0)
No security threats or policy violations detected.
```

---

## 6. Installation Troubleshooting

### Problem 1: `ModuleNotFoundError: No module named 'llmfirewall'`
- **Cause**: The package was installed under an incorrect name (e.g. `pip install llmfirewall`) or installed into a different Python environment.
- **Solution**:
  1. Confirm active virtual environment: `which python`
  2. Install using the correct distribution name:
     ```bash
     python -m pip install llmfirewall-core
     ```

### Problem 2: `ImportError: The 'fastapi' integration requires the optional 'fastapi' extra.`
- **Cause**: Importing `from llmfirewall.integrations.fastapi import ...` when `fastapi` is not installed.
- **Solution**:
  ```bash
  python -m pip install "llmfirewall-core[fastapi]"
  ```
  *Or use zero-dependency ASGI middleware:*
  ```python
  from llmfirewall.integrations import LLMFirewallASGIMiddleware
  ```

### Problem 3: `AttributeError: type object 'Config' has no attribute ...` (Pydantic V1 Conflict)
- **Cause**: An older Pydantic v1.x package is installed in your virtual environment.
- **Solution**: LLMFirewall-Core requires Pydantic v2. Upgrade via:
  ```bash
  python -m pip install --upgrade "pydantic>=2.0.0"
  ```

### Problem 4: `command not found: llmfirewall`
- **Cause**: Python's `bin/` directory is not in your system `$PATH`.
- **Solution**:
  1. Activate your virtual environment (`source .venv/bin/activate`).
  2. Alternatively, invoke the CLI directly via Python:
     ```bash
     python -m llmfirewall.cli.main --help
     ```

---

## 7. Next Steps

- Proceed to the [Five-Minute Quickstart Guide](quickstart.md).
- Browse verified framework integration guides in [docs/integrations/](integrations/).
- Review [docs/troubleshooting.md](troubleshooting.md) for common configuration patterns.
