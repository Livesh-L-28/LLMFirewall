# LLMFirewall Installation Guide

This guide covers installing, configuring, verifying, and troubleshooting **LLMFirewall Core v1.2.0**.

---

## 1. System Requirements

- **Python Version**: Python 3.9, 3.10, 3.11, or 3.12.
- **Operating Systems**: macOS (Apple Silicon / Intel), Linux (x86_64 / aarch64), Windows 10/11.
- **Minimal Core Dependencies**:
  - `pydantic >= 2.0.0` (data validation and schema serialization)
  - `pyyaml >= 6.0.0` (Policy-as-Code and configuration parsing)
- **Architecture**: In-process execution with zero external database or network dependencies.

---

## 2. Virtual Environment Setup

We recommend installing in an isolated virtual environment:

### macOS / Linux

```bash
# 1. Create a virtual environment
python3 -m venv .venv

# 2. Activate the environment
source .venv/bin/activate

# 3. Upgrade pip
pip install --upgrade pip
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

## 3. Installation Methods

### Option A: Standard PyPI Installation (Recommended)

Install the core distribution from PyPI:

```bash
pip install llmfirewall-core
```

> [!NOTE]
> **PyPI Distribution vs Python Import**:
> - PyPI Package: `llmfirewall-core`
> - Python Import: `import llmfirewall`
> - CLI Command: `llmfirewall`

### Option B: Pure ASGI 3.0 (Zero Framework Dependencies)

If you are deploying behind FastAPI, Starlette, Quart, or any ASGI gateway (e.g., Uvicorn), you do **not** need framework extras. The pure ASGI middleware is included in the base package:

```bash
pip install llmfirewall-core
```

Then in Python:
```python
from llmfirewall.integrations import LLMFirewallASGIMiddleware
app = LLMFirewallASGIMiddleware(base_asgi_app)
```

### Option C: Optional Framework Extras

Install additional integrations as needed:

```bash
# FastAPI helpers and route-level dependencies
pip install "llmfirewall-core[fastapi]"

# Flask extension
pip install "llmfirewall-core[flask]"

# Django middleware
pip install "llmfirewall-core[django]"

# LangChain callback handler
pip install "llmfirewall-core[langchain]"

# LlamaIndex node postprocessor
pip install "llmfirewall-core[llamaindex]"

# Cryptography (AES-256-GCM encrypted persistence)
pip install "llmfirewall-core[crypto]"

# All framework integrations
pip install "llmfirewall-core[all-integrations]"
```

### Option D: Source & Contributor Installation

To run test suites or contribute to LLMFirewall:

```bash
# 1. Clone the repository
git clone https://github.com/Livesh-L-28/LLMFirewall.git
cd LLMFirewall

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install in editable mode with development dependencies
pip install -e ".[dev,fastapi]"
```

---

## 4. Verification

After installation, verify that the package and CLI operate correctly:

### 1. Verify Package Version in Python

```bash
python -c "import llmfirewall; print('LLMFirewall Version:', llmfirewall.__version__)"
```

Expected output:
```text
LLMFirewall Version: 1.2.0
```

### 2. Verify CLI Command

```bash
llmfirewall --version
```

Expected output:
```text
llmfirewall 1.2.0
```

### 3. Run a Quick Sanity Scan

```bash
llmfirewall scan "Hello, world!"
```

Expected output:
```text
Decision: ALLOW
Risk Score: 0.0 (INFO)
```

---

## 5. Troubleshooting

### Issue: `pip install llmfirewall` fails or installs unrelated package
- **Cause**: The PyPI package name is `llmfirewall-core`.
- **Solution**: Run `pip install llmfirewall-core`.

### Issue: `command not found: llmfirewall`
- **Cause**: The virtual environment's `bin/` directory is not in your shell's `PATH`.
- **Solution**: Activate your virtual environment (`source .venv/bin/activate`), or run via Python module:
  ```bash
  python -m llmfirewall.cli.main --help
  ```

### Issue: `ImportError: cannot import name 'FastAPI' from 'fastapi'`
- **Cause**: Attempting to use `llmfirewall.integrations.fastapi` without installing the optional extra.
- **Solution**: Either install the extra via `pip install "llmfirewall-core[fastapi]"`, or use the zero-dependency pure ASGI middleware `from llmfirewall.integrations import LLMFirewallASGIMiddleware`.
