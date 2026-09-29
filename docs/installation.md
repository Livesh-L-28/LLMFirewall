# LLMFirewall Installation Guide

This guide covers installing, verifying, and troubleshooting **LLMFirewall v1.0.0**.

---

## 1. System Requirements

- **Python Version**: Python 3.9, 3.10, 3.11, or 3.12.
- **Operating Systems**: macOS (Apple Silicon / Intel), Linux (x86_64 / aarch64), Windows 10/11.
- **Runtime Dependencies**:
  - `pydantic >= 2.0.0` (robust data validation and schema serialization)
  - `pyyaml >= 6.0.0` (Policy-as-Code and configuration parsing)
- **Architecture**: In-process execution with zero required external database or network dependencies.

---

## 2. Virtual Environment Setup

We strongly recommend installing LLMFirewall in an isolated virtual environment:

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

### Windows (Command Prompt)

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
```

---

## 3. Installation Methods

### Option A: Standard Installation (PyPI)

Install the core package with minimal dependencies:

```bash
pip install llmfirewall
```

### Option B: Optional Integration Extras

LLMFirewall provides modular extras to minimize unnecessary dependencies:

```bash
# FastAPI ASGI middleware and helpers
pip install "llmfirewall[fastapi]"

# Flask middleware
pip install "llmfirewall[flask]"

# Django middleware
pip install "llmfirewall[django]"

# LangChain integration adapter
pip install "llmfirewall[langchain]"

# LlamaIndex context guard integration
pip install "llmfirewall[llamaindex]"

# All web and framework integrations
pip install "llmfirewall[all-integrations]"
```

### Option C: Source & Development Installation

If contributing to LLMFirewall or running test suites locally:

```bash
# 1. Clone the repository
git clone https://github.com/livesh/LLMFirewall.git
cd LLMFirewall

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install in editable mode with development dependencies
pip install -e ".[dev,fastapi]"
```

---

## 4. Verification

After installation, verify that the package and CLI are correctly installed and available:

### 1. Verify Package Version in Python

```bash
python -c "import llmfirewall; print('LLMFirewall Version:', llmfirewall.__version__)"
```

Expected output:
```text
LLMFirewall Version: 1.0.0
```

### 2. Verify CLI Command

```bash
llmfirewall --version
```

Expected output:
```text
llmfirewall 1.0.0
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

### Issue: `command not found: llmfirewall`
- **Cause**: The virtual environment's `bin/` (or `Scripts\` on Windows) directory is not in your shell's `PATH`.
- **Solution**: Activate your virtual environment first (`source .venv/bin/activate` or `.venv\Scripts\activate`), or invoke via Python module:
  ```bash
  python -m llmfirewall.cli.main --help
  ```

### Issue: `ModuleNotFoundError: No module named 'pydantic'`
- **Cause**: Incomplete installation or pip environment mismatch.
- **Solution**: Reinstall dependencies:
  ```bash
  pip install --force-reinstall pydantic pyyaml
  ```

### Issue: `ImportError: cannot import name 'FastAPI' from 'fastapi'`
- **Cause**: Attempting to use `llmfirewall.integrations.fastapi` without installing the optional extra.
- **Solution**: Install the extra:
  ```bash
  pip install "llmfirewall[fastapi]"
  ```
