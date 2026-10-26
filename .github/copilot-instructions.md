# GitHub Copilot Instructions for LLMFirewall

This repository provides `llmfirewall-core` (`import llmfirewall`).
Follow the authoritative architectural guidelines and security invariants in [AGENTS.md](../AGENTS.md).

## Non-Negotiable Security Invariants
1. **Redaction Downstream Invariant**: When `result.action == Action.REDACT`, always forward `result.processed_text` to models. Never pass the original input string.
2. **Never Bypass Block Decisions**: When `result.is_blocked` is True, drop the request immediately and return HTTP 403.
3. **Zero-Retention Safe Logging**: Never log raw prompts. Log `result.safe_dict()`.
4. **Exception Semantics**: Runtime decorators raise `SecurityBlockError`; client adapters raise `SecurityViolation`.
5. **Canonical Imports**: Do not invent classes. Refer to `AGENTS.md` for verified imports.

## Verification
```bash
llmfirewall integrate validate
pytest tests/test_integration_recipes.py -v
pytest tests/test_developer_tooling.py -v
pytest examples/sample_apps/ -v
pytest -q
```
