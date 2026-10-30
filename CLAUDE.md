# Claude Code Agent Guide for LLMFirewall

Authoritative guidelines for working on `llmfirewall-core`.
Full instructions and architecture: See [AGENTS.md](AGENTS.md).

## Package Identity & Minimal Dependencies
- Package: `llmfirewall-core` (`pip install llmfirewall-core`)
- Module: `llmfirewall` (`import llmfirewall`)
- CLI: `llmfirewall`
- Core Dependencies: `pydantic>=2.0.0`, `pyyaml>=6.0.0` (zero external network dependencies)

## Mandatory Security Invariants
1. **Redaction**: When `result.action == Action.REDACT`, forward `result.processed_text` downstream, never the raw input.
2. **Blocking**: When `result.is_blocked` is True, drop the request and return HTTP 403.
3. **Safe Logging**: Use `result.safe_dict()`, never raw text or secret substrings.
4. **Exceptions**: Catch `SecurityBlockError` or `SecurityViolation`.
5. **No Hallucinated Classes**: Use canonical imports from `AGENTS.md`. Report unsupported APIs explicitly.

## Developer Scaffolding
- Detect frameworks: `llmfirewall integrate detect`
- Scaffold recipe: `llmfirewall integrate scaffold --recipe <name>`
- Validate configuration: `llmfirewall integrate validate`

## Verification Commands
```bash
llmfirewall integrate validate
pytest tests/test_integration_recipes.py -v
pytest tests/test_developer_tooling.py -v
pytest examples/sample_apps/ -v
pytest -q
ruff check .
```
Invariant: Do not modify `tests/test_secrets.py`.
