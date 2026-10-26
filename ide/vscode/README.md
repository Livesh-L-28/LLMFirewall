# LLMFirewall VS Code Extension

Lightweight, developer-focused integration tooling for `llmfirewall-core`.

---

## Capabilities

1. **Find Integration Guidance & Verified Recipes**:
   Quick access to verified integration recipes (FastAPI, Pure ASGI 3.0, Streaming Text Guard, Agent Tool Sandboxing, and RAG Ingestion Guard).
2. **Validate Package & Security Policy Configuration**:
   Executes automated active enforcement checks (`Action.ALLOW`, `Action.BLOCK`, `Action.REDACT`), validates Policy-as-Code documents, and checks framework dependencies.
3. **Run Security Integration Tests**:
   Triggers automated test suites and displays pass/fail metrics.
4. **Actionable Validation Diagnostics**:
   Presents clear `[PASS]`, `[FAIL]`, and `[WARN]` diagnostic messages with remediation guidance.

---

## Commands

- `LLMFirewall: Find Integration Guidance & Recipes` (`llmfirewall.findGuidance`)
- `LLMFirewall: Validate Package & Security Policy Configuration` (`llmfirewall.validateConfig`)
- `LLMFirewall: Run Security Integration Tests` (`llmfirewall.runIntegrationTests`)

---

## Configuration Settings

- `llmfirewall.executablePath`: Path to the `llmfirewall` CLI binary or python virtualenv executable (default: `"llmfirewall"`).
- `llmfirewall.policyFile`: Path to custom Policy-as-Code YAML or JSON file (optional).

---

## Running Automated Tests

The extension's validation parser and diagnostic formatter are tested with Node's built-in test runner:

```bash
node --test test/extension.test.js
```

---

## Scope & Compatibility Notice

> [!NOTE]
> This extension is verified and tested specifically for **VS Code 1.80+**.  
> We do not claim universal compatibility across other IDEs (PyCharm, Neovim, Sublime) or coding agents. For terminal environments, CI/CD pipelines, and coding agents (Antigravity, Cursor, Claude Code, GitHub Copilot), use the standard `llmfirewall integrate` CLI and the verified markdown instruction files (`AGENTS.md`, `.cursorrules`, `CLAUDE.md`).
