/**
 * LLMFirewall VS Code Integration Extension.
 *
 * Provides minimal, independently testable actions:
 * 1. Finding integration guidance & verified recipes
 * 2. Validating documented package configuration & security invariants
 * 3. Running security integration tests
 * 4. Displaying actionable validation errors
 */

let vscode;
try {
  vscode = require("vscode");
} catch (e) {
  vscode = null;
}
const cp = require("child_process");
const path = require("path");

let outputChannel;

/**
 * Format raw JSON validation report into structured lines for display.
 */
function formatValidationReport(report) {
  if (!report || typeof report !== "object") {
    return ["Error: Invalid report payload received."];
  }

  const lines = [
    "=".repeat(60),
    `LLMFirewall Integration Validation Report (v${report.version || "unknown"})`,
    "=".repeat(60),
    `Overall Status: ${report.passed ? "PASSED" : "FAILED"}`,
    `Summary: ${report.pass_count || 0} passed, ${report.fail_count || 0} failed, ${report.warn_count || 0} warnings`,
    "",
  ];

  if (Array.isArray(report.checks)) {
    report.checks.forEach((chk) => {
      const badge = `[${chk.status || "INFO"}]`;
      lines.push(`${badge.padEnd(8)} ${chk.name}: ${chk.message}`);
      if (chk.details) {
        lines.push(`         Details: ${chk.details}`);
      }
      if (chk.action_item) {
        lines.push(`         Action:  ${chk.action_item}`);
      }
    });
  }

  lines.push("=".repeat(60));
  if (!report.passed) {
    lines.push("Action Required: Please resolve failed checks before deploying.");
  } else {
    lines.push("All security invariants and active enforcement checks passed.");
  }
  lines.push("=".repeat(60));

  return lines;
}

/**
 * Parses JSON output from `llmfirewall integrate validate --json`.
 */
function parseValidationOutput(rawOutput) {
  try {
    return JSON.parse(rawOutput.trim());
  } catch (err) {
    throw new Error(`Failed to parse validator JSON: ${err.message}`);
  }
}

/**
 * Executes a CLI command synchronously or asynchronously.
 */
function runCLI(cmd, args, cwd) {
  return new Promise((resolve, reject) => {
    cp.execFile(cmd, args, { cwd: cwd || process.cwd() }, (error, stdout, stderr) => {
      if (error && error.code !== 1) {
        // Exit code 1 means validation checks failed (handled in report parsing)
        return reject(new Error(stderr || error.message));
      }
      resolve({ stdout, stderr, exitCode: error ? error.code : 0 });
    });
  });
}

/**
 * Command: Find integration guidance and show recipes.
 */
async function findGuidanceCommand() {
  const recipes = [
    { label: "FastAPI Endpoint", detail: "docs/integrations/fastapi_endpoint.md", recipe: "fastapi" },
    { label: "Pure ASGI 3.0 Middleware", detail: "docs/integrations/asgi_middleware.md (Zero dependencies)", recipe: "asgi" },
    { label: "Real-Time Streaming Guard", detail: "docs/integrations/streaming_guard.md (Token boundary protection)", recipe: "streaming" },
    { label: "Agent Tool Calling Sandboxing", detail: "docs/integrations/agent_tool_calling.md (SSRF/SQLi defense)", recipe: "tools" },
    { label: "RAG Ingestion & Context Security", detail: "docs/integrations/rag_context_guard.md", recipe: "rag" },
  ];

  const selected = await vscode.window.showQuickPick(recipes, {
    placeHolder: "Select an LLMFirewall integration recipe to view guidance",
  });

  if (!selected) return;

  outputChannel.clear();
  outputChannel.show(true);
  outputChannel.appendLine(`Selected Recipe: ${selected.label}`);
  outputChannel.appendLine(`Documentation: ${selected.detail}`);
  outputChannel.appendLine("");
  outputChannel.appendLine(`To scaffold this recipe in terminal:`);
  outputChannel.appendLine(`  llmfirewall integrate scaffold --recipe ${selected.recipe}`);
}

/**
 * Command: Validate package configuration and enforcement checks.
 */
async function validateConfigCommand() {
  const config = vscode.workspace.getConfiguration("llmfirewall");
  const cliPath = config.get("executablePath") || "llmfirewall";
  const policyFile = config.get("policyFile") || "";

  outputChannel.clear();
  outputChannel.show(true);
  outputChannel.appendLine("Executing LLMFirewall configuration and security validation...");

  const args = ["integrate", "validate", "--json"];
  if (policyFile) {
    args.push("--policy", policyFile);
  }

  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri?.fsPath || process.cwd();

  try {
    const res = await runCLI(cliPath, args, workspaceRoot);
    const report = parseValidationOutput(res.stdout);
    const formattedLines = formatValidationReport(report);

    formattedLines.forEach((line) => outputChannel.appendLine(line));

    if (report.passed) {
      vscode.window.showInformationMessage(
        `LLMFirewall: All ${report.pass_count} validation checks passed!`
      );
    } else {
      vscode.window.showErrorMessage(
        `LLMFirewall: ${report.fail_count} validation checks failed. See output channel for details.`
      );
    }
  } catch (err) {
    outputChannel.appendLine(`Validation Error: ${err.message}`);
    vscode.window.showErrorMessage(`LLMFirewall validation failed: ${err.message}`);
  }
}

/**
 * Command: Run integration tests.
 */
async function runIntegrationTestsCommand() {
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri?.fsPath || process.cwd();
  outputChannel.clear();
  outputChannel.show(true);
  outputChannel.appendLine("Running LLMFirewall security integration tests...");

  const terminal = vscode.window.createTerminal("LLMFirewall Tests");
  terminal.show();
  terminal.sendText("pytest tests/test_integration_recipes.py -v");
}

function activate(context) {
  outputChannel = vscode.window.createOutputChannel("LLMFirewall");
  context.subscriptions.push(outputChannel);

  context.subscriptions.push(
    vscode.commands.registerCommand("llmfirewall.findGuidance", findGuidanceCommand),
    vscode.commands.registerCommand("llmfirewall.validateConfig", validateConfigCommand),
    vscode.commands.registerCommand("llmfirewall.runIntegrationTests", runIntegrationTestsCommand)
  );
}

function deactivate() {
  if (outputChannel) {
    outputChannel.dispose();
  }
}

module.exports = {
  activate,
  deactivate,
  formatValidationReport,
  parseValidationOutput,
  runCLI,
};
