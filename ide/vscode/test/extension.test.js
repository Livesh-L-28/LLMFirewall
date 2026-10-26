/**
 * Automated Unit Tests for LLMFirewall VS Code Extension logic.
 * Runs with Node.js built-in test runner: node --test test/extension.test.js
 */

const { test, describe } = require("node:test");
const assert = require("node:assert");
const {
  formatValidationReport,
  parseValidationOutput,
} = require("../extension.js");

describe("VS Code Extension Validation Parser & Formatter", () => {
  test("parseValidationOutput correctly parses valid JSON", () => {
    const jsonStr = JSON.stringify({
      version: "1.2.0",
      passed: true,
      pass_count: 5,
      fail_count: 0,
      checks: [
        { name: "core_public_apis", status: "PASS", message: "Core APIs imported." },
      ],
    });

    const parsed = parseValidationOutput(jsonStr);
    assert.strictEqual(parsed.version, "1.2.0");
    assert.strictEqual(parsed.passed, true);
    assert.strictEqual(parsed.checks.length, 1);
  });

  test("parseValidationOutput throws on malformed JSON", () => {
    assert.throws(() => {
      parseValidationOutput("invalid json string");
    }, /Failed to parse validator JSON/);
  });

  test("formatValidationReport produces structured lines for passing report", () => {
    const report = {
      version: "1.2.0",
      passed: true,
      pass_count: 8,
      fail_count: 0,
      warn_count: 1,
      checks: [
        { name: "enforcement_benign_allow", status: "PASS", message: "Benign input allowed." },
        { name: "framework_extra_flask", status: "WARN", message: "Flask not installed.", action_item: "pip install flask" },
      ],
    };

    const lines = formatValidationReport(report);
    const joined = lines.join("\n");

    assert.ok(joined.includes("Overall Status: PASSED"));
    assert.ok(joined.includes("[PASS]   enforcement_benign_allow"));
    assert.ok(joined.includes("[WARN]   framework_extra_flask"));
    assert.ok(joined.includes("Action:  pip install flask"));
    assert.ok(joined.includes("All security invariants and active enforcement checks passed."));
  });

  test("formatValidationReport displays failure actions when checks fail", () => {
    const report = {
      version: "1.2.0",
      passed: false,
      pass_count: 4,
      fail_count: 1,
      warn_count: 0,
      checks: [
        { name: "enforcement_injection_block", status: "FAIL", message: "Injection not blocked.", action_item: "Check policy" },
      ],
    };

    const lines = formatValidationReport(report);
    const joined = lines.join("\n");

    assert.ok(joined.includes("Overall Status: FAILED"));
    assert.ok(joined.includes("[FAIL]   enforcement_injection_block"));
    assert.ok(joined.includes("Action Required: Please resolve failed checks before deploying."));
  });

  test("formatValidationReport handles empty/invalid object gracefully", () => {
    const lines = formatValidationReport(null);
    assert.strictEqual(lines[0], "Error: Invalid report payload received.");
  });
});
