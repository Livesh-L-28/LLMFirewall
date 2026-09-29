"""Report formatters for evaluation outcomes: Human-readable CLI, JSON, SARIF, JUnit XML, and HTML."""

import html
import json
from typing import Any, Dict
import xml.etree.ElementTree as ET

from llmfirewall.eval.models import SecurityEvaluationReport


def format_human_report(report: SecurityEvaluationReport) -> str:
    """Format report into clean, high-visibility terminal text without leaking secret inputs."""
    lines = []
    lines.append("=" * 68)
    lines.append(f" LLMFirewall Security Evaluation: {report.suite_name} (v{report.suite_version})")
    lines.append(f" Policy: {report.policy_name} (v{report.policy_version}) | Engine: v{report.framework_version}")
    lines.append("=" * 68)

    m = report.metrics
    lines.append(f"{'Total Test Cases:':<24} {m.total_tests}")
    lines.append(f"{'Passed:':<24} {m.passed_tests} ({m.pass_rate * 100:.1f}%)")
    lines.append(f"{'Failed:':<24} {m.failed_tests}")
    if m.skipped_tests > 0:
        lines.append(f"{'Skipped:':<24} {m.skipped_tests}")
    lines.append(f"{'False Positives:':<24} {m.false_positives} ({m.false_positive_rate * 100:.1f}%)")
    lines.append(f"{'False Negatives:':<24} {m.false_negatives} ({m.false_negative_rate * 100:.1f}%)")
    lines.append(f"{'Detection Rate:':<24} {m.detection_rate * 100:.1f}%")
    lines.append(f"{'Mean Latency:':<24} {m.mean_latency_ms:.3f} ms (P95: {m.p95_latency_ms:.3f} ms)")
    lines.append("-" * 68)

    if report.regressions_detected:
        lines.append("⚠️  SECURITY REGRESSION DETECTED!")
        reg = report.regression_summary
        if reg.get("new_failures"):
            lines.append(f"   New Failing Tests: {', '.join(reg['new_failures'])}")
        if reg.get("false_negative_delta", 0) > 0:
            lines.append(f"   False Negative Delta: +{reg['false_negative_delta']}")
        lines.append("-" * 68)

    if report.findings:
        lines.append(f"Security Findings ({len(report.findings)}):")
        for f in report.findings:
            lines.append(f"  • [{f.severity.value.upper():<8}] {f.finding_id} ({f.test_id}): {f.description}")
            if f.evidence:
                lines.append(f"      Evidence: {f.evidence}")
            if f.recommendation:
                lines.append(f"      Fix: {f.recommendation}")
        lines.append("-" * 68)
    elif report.failed_test_ids:
        lines.append("Failed Test Cases:")
        failed_results = [r for r in report.results if not r.passed]
        for r in failed_results:
            tag = "FALSE POSITIVE" if r.is_false_positive else ("FALSE NEGATIVE" if r.is_false_negative else "ACTION MISMATCH")
            lines.append(f"  • [{r.severity.value.upper():<8}] {r.test_id:<14} expected={r.expected_action.value.upper():<6} actual={r.actual_action.value.upper():<6} ({tag})")
        lines.append("-" * 68)

    if report.detection_coverage:
        lines.append("Security Detection Coverage:")
        for cov in report.detection_coverage:
            lines.append(f"  • {cov.detector_name:<28} triggered={cov.tests_triggered:<3} ({cov.coverage_rate * 100:.1f}%)")
        lines.append("=" * 68)

    return "\n".join(lines)


def format_json_report(report: SecurityEvaluationReport, indent: int = 2) -> str:
    """Format report into valid JSON string."""
    return json.dumps(report.to_safe_dict(), indent=indent, sort_keys=True)


def format_sarif_report(report: SecurityEvaluationReport) -> str:
    """Format evaluation failures into standard SARIF (Static Analysis Results Interchange Format) for CI."""
    runs = []
    results = []

    for r in report.results:
        if not r.passed:
            results.append({
                "ruleId": f"LLMFIREWALL-{r.category.value.upper()}",
                "level": "error" if r.severity.value in ("critical", "high") else "warning",
                "message": {
                    "text": (
                        f"Security evaluation failed for {r.test_id}: expected {r.expected_action.value}, "
                        f"got {r.actual_action.value}."
                    )
                },
                "properties": {
                    "test_id": r.test_id,
                    "category": r.category.value,
                    "target_type": r.target_type.value,
                    "severity": r.severity.value,
                    "is_false_negative": r.is_false_negative,
                    "is_false_positive": r.is_false_positive,
                    "evidence": r.evidence or "",
                },
            })

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LLMFirewall Continuous Security Testing Engine",
                        "version": report.framework_version,
                        "informationUri": "https://github.com/livesh/LLMFirewall",
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)


def format_junit_report(report: SecurityEvaluationReport) -> str:
    """Format evaluation outcomes into standard JUnit XML for Jenkins/GitLab/GitHub Actions."""
    m = report.metrics
    testsuite = ET.Element(
        "testsuite",
        name=report.suite_name,
        tests=str(m.total_tests),
        failures=str(m.failed_tests),
        errors=str(m.error_count),
        skipped=str(m.skipped_tests),
        time=str(round(sum(r.latency_ms for r in report.results) / 1000.0, 4)),
    )

    for r in report.results:
        testcase = ET.SubElement(
            testsuite,
            "testcase",
            classname=f"llmfirewall.eval.{r.category.value}",
            name=r.test_id,
            time=str(round(r.latency_ms / 1000.0, 4)),
        )
        if not r.passed:
            failure = ET.SubElement(
                testcase,
                "failure",
                message=f"Expected action {r.expected_action.value}, but got {r.actual_action.value}",
                type="SecurityAssertionError",
            )
            failure.text = (
                f"Test ID: {r.test_id}\n"
                f"Category: {r.category.value}\n"
                f"Severity: {r.severity.value}\n"
                f"False Negative: {r.is_false_negative}\n"
                f"False Positive: {r.is_false_positive}\n"
                f"Evidence: {r.evidence or ''}\n"
            )

    return ET.tostring(testsuite, encoding="unicode")


def format_html_report(report: SecurityEvaluationReport) -> str:
    """Generate a clean, standalone, responsive HTML report without external dependencies."""
    m = report.metrics
    pass_pct = f"{m.pass_rate * 100:.1f}%"
    det_pct = f"{m.detection_rate * 100:.1f}%"
    status_color = "#10b981" if (m.failed_tests == 0 and not report.regressions_detected) else "#ef4444"
    status_label = "ALL PASSED" if (m.failed_tests == 0 and not report.regressions_detected) else "DEFECTS DETECTED"
    if report.regressions_detected:
        status_label = "REGRESSION DETECTED"

    findings_rows = ""
    for f in report.findings:
        sev_color = {
            "critical": "#ef4444",
            "high": "#f97316",
            "medium": "#eab308",
            "low": "#3b82f6",
        }.get(f.severity.value.lower(), "#6b7280")
        findings_rows += f"""
        <tr>
            <td><code>{html.escape(f.finding_id)}</code></td>
            <td><strong>{html.escape(f.test_id)}</strong></td>
            <td><span class="badge" style="background:{sev_color}; color:#fff;">{html.escape(f.severity.value.upper())}</span></td>
            <td>{html.escape(f.category)}</td>
            <td>{html.escape(f.description)}</td>
            <td><code>{html.escape(f.evidence or '-')}</code></td>
            <td>{html.escape(f.recommendation or '-')}</td>
        </tr>
        """

    results_rows = ""
    for r in report.results:
        res_badge = '<span class="badge" style="background:#10b981; color:#fff;">PASS</span>' if r.passed else '<span class="badge" style="background:#ef4444; color:#fff;">FAIL</span>'
        results_rows += f"""
        <tr>
            <td><code>{html.escape(r.test_id)}</code></td>
            <td>{html.escape(r.category.value)}</td>
            <td>{html.escape(r.severity.value.upper())}</td>
            <td>{res_badge}</td>
            <td><code>{html.escape(r.expected_action.value.upper())}</code></td>
            <td><code>{html.escape(r.actual_action.value.upper())}</code></td>
            <td>{r.latency_ms:.2f} ms</td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LLMFirewall Security Test Report: {html.escape(report.suite_name)}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --text: #f8fafc;
            --muted: #94a3b8;
            --border: #334155;
            --primary: #38bdf8;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 24px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        .badge {{
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.05em;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 28px;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
        }}
        .card-label {{
            font-size: 13px;
            color: var(--muted);
            margin-bottom: 6px;
        }}
        .card-value {{
            font-size: 24px;
            font-weight: 700;
        }}
        h2 {{
            font-size: 18px;
            margin-top: 32px;
            margin-bottom: 12px;
            color: var(--primary);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--surface);
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 24px;
        }}
        th, td {{
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
            font-size: 13px;
        }}
        th {{
            background: rgba(255,255,255,0.04);
            color: var(--muted);
            font-weight: 600;
        }}
        code {{
            background: rgba(0,0,0,0.3);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 style="margin:0; font-size:24px;">🛡️ LLMFirewall Security Test Report</h1>
                <p style="margin:4px 0 0 0; color:var(--muted); font-size:14px;">
                    Suite: <strong>{html.escape(report.suite_name)}</strong> (v{html.escape(report.suite_version)}) | Policy: {html.escape(report.policy_name)}
                </p>
            </div>
            <div>
                <span class="badge" style="background:{status_color}; color:#fff; font-size:14px; padding:6px 14px;">
                    {status_label}
                </span>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <div class="card-label">Total Tests</div>
                <div class="card-value">{m.total_tests}</div>
            </div>
            <div class="card">
                <div class="card-label">Pass Rate</div>
                <div class="card-value" style="color:#10b981;">{pass_pct}</div>
            </div>
            <div class="card">
                <div class="card-label">Detection Rate</div>
                <div class="card-value" style="color:var(--primary);">{det_pct}</div>
            </div>
            <div class="card">
                <div class="card-label">Failed Tests</div>
                <div class="card-value" style="color:{'#ef4444' if m.failed_tests > 0 else 'var(--text)'};">{m.failed_tests}</div>
            </div>
            <div class="card">
                <div class="card-label">False Positives</div>
                <div class="card-value">{m.false_positives}</div>
            </div>
            <div class="card">
                <div class="card-label">P95 Latency</div>
                <div class="card-value">{m.p95_latency_ms:.2f} ms</div>
            </div>
        </div>

        {"<h2>⚠️ Security Findings</h2><table><thead><tr><th>ID</th><th>Test ID</th><th>Severity</th><th>Category</th><th>Description</th><th>Evidence</th><th>Remediation</th></tr></thead><tbody>" + findings_rows + "</tbody></table>" if report.findings else ""}

        <h2>Detailed Test Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Test ID</th>
                    <th>Category</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Expected</th>
                    <th>Actual</th>
                    <th>Latency</th>
                </tr>
            </thead>
            <tbody>
                {results_rows}
            </tbody>
        </table>
    </div>
</body>
</html>"""
    return html_content
