"""Output formatters for LLMFirewall CLI."""

import json
import re
from typing import Any, Dict
from llmfirewall.core.models import Action, ScanResult

# Regex to strip dangerous ANSI escape sequences and non-printable terminal control codes
_ANSI_ESCAPE_PATTERN = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def sanitize_terminal_text(text: str) -> str:
    """Strip ANSI escape sequences and control characters that could spoof CLI terminal output."""
    if not text:
        return ""
    # Strip ANSI sequences
    clean = _ANSI_ESCAPE_PATTERN.sub("", text)
    # Strip dangerous non-newline control characters (\x00-\x08, \x0B, \x0C, \x0E-\x1F, \x7F)
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", clean)


def format_human_output(result: ScanResult, use_color: bool = False) -> str:
    """Format a ScanResult into clean, human-readable terminal output.
    
    Security & Privacy Guarantees:
    - Never prints raw secrets or raw matched PII.
    - Displays high-level findings, severities, confidence, and sanitized processed text.
    """
    lines = []
    lines.append("LLMFirewall Scan Summary")
    lines.append("─" * 40)

    action_str = result.decision.action.value.upper()
    lines.append(f"Status       : {action_str}")
    lines.append(f"Risk Score   : {result.risk_score.score:.2f}")
    lines.append(f"Risk Level   : {result.risk_score.max_severity.value.upper()}")
    lines.append(f"Action       : {action_str}")
    lines.append(f"Execution    : {result.execution_time_ms} ms")
    lines.append(f"Request ID   : {result.request_id}")

    if result.decision.policy_id:
        lines.append(f"Policy       : {result.decision.policy_id} (v{result.decision.policy_version or '1.0'})")

    if result.decision.reason:
        clean_reason = sanitize_terminal_text(result.decision.reason)
        lines.append(f"Policy Note  : {clean_reason}")

    if result.decision.explanations:
        lines.append("")
        lines.append("Matched Policy Rules:")
        for exp in result.decision.explanations:
            r_name = sanitize_terminal_text(exp.get("rule_name", exp.get("rule_id", "")))
            r_act = exp.get("action", "").upper()
            r_prio = exp.get("priority", 100)
            lines.append(f"  • [{r_act}] {r_name} (priority: {r_prio})")

    if result.findings:
        lines.append("")
        lines.append(f"Threat Findings ({len(result.findings)}):")
        for finding in result.findings:
            lines.append(f"  • {finding.threat_type.value}")
            lines.append(f"    Severity   : {finding.severity.value.upper()}")
            lines.append(f"    Confidence : {finding.confidence:.2f}")
            clean_desc = sanitize_terminal_text(finding.description)
            lines.append(f"    Description: {clean_desc}")
            if finding.replacement_text:
                clean_mask = sanitize_terminal_text(finding.replacement_text)
                lines.append(f"    Safe Mask  : {clean_mask}")
    else:
        lines.append("")
        lines.append("No security threats or policy violations detected.")

    if result.decision.action == Action.REDACT and result.processed_text:
        lines.append("")
        lines.append("Sanitized Text:")
        clean_processed = sanitize_terminal_text(result.processed_text)
        lines.append(f"  {clean_processed}")

    return "\n".join(lines)


def format_json_output(result: ScanResult) -> str:
    """Format a ScanResult into valid, deterministic, unescaped JSON.
    
    Guarantees:
    - Strictly valid JSON.
    - Zero ANSI escape sequences.
    - Zero raw secrets or raw unmasked PII.
    - Machine-readable structure ideal for CI/CD, SIEM, and scripts.
    """
    threats = []
    for f in result.findings:
        item: Dict[str, Any] = {
            "threat_type": f.threat_type.value,
            "severity": f.severity.value,
            "confidence": f.confidence,
            "description": f.description,
            "detector_name": f.detector_name,
        }
        if f.replacement_text:
            item["replacement_text"] = f.replacement_text
        threats.append(item)

    payload: Dict[str, Any] = {
        "status": result.decision.action.value,
        "allowed": result.decision.action != Action.BLOCK,
        "action": result.decision.action.value,
        "risk_score": result.risk_score.score,
        "risk_level": result.risk_score.max_severity.value,
        "request_id": result.request_id,
        "execution_time_ms": result.execution_time_ms,
        "threats": threats,
    }

    if result.decision.policy_id:
        payload["policy"] = {
            "name": result.decision.policy_id,
            "version": result.decision.policy_version,
            "triggered_rules": result.decision.triggered_rules,
            "explanations": result.decision.explanations,
        }

    if result.decision.action == Action.REDACT:
        payload["sanitized_text"] = result.processed_text

    return json.dumps(payload, indent=2, sort_keys=True)
