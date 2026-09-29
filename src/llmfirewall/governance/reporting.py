"""Human-readable, JSON, and SARIF report formatters for GovernanceResult."""

import json
from typing import Any, Dict, List

from llmfirewall._version import __version__
from llmfirewall.governance.decisions import GovernanceDecision, GovernanceResult


def format_governance_human(result: GovernanceResult) -> str:
    """Format GovernanceResult into clear, objective, non-alarmist terminal text.
    
    Security Invariants:
    1. Zero Secret Infiltration: Never prints raw credentials or secret tokens.
    2. Evidence-Based Clarity: Clearly separates passed, failed, review, and override items.
    """
    lines: List[str] = []
    lines.append("=" * 70)
    lines.append(" LLMFirewall Security Governance Report")
    lines.append(f" Release: {result.release_id} | Profile: {result.profile.upper()} | Policy: v{result.policy_version}")
    lines.append("=" * 70)

    # Decision Banner
    dec = result.decision.value
    symbol = "✓" if dec == "PASS" else ("✗" if dec in ("FAIL", "BLOCK") else "⚠")
    lines.append(f" Overall Decision: {symbol} {dec}")
    if result.override:
        lines.append(f"   [OVERRIDE APPLIED: Released with exception by {result.override.get('owner', 'unknown')}]")
        lines.append(f"   Reason: {result.override.get('reason', '')}")
    lines.append("-" * 70)

    # Failed Gates
    if result.failed_gates:
        lines.append(f"Failed Gates ({len(result.failed_gates)}):")
        for g in result.failed_gates:
            lines.append(f"  ✗ [{g.gate_type.upper():<12}] {g.gate_id}: {g.reason}")
            if g.reason_codes:
                codes_str = ", ".join(rc.value for rc in g.reason_codes)
                lines.append(f"      Reason Codes: {codes_str}")
        lines.append("-" * 70)

    # Review Items
    if result.review_items:
        lines.append(f"Review Items ({len(result.review_items)}):")
        for g in result.review_items:
            lines.append(f"  ⚠ [{g.gate_type.upper():<12}] {g.gate_id}: {g.reason}")
            if g.reason_codes:
                codes_str = ", ".join(rc.value for rc in g.reason_codes)
                lines.append(f"      Reason Codes: {codes_str}")
        lines.append("-" * 70)

    # Passed Gates
    if result.passed_gates:
        lines.append(f"Passed Gates ({len(result.passed_gates)}):")
        for g in result.passed_gates:
            lines.append(f"  ✓ [{g.gate_type.upper():<12}] {g.gate_id}")
        lines.append("-" * 70)

    # Missing Evidence
    if result.missing_evidence:
        lines.append(f"Missing Required Evidence ({len(result.missing_evidence)}):")
        for ev in result.missing_evidence:
            lines.append(f"  • {ev}")
        lines.append("-" * 70)

    # Findings
    if result.findings:
        lines.append(f"Security Findings ({len(result.findings)}):")
        for f in result.findings:
            if hasattr(f, "severity"):
                sev = getattr(f.severity, "value", str(f.severity)).upper()
            else:
                sev = str(f.get("severity", "MEDIUM")).upper()
            fp = getattr(f, "fingerprint", f.get("fingerprint", "unknown"))[:12]
            desc = getattr(f, "description", f.get("description", ""))
            status = getattr(f, "status", f.get("status", "OPEN"))
            st_val = getattr(status, "value", str(status))
            lines.append(f"  • [{sev:<8}] ({st_val:<12}) {fp}: {desc}")
        lines.append("-" * 70)

    # Required Action
    lines.append("Required Action:")
    if result.decision == GovernanceDecision.PASS:
        lines.append("  All configured security controls satisfied. Release permitted.")
    elif result.override:
        lines.append("  Release proceeded with recorded exception. Address open findings post-release.")
    elif result.decision in (GovernanceDecision.BLOCK, GovernanceDecision.FAIL):
        lines.append("  Resolve failed gates or provide an authorized, time-bounded override.")
    elif result.decision == GovernanceDecision.REVIEW:
        lines.append("  Requires explicit security owner review before release can proceed.")
    else:
        lines.append("  Supply missing evidence and re-evaluate release gates.")
    lines.append("=" * 70)

    return "\n".join(lines)


def format_governance_json(result: GovernanceResult, indent: int = 2) -> str:
    """Format GovernanceResult into valid machine-readable JSON."""
    return json.dumps(result.to_dict(), indent=indent, sort_keys=True)


def format_governance_sarif(result: GovernanceResult) -> Dict[str, Any]:
    """Format governance findings and failed gates into SARIF 2.1.0."""
    sarif_results: List[Dict[str, Any]] = []

    # Map failed gates
    for g in result.failed_gates:
        sarif_results.append({
            "ruleId": f"LLMFIREWALL-GATE-{g.gate_id.upper()}",
            "level": "error" if g.decision == GovernanceDecision.BLOCK else "warning",
            "message": {
                "text": f"Security Gate Failed: {g.gate_id} ({g.gate_type}). {g.reason}",
            },
            "properties": {
                "gate_id": g.gate_id,
                "gate_type": g.gate_type,
                "decision": g.decision.value,
                "reason_codes": [rc.value for rc in g.reason_codes],
            },
        })

    # Map findings
    for f in result.findings:
        if hasattr(f, "severity"):
            sev_val = getattr(f.severity, "value", "medium").lower()
            cat = getattr(f, "category", "general")
            desc = getattr(f, "description", "")
            fp = getattr(f, "fingerprint", "")
            test_id = getattr(f, "test_id", "")
        else:
            sev_val = str(f.get("severity", "medium")).lower()
            cat = f.get("category", "general")
            desc = f.get("description", "")
            fp = f.get("fingerprint", "")
            test_id = f.get("test_id", "")

        level = "error" if sev_val in ("critical", "high") else ("warning" if sev_val == "medium" else "note")
        sarif_results.append({
            "ruleId": f"LLMFIREWALL-FINDING-{cat.upper()}",
            "level": level,
            "message": {
                "text": f"[{cat}] {desc}",
            },
            "properties": {
                "fingerprint": fp,
                "severity": sev_val,
                "test_id": test_id,
            },
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LLMFirewall Security Governance",
                        "version": __version__,
                        "informationUri": "https://github.com/livesh/LLMFirewall",
                        "rules": [
                            {
                                "id": f"LLMFIREWALL-GATE-{g.gate_id.upper()}",
                                "name": g.gate_id,
                                "shortDescription": {
                                    "text": f"Enforces {g.gate_type} security gate.",
                                },
                            }
                            for g in result.failed_gates
                        ],
                    }
                },
                "results": sarif_results,
            }
        ],
    }
