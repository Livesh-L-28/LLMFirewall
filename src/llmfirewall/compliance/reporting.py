"""Reporting formatters (Human-readable CLI text, JSON, YAML, and SARIF) for Phase 36."""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import yaml

from llmfirewall.compliance.models import (
    ApplicabilityStatus,
    ComplianceControl,
    ComplianceDiff,
    ComplianceEvidence,
    ComplianceException,
    ComplianceGap,
    ControlAssessment,
    ControlState,
    ExceptionStatus,
)


def format_compliance_human(
    assessments: List[ControlAssessment],
    framework_name: str = "AI Security Baseline",
    framework_version: str = "1.0",
    exceptions: Optional[List[ComplianceException]] = None,
    regressions: int = 0,
) -> str:
    """Format overall compliance assessment summary matching Section 62."""
    unique_assets = sorted(list(set(a.asset_id for a in assessments)))
    applicable_assessments = [a for a in assessments if a.applicability == ApplicabilityStatus.APPLICABLE]

    evidenced_count = sum(1 for a in applicable_assessments if a.status == ControlState.EVIDENCED)
    partial_count = sum(1 for a in applicable_assessments if a.status == ControlState.PARTIALLY_EVIDENCED)
    implemented_count = sum(1 for a in applicable_assessments if a.status == ControlState.IMPLEMENTED)
    not_impl_count = sum(1 for a in applicable_assessments if a.status == ControlState.NOT_IMPLEMENTED)
    failed_count = sum(1 for a in applicable_assessments if a.status == ControlState.FAILED)
    unknown_count = sum(1 for a in applicable_assessments if a.status == ControlState.UNKNOWN)

    # Collect gaps
    key_gaps: List[str] = []
    for a in assessments:
        for g in a.gaps:
            gap_summary = g.title
            if g.missing_evidence:
                gap_summary += f" ({', '.join(g.missing_evidence)})"
            if gap_summary not in key_gaps:
                key_gaps.append(gap_summary)

    # Exceptions
    all_exc = exceptions or []
    active_exc = sum(1 for e in all_exc if e.is_active)
    expired_exc = sum(1 for e in all_exc if not e.is_active)

    lines = [
        "=" * 60,
        "AI SECURITY CONTROL ASSESSMENT",
        "=" * 60,
        "",
        "Framework:",
        f"{framework_name} v{framework_version}",
        "",
        f"Assets:\n{len(unique_assets)}",
        "",
        f"Controls:\n{len(applicable_assessments)} applicable ({len(assessments)} total evaluated)",
        "",
        "Status:",
        "",
        f"Evidenced:\n{evidenced_count}",
        f"Partially Evidenced:\n{partial_count}",
        f"Implemented (Untested):\n{implemented_count}",
        f"Not Implemented:\n{not_impl_count}",
        f"Failed:\n{failed_count}",
        f"Unknown:\n{unknown_count}",
        "",
        "Key Evidence Gaps:",
        "",
    ]

    if key_gaps:
        for idx, gap in enumerate(key_gaps[:10], start=1):
            lines.append(f"{idx}. {gap}")
    else:
        lines.append("None identified.")

    lines.extend([
        "",
        "Exceptions:",
        f"{active_exc} active\n{expired_exc} expired",
        "",
        f"Regressions:\n{regressions}",
        "",
        "-" * 60,
        "NOTE: This report provides technical evidence mapping, not legal certification.",
        "=" * 60,
    ])

    return "\n".join(lines)


def format_control_detail_human(
    assessment: ControlAssessment,
    control: Optional[ComplianceControl] = None,
) -> str:
    """Format comprehensive control details matching Section 56."""
    cid = control.control_id if control else assessment.control_id
    title = control.title if control else assessment.control_id
    desc = control.description if control else ""

    lines = [
        "=" * 60,
        f"CONTROL DETAILS: {assessment.control_id}",
        "=" * 60,
        f"Framework:      {assessment.framework_id}",
        f"Control:        {cid} - {title}",
        f"Description:    {desc}",
        f"Applicability:  {assessment.applicability.value} ({assessment.applicability_reason})",
        f"Status:         {assessment.status.value}",
        f"Target Asset:   {assessment.asset_id}",
        "",
        "Requirements:",
    ]
    if control and control.requirements:
        for r in control.requirements:
            lines.append(f"  - {r}")
    else:
        lines.append("  (No specific requirements recorded)")

    lines.extend(["", "Evidence Collected:"])
    if assessment.evidence:
        for e in assessment.evidence:
            lines.append(f"  - [{e.status.value}] {e.id} ({e.type.value}): {e.content_reference} (source: {e.source})")
    else:
        lines.append("  (No evidence artifacts collected)")

    lines.extend(["", "Identified Gaps:"])
    if assessment.gaps:
        for g in assessment.gaps:
            lines.append(f"  - [{g.severity.value}] {g.title}: {g.description}")
            if g.remediation_guidance:
                lines.append(f"    Remediation: {g.remediation_guidance}")
    else:
        lines.append("  (No open gaps)")

    lines.extend(["", "Related Entities:"])
    lines.append(f"  - Security Controls: {', '.join(assessment.related_security_controls) if assessment.related_security_controls else 'None'}")
    lines.append(f"  - Related Findings:  {len(assessment.related_findings)} findings")
    lines.append(f"  - Attack Paths:      {len(assessment.related_attack_paths)} paths")

    lines.extend([
        "",
        "Evidence Chain Traceability:",
        f"  Requirement -> Control ({assessment.control_id})",
        f"    -> Asset ({assessment.asset_id})",
        f"    -> Security Controls: {assessment.evidence_chain.get('security_controls', [])}",
        f"    -> Posture: {assessment.evidence_chain.get('posture', 'UNKNOWN')}",
        f"    -> Evidence: {assessment.evidence_chain.get('evidence', [])}",
        "=" * 60,
    ])

    return "\n".join(lines)


def format_gaps_human(gaps: List[ComplianceGap]) -> str:
    """Format compliance gaps in a structured text layout."""
    if not gaps:
        return "No compliance gaps identified."

    lines = [
        "=" * 70,
        "COMPLIANCE GAPS",
        "=" * 70,
        f"{'GAP ID':<16} {'SEVERITY':<10} {'CONTROL':<18} {'ASSET':<20}",
        "-" * 70,
    ]
    for g in gaps:
        lines.append(f"{g.gap_id:<16} {g.severity.value:<10} {g.control_id:<18} {g.asset_id:<20}")
        lines.append(f"  Title: {g.title}")
        if g.missing_evidence:
            lines.append(f"  Missing Evidence: {', '.join(g.missing_evidence)}")
        if g.remediation_guidance:
            lines.append(f"  Remediation: {g.remediation_guidance}")
        lines.append("")

    return "\n".join(lines)


def format_evidence_human(evidence_list: List[ComplianceEvidence]) -> str:
    """Format evidence inventory in a structured text layout."""
    if not evidence_list:
        return "No compliance evidence registered."

    lines = [
        "=" * 75,
        "COMPLIANCE EVIDENCE REPOSITORY",
        "=" * 75,
        f"{'EVIDENCE ID':<16} {'TYPE':<16} {'STATUS':<12} {'CONTROL':<18} {'ASSET':<16}",
        "-" * 75,
    ]
    for e in evidence_list:
        lines.append(f"{e.id:<16} {e.type.value:<16} {e.status.value:<12} {e.control_id:<18} {e.asset_id:<16}")
        lines.append(f"  Source: {e.source} | Ref: {e.content_reference}")
    lines.append("=" * 75)
    return "\n".join(lines)


def format_diff_human(diff: ComplianceDiff) -> str:
    """Format snapshot diff and regressions summary."""
    lines = [
        "=" * 60,
        "COMPLIANCE SNAPSHOT COMPARISON & REGRESSION REPORT",
        "=" * 60,
        f"Identical State:     {diff.is_identical}",
        f"Regressions:         {len(diff.regressions)}",
        f"Status Changes:      {len(diff.control_status_changed)}",
        f"New Gaps:            {len(diff.new_gaps)}",
        f"Resolved Gaps:       {len(diff.resolved_gaps)}",
        f"Expired Evidence:    {len(diff.evidence_expired)}",
        "",
    ]
    if diff.regressions:
        lines.append("REGRESSIONS DETECTED:")
        for r in diff.regressions:
            lines.append(f"  [!] {r}")
        lines.append("")

    if diff.control_status_changed:
        lines.append("Status Changes:")
        for sc in diff.control_status_changed:
            lines.append(f"  - {sc}")
        lines.append("")

    if diff.new_gaps:
        lines.append("New Compliance Gaps:")
        for g in diff.new_gaps:
            lines.append(f"  + [{g.severity.value}] {g.title} ({g.control_id} @ {g.asset_id})")
        lines.append("")

    if diff.resolved_gaps:
        lines.append("Resolved Gaps:")
        for rg in diff.resolved_gaps:
            lines.append(f"  - Resolved: {rg.title} ({rg.control_id} @ {rg.asset_id})")
        lines.append("")

    if diff.evidence_expired:
        lines.append("Expired Evidence:")
        for ee in diff.evidence_expired:
            lines.append(f"  * {ee}")
        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)


def format_compliance_json(data: Any, indent: int = 2) -> str:
    """Format compliance data as indented JSON."""
    if hasattr(data, "to_dict"):
        payload = data.to_dict()
    elif isinstance(data, list):
        payload = [item.to_dict() if hasattr(item, "to_dict") else item for item in data]
    elif isinstance(data, dict):
        payload = {k: v.to_dict() if hasattr(v, "to_dict") else v for k, v in data.items()}
    else:
        payload = data
    return json.dumps(payload, indent=indent, default=str)


def format_compliance_yaml(data: Any) -> str:
    """Format compliance data as YAML."""
    if hasattr(data, "to_dict"):
        payload = data.to_dict()
    elif isinstance(data, list):
        payload = [item.to_dict() if hasattr(item, "to_dict") else item for item in data]
    elif isinstance(data, dict):
        payload = {k: v.to_dict() if hasattr(v, "to_dict") else v for k, v in data.items()}
    else:
        payload = data
    return yaml.safe_dump(payload, sort_keys=False)
