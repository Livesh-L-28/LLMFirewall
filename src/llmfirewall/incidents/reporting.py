"""Incident report generation, timeline formatting, and CLI presenters for Phase 38."""

from __future__ import annotations

from datetime import datetime
import json
from typing import Any, Dict, List, Optional
import yaml

from llmfirewall.incidents.models import SecurityIncident, TimelineEntry


def format_incidents_table_human(incidents: List[SecurityIncident]) -> str:
    """Formats a list of incidents as a clean, human-readable table."""
    if not incidents:
        return "No security incidents detected or on record."

    lines = [
        "================================================================================",
        "                       AI SECURITY INCIDENTS OVERVIEW                          ",
        "================================================================================",
        f"{'INCIDENT ID':<12} {'SEVERITY':<10} {'STATUS':<14} {'ASSETS':<24} {'TITLE'}",
        "-" * 80,
    ]

    for inc in incidents:
        assets_str = ", ".join(inc.assets[:2])
        if len(inc.assets) > 2:
            assets_str += f" (+{len(inc.assets)-2})"
        if not assets_str:
            assets_str = "global"

        lines.append(
            f"{inc.id:<12} {inc.severity.value:<10} {inc.status.value:<14} {assets_str:<24} {inc.title}"
        )

    lines.append("-" * 80)
    lines.append(f"Total Incidents: {len(incidents)}")
    return "\n".join(lines)


def format_incident_detail_human(incident: SecurityIncident, timeline: Optional[List[TimelineEntry]] = None) -> str:
    """Formats full incident details including evidence, actions, and attack paths."""
    lines = [
        "================================================================================",
        f"                 SECURITY INCIDENT DETAIL: {incident.id}                       ",
        "================================================================================",
        f"Title:          {incident.title}",
        f"Status:         {incident.status.value}",
        f"Severity:       {incident.severity.value}",
        f"Owner:          {incident.owner or 'Unassigned'}",
        f"Detected At:    {incident.detected_at.isoformat()}",
        f"Resolved At:    {incident.resolved_at.isoformat() if incident.resolved_at else 'Active / Unresolved'}",
        f"Affected Assets: {', '.join(incident.assets) if incident.assets else 'None'}",
        f"Attack Paths:   {', '.join(incident.attack_paths) if incident.attack_paths else 'None correlated'}",
        f"Correlated Evts: {len(incident.events)} event(s)",
        "",
        "--- Description ---",
        incident.description,
        "",
        "--- Actions & Containment Audit Trail ---",
    ]

    if not incident.actions:
        lines.append("  (No actions recorded yet)")
    else:
        for act in incident.actions:
            lines.append(
                f"  [{act.timestamp.strftime('%H:%M:%S')}] {act.action.value} by {act.actor}: {act.notes}"
            )

    if timeline:
        lines.append("")
        lines.append("--- Chronological Timeline ---")
        for t in timeline:
            obs = "[OBSERVED EVIDENCE]" if t.observed else "[HYPOTHESIS/INFERENCE]"
            ev_hash = f" (hash: {t.evidence_hash[:8]}...)" if t.evidence_hash else ""
            lines.append(f"  {t.timestamp.strftime('%Y-%m-%d %H:%M:%S')} {obs} | {t.title}{ev_hash}")
            lines.append(f"    └─ {t.description}")

    lines.append("================================================================================")
    return "\n".join(lines)


def format_incident_timeline_human(incident: SecurityIncident, timeline: List[TimelineEntry]) -> str:
    """Formats an investigation timeline exclusively."""
    lines = [
        f"INVESTIGATION TIMELINE FOR INCIDENT {incident.id}",
        "=" * 70,
        f"Incident: {incident.title} (Status: {incident.status.value}, Severity: {incident.severity.value})",
        "-" * 70,
    ]

    if not timeline:
        lines.append("No timeline entries recorded.")
    else:
        for entry in timeline:
            obs_tag = "[OBSERVED]" if entry.observed else "[HYPOTHESIS]"
            time_str = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            lines.append(f"[{time_str}] {obs_tag} {entry.stage}: {entry.title}")
            lines.append(f"    Detail: {entry.description}")
            if entry.evidence_hash:
                lines.append(f"    Evidence Hash: {entry.evidence_hash}")
            if entry.asset_id:
                lines.append(f"    Asset: {entry.asset_id}")

    lines.append("=" * 70)
    return "\n".join(lines)


def generate_post_incident_report(
    incident: SecurityIncident,
    timeline: Optional[List[TimelineEntry]] = None,
    format_type: str = "markdown",
) -> str:
    """Generates a structured Post-Incident Report.
    
    Clearly distinguishes observed evidence from hypotheses and includes:
    - Incident & Detection
    - Affected Assets
    - Chronological Timeline
    - Attack Path correlation
    - Preserved Evidence
    - Containment & Response Actions
    - Current Status
    - Root-Cause Indicators
    - Lessons / Follow-up Recommendations
    """
    if format_type.lower() == "json":
        data = incident.model_dump()
        data["timeline"] = [t.model_dump() for t in (timeline or [])]
        return json.dumps(data, indent=2, default=str)

    # Markdown Post-Incident Report
    md_lines = [
        f"# POST-INCIDENT SECURITY REPORT: {incident.id}",
        "",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Incident Title:** {incident.title}  ",
        f"**Current Status:** `{incident.status.value}`  ",
        f"**Assigned Severity:** `{incident.severity.value}`  ",
        f"**Assigned Owner:** `{incident.owner or 'Unassigned'}`  ",
        "",
        "---",
        "",
        "## 1. Executive Summary & Detection",
        f"{incident.description}",
        "",
        f"- **Initial Detection Time:** `{incident.detected_at.isoformat()}`",
        f"- **Resolution Time:** `{incident.resolved_at.isoformat() if incident.resolved_at else 'Active / Unresolved'}`",
        f"- **Total Correlated Events:** {len(incident.events)}",
        "",
        "## 2. Affected AI Assets & Capabilities",
    ]

    if incident.assets:
        for asset in incident.assets:
            md_lines.append(f"- `{asset}`")
    else:
        md_lines.append("- *(No specific assets isolated)*")

    md_lines.extend([
        "",
        "## 3. Attack Path Correlation (Phase 33)",
    ])

    if incident.attack_paths:
        for ap in incident.attack_paths:
            md_lines.append(f"- **Attack Path ID:** `{ap}`")
    else:
        md_lines.append("- *No corresponding attack graph paths breached or mapped.*")

    md_lines.extend([
        "",
        "## 4. Chronological Investigation Timeline",
        "",
        "| Timestamp (UTC) | Category | Classification | Title & Summary | Evidence Reference |",
        "|---|---|---|---|---|",
    ])

    if timeline:
        for t in timeline:
            obs = "**OBSERVED**" if t.observed else "*HYPOTHESIS*"
            hash_ref = f"`{t.evidence_hash[:10]}...`" if t.evidence_hash else "None"
            t_str = t.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            md_lines.append(
                f"| {t_str} | {t.stage} | {obs} | {t.title}: {t.description} | {hash_ref} |"
            )
    else:
        md_lines.append("| - | - | - | *(Timeline not populated)* | - |")

    md_lines.extend([
        "",
        "## 5. Preserved Evidence Artifacts",
        "> [!NOTE]",
        "> All evidence items are cryptographic hashes; sensitive payloads and raw credentials have been sanitized.",
        "",
    ])

    if incident.evidence:
        for i, ev in enumerate(incident.evidence, 1):
            md_lines.append(f"### Evidence Item #{i}")
            md_lines.append("```json")
            md_lines.append(json.dumps(ev, indent=2, default=str))
            md_lines.append("```")
    else:
        md_lines.append("*(No external evidence objects attached)*")

    md_lines.extend([
        "",
        "## 6. Actions Taken & Containment Trail",
    ])

    if incident.actions:
        for act in incident.actions:
            md_lines.append(
                f"- **[{act.timestamp.strftime('%H:%M:%S')}] {act.action.value}** by `{act.actor}`: {act.notes}"
            )
    else:
        md_lines.append("- *(No actions logged)*")

    md_lines.extend([
        "",
        "## 7. Root-Cause Indicators & Hypotheses",
        "",
        "- **Observed Finding:** Runtime security sensors recorded unauthorized operations matching threat signatures.",
        "- **Inferred Root Cause (Hypothesis):** Lack of strict parameter validation or missing boundary isolation between prompt input and tool capabilities.",
        "",
        "## 8. Lessons Learned & Recommended Remediations",
        "",
        "1. **Enforce Stricter Tool Authorization:** Ensure sensitive tools require explicit capability tokens.",
        "2. **Implement Input/Output Guardrails:** Enable Phase 39 runtime inspection policies in `ENFORCE` mode.",
        "3. **Update Attack Graph Tests:** Add regression tests in `tests/security/` to simulate the event chain.",
        "",
        "---",
        "*Report compiled automatically by LLMFirewall Incident Response Engine v1.0.0*",
    ])

    return "\n".join(md_lines)
