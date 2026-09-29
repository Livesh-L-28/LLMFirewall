"""Human-readable, JSON, and SARIF report formatters for AI Security Posture Management (AI-SPM)."""

import json
from typing import Any, Dict, List, Optional, Union

from llmfirewall.spm.models import (
    ControlEffectiveness,
    ControlPresence,
    PostureDiff,
    PostureSnapshot,
    PostureState,
    SecurityGap,
    SecurityPosture,
    sanitize_posture_metadata,
)


def _control_glyph(presence: ControlPresence, effectiveness: ControlEffectiveness) -> str:
    """Return appropriate Unicode indicator symbol for a security control."""
    if effectiveness == ControlEffectiveness.FAILED or presence == ControlPresence.ABSENT:
        return "✗"
    if effectiveness == ControlEffectiveness.VALIDATED or presence == ControlPresence.PRESENT:
        return "✓"
    if presence == ControlPresence.PARTIALLY_PRESENT or effectiveness in (ControlEffectiveness.CONFIGURED, ControlEffectiveness.TESTED):
        return "⚠"
    return "?"


def format_posture_human(posture: SecurityPosture) -> str:
    """Format single asset posture into human-readable report matching Sections 51 and 52."""
    state_glyph = {
        PostureState.HEALTHY: "✓ HEALTHY",
        PostureState.ATTENTION_REQUIRED: "⚠ ATTENTION_REQUIRED",
        PostureState.DEGRADED: "▼ DEGRADED",
        PostureState.CRITICAL: "✖ CRITICAL",
        PostureState.UNKNOWN: "? UNKNOWN",
    }.get(posture.state, posture.state.value)

    lines: List[str] = [
        "AI Security Posture Report",
        "=========================",
        f"Asset:       {posture.asset_name or posture.asset_id}",
        f"Asset ID:    {posture.asset_id}",
        f"Type:        {posture.asset_type}",
        f"Environment: {posture.environment}",
        f"State:       {state_glyph}",
    ]
    if posture.state_reason:
        lines.append(f"Reason:      {posture.state_reason}")
    if posture.fingerprint:
        lines.append(f"Fingerprint: {posture.fingerprint[:16]}...")

    # Controls Section
    lines.append("\nControls")
    lines.append("--------")
    if posture.controls:
        for cid, ctrl in sorted(posture.controls.items()):
            glyph = _control_glyph(ctrl.presence, ctrl.effectiveness)
            status_desc = f"Presence: {ctrl.presence.value} | Effectiveness: {ctrl.effectiveness.value}"
            if ctrl.tested:
                fresh_str = f" [Freshness: {ctrl.test_freshness.value}]"
            else:
                fresh_str = " [UNTESTED]"
            lines.append(f"  {glyph} {ctrl.name:<30} ({status_desc}){fresh_str}")
            for ev in ctrl.evidence:
                lines.append(f"      - {ev}")
    else:
        lines.append("  ? No security controls registered or detected.")

    # Testing Section
    lines.append("\nTesting")
    lines.append("-------")
    cov = posture.test_coverage
    lines.append(f"  Total:        {cov.total_tests}")
    lines.append(f"  Passed:       {cov.passed}")
    lines.append(f"  Failed:       {cov.failed}")
    lines.append(f"  Not Executed: {cov.not_executed}")
    if cov.is_stale:
        lines.append(f"  Status:       STALE ({cov.stale_reason or 'asset modified after testing'})")
    elif cov.total_tests > 0:
        lines.append("  Status:       FRESH")
    else:
        lines.append("  Status:       UNTESTED")

    # Attack Surface Section
    lines.append("\nAttack Surface")
    lines.append("--------------")
    surf = posture.attack_surface
    lines.append(f"  Tools:            {surf.tools_count} ({', '.join(surf.tools) if surf.tools else 'None'})")
    lines.append(f"  External APIs:    {surf.external_apis_count} ({', '.join(surf.external_apis) if surf.external_apis else 'None'})")
    lines.append(f"  Memory Stores:    {surf.memory_stores_count} ({', '.join(surf.memory_stores) if surf.memory_stores else 'None'})")
    lines.append(f"  RAG Sources:      {surf.rag_sources_count} ({', '.join(surf.rag_sources) if surf.rag_sources else 'None'})")
    lines.append(f"  External Entry:   {surf.entry_points_count} ({', '.join(surf.entry_points) if surf.entry_points else 'None'})")

    if surf.entry_point_postures:
        lines.append("  Entry Point Details:")
        for ep, ep_posture in surf.entry_point_postures.items():
            lines.append(f"    - {ep}:")
            for prop, val in ep_posture.items():
                lines.append(f"        {prop}: {val}")

    # Attack Paths Section
    lines.append("\nAttack Paths")
    lines.append("------------")
    paths = posture.attack_paths
    cand = len(paths.get("candidate", []))
    supp = len(paths.get("supported", []))
    test = len(paths.get("tested", []))
    obs = len(paths.get("observed", []))
    blk = len(paths.get("blocked", []))
    lines.append(f"  Candidate: {cand} | Supported: {supp} | Tested: {test} | Observed: {obs} | Blocked: {blk}")
    for category in ("supported", "candidate", "tested"):
        for p in paths.get(category, []):
            pid = p.get("path_id", "unknown")
            desc = p.get("description", "")
            mit = p.get("mitigation_status", "UNMITIGATED")
            lines.append(f"    - [{category.upper()}] {pid}: {desc} (Mitigation: {mit})")

    # Security Gaps Section
    lines.append("\nSecurity Gaps")
    lines.append("-------------")
    if posture.security_gaps:
        for idx, gap in enumerate(posture.security_gaps, 1):
            lines.append(f"  {idx}. [{gap.severity.value}] {gap.title} ({gap.dimension})")
            lines.append(f"     Description: {gap.description}")
            if gap.related_control:
                lines.append(f"     Related Control: {gap.related_control}")
            if gap.related_attack_path:
                lines.append(f"     Related Attack Path: {gap.related_attack_path}")
            if gap.remediation_guidance:
                lines.append(f"     Remediation: {gap.remediation_guidance}")
            if gap.evidence:
                lines.append("     Evidence:")
                for ev in gap.evidence:
                    lines.append(f"       * {ev}")
    else:
        lines.append("  ✓ No open security gaps identified.")

    # Policy Posture
    if posture.policy_status:
        lines.append("\nPolicy Posture")
        lines.append("--------------")
        assigned = posture.policy_status.get("assigned_policies", [])
        lines.append(f"  Assigned Policies: {len(assigned)}")
        for pol in assigned:
            name = pol.get("name", "policy")
            ver = pol.get("version", "unknown")
            status = pol.get("status", "ACTIVE")
            lines.append(f"    - {name} (v{ver}): {status}")
        conflicts = posture.policy_status.get("conflicts", [])
        if conflicts:
            lines.append("  ⚠ Policy Conflicts Detected:")
            for conf in conflicts:
                lines.append(f"    - {conf}")

    # Unknowns
    if posture.unknowns:
        lines.append("\nUnknown Areas")
        lines.append("-------------")
        for u in posture.unknowns:
            lines.append(f"  ? {u}")

    # Consolidated Evidence
    if posture.evidence:
        lines.append("\nConsolidated Evidence")
        lines.append("---------------------")
        for ev in posture.evidence:
            lines.append(f"  - {ev}")

    return "\n".join(lines)


def format_posture_summary_human(summary: Dict[str, Any]) -> str:
    """Format aggregated security posture summary matching Section 48."""
    lines: List[str] = [
        "AI Security Posture",
        "===================",
        f"Assets: {summary.get('assets_count', 0)}\n",
    ]

    states = summary.get("posture_states", {})
    if states:
        lines.append("Posture States:")
        for s in ("HEALTHY", "ATTENTION_REQUIRED", "DEGRADED", "CRITICAL", "UNKNOWN"):
            lines.append(f"  {s:<20}: {states.get(s, 0)}")
        lines.append("")

    ctrls = summary.get("controls", {})
    lines.append("Controls:")
    lines.append(f"  Present:  {ctrls.get('PRESENT', 0)}")
    lines.append(f"  Partial:  {ctrls.get('PARTIALLY_PRESENT', 0)}")
    lines.append(f"  Unknown:  {ctrls.get('UNKNOWN', 0)}")
    lines.append(f"  Absent:   {ctrls.get('ABSENT', 0)}\n")

    finds = summary.get("findings", {})
    lines.append("Findings:")
    lines.append(f"  Open:     {finds.get('open', 0)}\n")

    paths = summary.get("attack_paths", {})
    lines.append("Attack Paths:")
    lines.append(f"  Candidate: {paths.get('candidate', 0)}")
    lines.append(f"  Supported: {paths.get('supported', 0)}")
    lines.append(f"  Tested:    {paths.get('tested', 0)}")
    lines.append(f"  Observed:  {paths.get('observed', 0)}\n")

    tests = summary.get("security_tests", {})
    lines.append("Security Tests:")
    lines.append(f"  Passed:     {tests.get('passed', 0)}")
    lines.append(f"  Failed:     {tests.get('failed', 0)}")
    lines.append(f"  Not Tested: {tests.get('not_executed', 0)}\n")

    gaps = summary.get("security_gaps", {})
    by_sev = gaps.get("by_severity", {})
    lines.append("Security Gaps:")
    lines.append(f"  Total:      {gaps.get('total', 0)}")
    if by_sev:
        lines.append(f"  Critical:   {by_sev.get('CRITICAL', 0)}")
        lines.append(f"  High:       {by_sev.get('HIGH', 0)}")
        lines.append(f"  Medium:     {by_sev.get('MEDIUM', 0)}")
        lines.append(f"  Low:        {by_sev.get('LOW', 0)}")
    lines.append("")

    lines.append("Unknown Areas:")
    lines.append(f"  {summary.get('unknown_areas_count', 0)}")

    return "\n".join(lines)


def format_posture_diff_human(diff: PostureDiff) -> str:
    """Format comparative posture diff into human-readable regression/improvement output."""
    lines: List[str] = [
        "AI Security Posture Diff",
        "========================",
        f"Identical Baseline: {'YES' if diff.is_identical else 'NO'}\n",
    ]

    if diff.regressions:
        lines.append("Security Regressions Detected:")
        for reg in diff.regressions:
            lines.append(f"  ✖ {reg}")
        lines.append("")

    if diff.posture_improved:
        lines.append("Posture Improvements:")
        for imp in diff.posture_improved:
            lines.append(f"  ✓ {imp}")
        lines.append("")

    if diff.posture_degraded:
        lines.append("Posture Degradations:")
        for deg in diff.posture_degraded:
            lines.append(f"  ▼ {deg}")
        lines.append("")

    if diff.controls_added:
        lines.append("Controls Added:")
        for c in diff.controls_added:
            lines.append(f"  + {c}")
        lines.append("")

    if diff.controls_removed:
        lines.append("Controls Removed:")
        for c in diff.controls_removed:
            lines.append(f"  - {c}")
        lines.append("")

    if diff.tests_became_stale:
        lines.append("Tests Became Stale:")
        for t in diff.tests_became_stale:
            lines.append(f"  ⚠ {t}")
        lines.append("")

    if diff.new_security_gaps:
        lines.append("New Security Gaps:")
        for g in diff.new_security_gaps:
            lines.append(f"  ! [{g.severity.value}] {g.title} ({g.asset_id})")
        lines.append("")

    if diff.gaps_resolved:
        lines.append("Security Gaps Resolved:")
        for g in diff.gaps_resolved:
            lines.append(f"  ✓ [{g.severity.value}] {g.title} ({g.asset_id})")
        lines.append("")

    if diff.attack_surface_changed:
        lines.append("Attack Surface Changes:")
        for sc in diff.attack_surface_changed:
            lines.append(f"  * {sc}")
        lines.append("")

    if diff.policy_conflicts_detected:
        lines.append("Policy Conflicts Detected:")
        for pc in diff.policy_conflicts_detected:
            lines.append(f"  ⚠ {pc}")
        lines.append("")

    return "\n".join(lines)


def format_posture_json(data: Any, indent: int = 2) -> str:
    """Format posture models, snapshots, or summaries to sanitized versioned JSON."""
    if hasattr(data, "to_dict"):
        raw_dict = data.to_dict()
    elif isinstance(data, dict):
        raw_dict = data
    else:
        raw_dict = {"data": str(data)}

    # Ensure schema_version is present
    if "schema_version" not in raw_dict:
        raw_dict["schema_version"] = "1.0.0"

    sanitized = sanitize_posture_metadata(raw_dict)
    return json.dumps(sanitized, indent=indent, default=str, sort_keys=True)


def format_posture_sarif(sarif_data: Dict[str, Any], indent: int = 2) -> str:
    """Format SARIF 2.1.0 output to formatted JSON string."""
    sanitized = sanitize_posture_metadata(sarif_data)
    return json.dumps(sanitized, indent=indent, default=str)
