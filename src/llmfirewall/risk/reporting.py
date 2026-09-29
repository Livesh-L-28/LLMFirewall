"""Reporting formatters (Human-readable text, JSON, YAML) for Phase 37 AI Security Risk Engine."""

import json
from typing import Any, Dict, List
import yaml

from llmfirewall.risk.models import RiskAssessment, RiskDiff


def format_risk_human(risks: List[RiskAssessment]) -> str:
    """Format risk assessments into structured, explainable CLI output."""
    if not risks:
        return "No prioritized security risks identified."

    lines = [
        "=" * 80,
        "AI SECURITY RISK PRIORITIZATION & ASSESSMENT REPORT",
        "=" * 80,
        f"{'LEVEL':<10} {'RISK ID':<16} {'ASSET':<24} {'IMPACT':<8} {'EXPOSURE':<10}",
        "-" * 80,
    ]

    for r in risks:
        lines.append(f"{r.level.value:<10} {r.id:<16} {r.asset_id:<24} {r.impact:<8.2f} {r.exposure.upper():<10}")
        lines.append(f"  Title:     {r.title}")
        lines.append(f"  Rationale: {r.rationale}")
        if r.inherited_from:
            lines.append(f"  Inherited: Downstream target '{r.inherited_from}'")
        if r.remediation_guidance:
            lines.append(f"  Guidance:  {r.remediation_guidance}")
        lines.append("")

    lines.append("-" * 80)
    lines.append("NOTE: Risk priority is deterministically computed from exposure, control efficacy, and attack reachability.")
    lines.append("=" * 80)
    return "\n".join(lines)


def format_risk_detail_human(r: RiskAssessment) -> str:
    """Format full details and factor breakdown for an individual risk."""
    lines = [
        "=" * 60,
        f"RISK ASSESSMENT DETAILS: {r.id}",
        "=" * 60,
        f"Target Asset:       {r.asset_id}",
        f"Risk Level:         {r.level.value}",
        f"Impact:             {r.impact:.2f}",
        f"Exposure:           {r.exposure.upper()}",
        f"Exploitability:     {r.exploitability:.2f}",
        f"Uncertainty:        {r.uncertainty.value}",
        f"Treatment:          {r.treatment.value}",
        f"Inherited From:     {r.inherited_from or 'None'}",
        f"Rationale:          {r.rationale}",
        "",
        "Independently Evaluated Risk Factors:",
    ]

    for f in r.factors:
        lines.append(f"  - [{f.factor_type.value}] {f.name} (Score: {f.score:.2f}, Weight: {f.weight:.1f})")
        lines.append(f"    {f.description}")
        if f.rationale:
            lines.append(f"    Reason: {f.rationale}")

    if r.remediation_guidance:
        lines.extend(["", f"Remediation Guidance: {r.remediation_guidance}"])

    lines.append("=" * 60)
    return "\n".join(lines)


def format_risk_diff_human(diff: RiskDiff) -> str:
    """Format risk delta and regressions."""
    lines = [
        "=" * 60,
        "RISK POSTURE COMPARISON & REGRESSION REPORT",
        "=" * 60,
        f"Identical State:     {diff.is_identical}",
        f"Regressions:         {len(diff.regressions)}",
        f"Level Changes:       {len(diff.level_changes)}",
        f"New Risks:           {len(diff.new_risks)}",
        f"Resolved Risks:      {len(diff.resolved_risks)}",
        "",
    ]
    if diff.regressions:
        lines.append("RISK REGRESSIONS DETECTED:")
        for reg in diff.regressions:
            lines.append(f"  [!] {reg}")
        lines.append("")

    if diff.level_changes:
        lines.append("Level Transitions:")
        for lc in diff.level_changes:
            lines.append(f"  * {lc}")
        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)


def format_risk_json(data: Any, indent: int = 2) -> str:
    if hasattr(data, "to_dict"):
        payload = data.to_dict()
    elif isinstance(data, list):
        payload = [item.to_dict() if hasattr(item, "to_dict") else item for item in data]
    elif isinstance(data, dict):
        payload = {k: v.to_dict() if hasattr(v, "to_dict") else v for k, v in data.items()}
    else:
        payload = data
    return json.dumps(payload, indent=indent, default=str)


def format_risk_yaml(data: Any) -> str:
    if hasattr(data, "to_dict"):
        payload = data.to_dict()
    elif isinstance(data, list):
        payload = [item.to_dict() if hasattr(item, "to_dict") else item for item in data]
    elif isinstance(data, dict):
        payload = {k: v.to_dict() if hasattr(v, "to_dict") else v for k, v in data.items()}
    else:
        payload = data
    return yaml.safe_dump(payload, sort_keys=False)
