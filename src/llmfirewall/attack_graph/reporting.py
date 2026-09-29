"""Human-readable, JSON, and SARIF report formatters for AttackGraph and ThreatModel."""

import json
from typing import Any, Dict, List, Optional

from llmfirewall._version import __version__
from llmfirewall.attack_graph.models import AttackPath, MitigationStatus, PathStatus, ThreatModel


def format_attack_paths_human(
    paths: List[AttackPath],
    asset_id: Optional[str] = None,
    entry_points: Optional[List[str]] = None,
) -> str:
    """Format discovered attack paths into readable human output matching Phase 33 specification."""
    lines: List[str] = [
        "AI Attack Surface Report",
        "========================",
    ]

    if asset_id:
        lines.append(f"\nAsset:\n  {asset_id}")

    if entry_points:
        lines.append("\nEntry Points:")
        for ep in entry_points:
            lines.append(f"  - {ep}")

    lines.append(f"\nCandidate Attack Paths ({len(paths)}):\n")

    if not paths:
        lines.append("  No candidate attack paths discovered.")
        return "\n".join(lines)

    for idx, path in enumerate(paths, 1):
        lines.append(f"[{idx}] {path.path_id}")

        # Render chain
        if path.steps:
            for s_idx, step in enumerate(path.steps):
                tech_label = step.technique_name or step.technique
                if s_idx == 0:
                    lines.append(f"    {step.source}")
                lines.append(f"        ↓ [{tech_label}]")
                lines.append(f"    {step.target}")
        else:
            lines.append(f"    {path.source}  ──>  {path.target}")

        lines.append(f"\n    Status: {path.status.value}")
        lines.append(f"    Confidence: {path.confidence.value}")
        lines.append(f"    Mitigation Status: {path.mitigation_status.value}")

        # Evidence
        lines.append("    Evidence:")
        if path.evidence:
            for ev in path.evidence:
                lines.append(f"      - [{ev.evidence_type.value}] {ev.description}")
        else:
            lines.append("      - None recorded.")

        # Mitigations
        lines.append("    Mitigations:")
        if path.mitigations:
            for m in path.mitigations:
                lines.append(f"      - {m}")
        else:
            lines.append("      - None (Security Gap)")

        # Assumptions
        if path.assumptions:
            lines.append("    Assumptions:")
            for a in path.assumptions:
                lines.append(f"      - {a}")

        # Validation status
        validation_label = "TESTED & CONFIRMED" if path.is_tested else (
            "OBSERVED IN RUNTIME" if path.is_observed else "NOT TESTED"
        )
        lines.append(f"    Validation:\n      {validation_label}\n")

    return "\n".join(lines)


def format_threat_model_human(tm: ThreatModel) -> str:
    """Format ThreatModel into clean human-readable text."""
    lines: List[str] = [
        f"Threat Model: {tm.name}",
        "=" * (len(tm.name) + 14),
        f"Model ID: {tm.model_id} | Version: {tm.version}",
        "",
        "Entry Points:",
    ]
    if tm.entry_points:
        for ep in tm.entry_points:
            lines.append(f"  - {ep.name} ({ep.type.value}) -> target: {ep.target_asset_id}")
    else:
        lines.append("  - None defined")

    lines.append("\nAssets:")
    if tm.assets:
        for a in tm.assets:
            lines.append(f"  - {a}")
    else:
        lines.append("  - None defined")

    lines.append("\nTrust Boundaries:")
    if tm.trust_boundaries:
        for tb in tm.trust_boundaries:
            lines.append(f"  - {tb.source_entity} → {tb.target_entity} ({tb.trust_level_from} -> {tb.trust_level_to})")
    else:
        lines.append("  - None defined")

    lines.append(f"\nCandidate Attack Paths ({len(tm.attack_paths)}):")
    if tm.attack_paths:
        for idx, p in enumerate(tm.attack_paths, 1):
            hops = " → ".join(p.node_sequence)
            status_tag = f"[{p.status.value}]"
            lines.append(f"  {idx}. {hops} {status_tag} (Mitigation: {p.mitigation_status.value})")
    else:
        lines.append("  - None discovered")

    lines.append("\nControls:")
    if tm.security_controls:
        for c in tm.security_controls:
            lines.append(f"  - {c}")
    else:
        lines.append("  - None mapped")

    lines.append("\nUnverified Assumptions:")
    if tm.assumptions:
        for a in tm.assumptions:
            lines.append(f"  - {a}")
    else:
        lines.append("  - None recorded")

    if tm.security_gaps_count > 0:
        lines.append(f"\nSECURITY GAPS: {tm.security_gaps_count} unmitigated attack path(s) detected!")

    return "\n".join(lines)


def format_attack_paths_json(paths: List[AttackPath], indent: int = 2) -> str:
    """Format attack paths in standardized JSON schema."""
    doc = {
        "schema_version": "1",
        "paths_count": len(paths),
        "paths": [p.to_dict() for p in paths],
    }
    return json.dumps(doc, indent=indent, sort_keys=True)


def format_attack_graph_sarif(paths: List[AttackPath]) -> Dict[str, Any]:
    """Export validated and unmitigated attack path findings to SARIF 2.1.0."""
    sarif_results: List[Dict[str, Any]] = []

    for path in paths:
        # Invariant: Do not report theoretical blocked paths as vulnerabilities
        if path.status == PathStatus.BLOCKED:
            continue

        is_tested_or_observed = path.status in (PathStatus.TESTED, PathStatus.OBSERVED)
        is_unmitigated = path.mitigation_status == MitigationStatus.UNMITIGATED

        # Error if tested/observed, warning if unmitigated candidate, note otherwise
        if is_tested_or_observed:
            level = "error"
        elif is_unmitigated:
            level = "warning"
        else:
            level = "note"

        rule_id = f"LLMFIREWALL-ATTACK-{path.path_id}"
        message = (
            f"Attack path '{path.path_id}' ({path.status.value}): "
            f"{' -> '.join(path.node_sequence)}. "
            f"Techniques: [{', '.join(path.technique_sequence)}]. "
            f"Mitigation: {path.mitigation_status.value}."
        )

        sarif_results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": message,
            },
            "properties": {
                "path_id": path.path_id,
                "source": path.source,
                "target": path.target,
                "status": path.status.value,
                "confidence": path.confidence.value,
                "mitigation_status": path.mitigation_status.value,
                "technique_sequence": path.technique_sequence,
                "assumptions": path.assumptions,
            },
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LLMFirewall Attack Graph & Threat Modeling",
                        "version": __version__,
                        "informationUri": "https://github.com/livesh/LLMFirewall",
                        "rules": [
                            {
                                "id": f"LLMFIREWALL-ATTACK-{p.path_id}",
                                "name": f"AttackPath_{p.path_id}",
                                "shortDescription": {
                                    "text": f"Potential AI Attack Path to {p.target}",
                                },
                            }
                            for p in paths
                            if p.status != PathStatus.BLOCKED
                        ],
                    }
                },
                "results": sarif_results,
            }
        ],
    }
