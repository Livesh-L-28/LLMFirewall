"""Reporting and terminal formatting helpers for AI Security Knowledge Graph outcomes."""

import json
from typing import Any, Dict, List

from llmfirewall.graph.models import (
    BlastRadiusResult,
    ControlCoverageResult,
    GraphDiff,
    GraphPath,
    Node,
    Relationship,
    SecurityDiff,
    SecurityImpactResult,
)


def format_impact_human(impact: SecurityImpactResult) -> str:
    """Format SecurityImpactResult into clean, readable terminal text."""
    lines = []
    lines.append("=" * 65)
    lines.append(f" Security Impact Analysis: {impact.asset_id} ({impact.asset_type.upper()})")
    lines.append("=" * 65)
    lines.append(f"Direct Connections: {impact.directly_connected_count} | Total Impacted Entities: {impact.total_impact_count}")
    lines.append("-" * 65)

    if impact.controls:
        lines.append(f"Security Controls ({len(impact.controls)}):")
        for c in impact.controls:
            lines.append(f"  • {c if isinstance(c, str) else c['id']}")
    else:
        lines.append("Security Controls: None directly attached")

    if impact.policies:
        lines.append(f"\nGoverning Policies ({len(impact.policies)}):")
        for p in impact.policies:
            lines.append(f"  • {p if isinstance(p, str) else p['id']}")

    if impact.findings:
        lines.append(f"\nAffecting Findings ({len(impact.findings)}):")
        for f in impact.findings:
            if isinstance(f, dict):
                sev = f.get("properties", {}).get("severity", "unknown").upper()
                lines.append(f"  • [{sev}] {f['id']}")
            else:
                lines.append(f"  • {f}")

    if impact.tests:
        lines.append(f"\nEvaluating Tests ({len(impact.tests)}):")
        for t in impact.tests:
            lines.append(f"  • {t if isinstance(t, str) else t['id']}")

    if impact.threats:
        lines.append(f"\nTargeting Threats & Attack Techniques ({len(impact.threats)}):")
        for th in impact.threats:
            lines.append(f"  • {th if isinstance(th, str) else th['id']}")

    if impact.dependencies:
        lines.append(f"\nUnderlying Dependencies ({len(impact.dependencies)}):")
        for d in impact.dependencies:
            lines.append(f"  • {d if isinstance(d, str) else d['id']}")

    lines.append("=" * 65)
    return "\n".join(lines)


def format_blast_radius_human(blast: BlastRadiusResult) -> str:
    """Format BlastRadiusResult into clean terminal output."""
    lines = []
    lines.append("=" * 65)
    lines.append(f" Security Blast Radius Assessment: {blast.source_asset_id}")
    lines.append("=" * 65)
    lines.append(f"Origin Type: {blast.source_asset_type} | Total Cascading Nodes: {blast.total_impacted_nodes} | Max Propagation Depth: {blast.max_depth_reached}")
    lines.append("-" * 65)

    if blast.impacted_applications:
        lines.append(f"Impacted Applications ({len(blast.impacted_applications)}):")
        for a in blast.impacted_applications:
            lines.append(f"  • {a}")

    if blast.impacted_agents:
        lines.append(f"Impacted Agents ({len(blast.impacted_agents)}):")
        for ag in blast.impacted_agents:
            lines.append(f"  • {ag}")

    if blast.impacted_tools:
        lines.append(f"Impacted Tools ({len(blast.impacted_tools)}):")
        for t in blast.impacted_tools:
            lines.append(f"  • {t}")

    if blast.impacted_models:
        lines.append(f"Impacted Models ({len(blast.impacted_models)}):")
        for m in blast.impacted_models:
            lines.append(f"  • {m}")

    if blast.impacted_policies:
        lines.append(f"Impacted Policies ({len(blast.impacted_policies)}):")
        for p in blast.impacted_policies:
            lines.append(f"  • {p}")

    if blast.impacted_findings:
        lines.append(f"Associated Findings ({len(blast.impacted_findings)}):")
        for f in blast.impacted_findings:
            lines.append(f"  • {f}")

    lines.append("=" * 65)
    return "\n".join(lines)


def format_coverage_human(cov: ControlCoverageResult) -> str:
    """Format ControlCoverageResult without fake coverage assumptions."""
    lines = []
    lines.append("=" * 65)
    lines.append(f" Control Coverage Assessment: {cov.asset_id} ({cov.asset_type.upper()})")
    lines.append("=" * 65)
    lines.append(f"Total Controls: {cov.total_controls} | Passing: {cov.passing_controls} | Failing: {cov.failing_controls} | Rate: {cov.coverage_rate * 100:.1f}%")
    lines.append("-" * 65)

    if not cov.controls:
        lines.append("No security controls registered protecting this asset.")
    else:
        for c in cov.controls:
            icon = "✓" if c.status.value == "passing" else ("✗" if c.status.value == "failing" else "•")
            lines.append(f"  {icon} [{c.status.value.upper():<10}] {c.control_name} ({c.control_id})")
            if c.verified_by_test:
                lines.append(f"      Verified by test: {c.verified_by_test}")

    lines.append("=" * 65)
    return "\n".join(lines)


def format_graph_diff_human(diff: GraphDiff) -> str:
    """Format GraphDiff into human-readable text."""
    lines = []
    lines.append("=" * 65)
    lines.append(" Knowledge Graph Structural Diff")
    lines.append("=" * 65)
    lines.append(f"Identical: {diff.is_identical}")
    lines.append(f"Nodes Added: {len(diff.nodes_added)} | Removed: {len(diff.nodes_removed)} | Changed: {len(diff.nodes_changed)}")
    lines.append(f"Relationships Added: {len(diff.relationships_added)} | Removed: {len(diff.relationships_removed)}")
    lines.append("-" * 65)

    if diff.nodes_added:
        lines.append(f"Added Nodes ({len(diff.nodes_added)}):")
        for n in diff.nodes_added:
            lines.append(f"  + {n}")

    if diff.nodes_removed:
        lines.append(f"Removed Nodes ({len(diff.nodes_removed)}):")
        for n in diff.nodes_removed:
            lines.append(f"  - {n}")

    if diff.relationships_added:
        lines.append(f"Added Relationships ({len(diff.relationships_added)}):")
        for r in diff.relationships_added:
            lines.append(f"  + {r}")

    if diff.relationships_removed:
        lines.append(f"Removed Relationships ({len(diff.relationships_removed)}):")
        for r in diff.relationships_removed:
            lines.append(f"  - {r}")

    lines.append("=" * 65)
    return "\n".join(lines)


def format_node_show_human(
    node: Node,
    in_edges: List[Relationship],
    out_edges: List[Relationship],
) -> str:
    """Format single node details and its bidirectional connection edges."""
    lines = []
    lines.append("=" * 65)
    lines.append(f" Node: {node.id}")
    lines.append("=" * 65)
    lines.append(f"Type: {node.type}")
    if node.properties:
        lines.append(f"Properties: {json.dumps(node.properties, indent=2)}")
    lines.append("-" * 65)

    lines.append(f"Outgoing Relationships ({len(out_edges)}):")
    if not out_edges:
        lines.append("  (none)")
    else:
        for e in out_edges:
            lines.append(f"  ──[{e.type}]──> {e.target}")

    lines.append(f"\nIncoming Relationships ({len(in_edges)}):")
    if not in_edges:
        lines.append("  (none)")
    else:
        for e in in_edges:
            lines.append(f"  <──[{e.type}]── {e.source}")

    lines.append("=" * 65)
    return "\n".join(lines)


def format_path_human(path: GraphPath) -> str:
    """Format traversed graph path."""
    segments = []
    for i, node in enumerate(path.nodes):
        segments.append(node)
        if i < len(path.relationships):
            segments.append(f"──[{path.relationships[i]}]──>")
    return " ".join(segments)
