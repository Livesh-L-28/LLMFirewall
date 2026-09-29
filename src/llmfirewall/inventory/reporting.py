"""Human-readable, JSON, and CLI report formatters for AI Asset Inventory and Discovery."""

import json
from typing import Any, Dict, List, Optional

from llmfirewall.inventory.models import (
    Asset,
    AssetExposure,
    DiscoveryResult,
    InventoryDiff,
)


def format_inventory_list_human(assets: List[Asset]) -> str:
    """Format inventory assets list into readable table/bullet output."""
    lines: List[str] = [
        "AI Asset Inventory",
        "==================",
        f"Total Assets: {len(assets)}\n",
    ]

    if not assets:
        lines.append("  No assets found matching criteria.")
        return "\n".join(lines)

    lines.append(f"{'Asset ID':<36} | {'Type':<18} | {'Env':<10} | {'Status':<8} | {'Source':<16}")
    lines.append("-" * 96)

    for a in assets:
        lines.append(
            f"{a.id:<36} | {a.type:<18} | {a.environment:<10} | {a.status.value:<8} | {a.source.value:<16}"
        )

    return "\n".join(lines)


def format_asset_show_human(asset: Asset, exposure: Optional[AssetExposure] = None) -> str:
    """Format single asset details, provenance, and security exposure matching Section 57."""
    lines: List[str] = [
        f"Asset Details: {asset.id}",
        "=" * (len(asset.id) + 15),
        f"Name:         {asset.name}",
        f"Type:         {asset.type}",
        f"Version:      {asset.version or 'unversioned'}",
        f"Environment:  {asset.environment}",
        f"Status:       {asset.status.value}",
        f"Primary Source: {asset.source.value}",
        f"Confidence:   {asset.confidence.value}",
        f"Fingerprint:  {asset.fingerprint[:16]}...",
        f"First Seen:   {asset.first_seen}",
        f"Last Seen:    {asset.last_seen}",
    ]

    if asset.tags:
        lines.append(f"Tags:         {', '.join(asset.tags)}")
    if asset.owner:
        lines.append(f"Owner:        {asset.owner}")

    # Provenance
    lines.append("\nProvenance Sources:")
    if asset.provenance:
        for p in asset.provenance:
            lines.append(f"  - [{p.source.value}] via '{p.provider_name}' (ref: {p.reference or 'direct'})")
    else:
        lines.append("  - None recorded")

    # Conflicts
    if asset.conflicts:
        lines.append("\nRecorded Conflicts:")
        for c in asset.conflicts:
            lines.append(f"  - [{c.field}]: configured='{c.configured_value}' vs observed='{c.observed_value}' ({c.description})")

    # Exposure Details
    if exposure:
        lines.append("\nSecurity Exposure:")
        lines.append(f"  Entry Points ({len(exposure.entry_points)}):")
        for ep in exposure.entry_points:
            lines.append(f"    - {ep}")
        if not exposure.entry_points:
            lines.append("    - None")

        lines.append(f"  Accessible Tools ({len(exposure.tools)}):")
        for t in exposure.tools:
            lines.append(f"    - {t}")
        if not exposure.tools:
            lines.append("    - None")

        lines.append(f"  Protecting Security Controls ({len(exposure.security_controls)}):")
        for c in exposure.security_controls:
            lines.append(f"    - {c}")
        if not exposure.security_controls:
            lines.append("    - None (Unprotected)")

        lines.append(f"  Candidate Attack Paths ({len(exposure.attack_paths)}):")
        for p in exposure.attack_paths:
            p_id = p.get("path_id", "path")
            p_status = p.get("status", "CANDIDATE")
            p_mit = p.get("mitigation_status", "UNMITIGATED")
            lines.append(f"    - {p_id}: {p_status} [{p_mit}]")
        if not exposure.attack_paths:
            lines.append("    - None")

        lines.append(f"  Associated Findings ({len(exposure.findings)}):")
        for f in exposure.findings:
            lines.append(f"    - [{f.get('id')}] {f.get('type')}: {f.get('properties', {}).get('severity', 'medium')}")
        if not exposure.findings:
            lines.append("    - None")

    return "\n".join(lines)


def format_discovery_result_human(res: DiscoveryResult) -> str:
    """Format discovery execution result report matching Section 68."""
    lines: List[str] = [
        "AI Asset Discovery Run Report",
        "=============================",
        f"Status:            {res.status.value}",
        f"Assets Discovered: {res.assets_discovered}",
        f"Assets Added:      {res.assets_added}",
        f"Assets Changed:    {res.assets_changed}",
        f"Assets Removed:    {res.assets_removed}",
        f"Duration:          {res.duration_ms:.2f} ms",
        "\nProviders:",
    ]

    for p_name, p_res in res.provider_results.items():
        st = p_res.get("status", "unknown")
        found = p_res.get("assets_found", 0)
        dur = p_res.get("duration_ms", 0.0)
        err = f" | Error: {p_res['error']}" if "error" in p_res else ""
        lines.append(f"  - {p_name:<24}: {st:<8} ({found} assets, {dur:.1f} ms){err}")

    if res.warnings:
        lines.append("\nWarnings:")
        for w in res.warnings:
            lines.append(f"  - {w}")

    return "\n".join(lines)


def format_inventory_diff_human(diff: InventoryDiff) -> str:
    """Format inventory comparison diff matching Section 53."""
    lines: List[str] = [
        "Inventory Architectural Diff",
        "============================",
    ]

    if diff.is_identical:
        lines.append("Inventories are identical. No drift detected.")
        return "\n".join(lines)

    lines.append(f"Added ({len(diff.assets_added)}):")
    if diff.assets_added:
        for a_id in diff.assets_added:
            lines.append(f"  + {a_id}")
    else:
        lines.append("  (none)")

    lines.append(f"\nChanged ({len(diff.assets_changed)}):")
    if diff.assets_changed:
        for a_id in diff.assets_changed:
            lines.append(f"  ~ {a_id}")
    else:
        lines.append("  (none)")

    lines.append(f"\nRemoved ({len(diff.assets_removed)}):")
    if diff.assets_removed:
        for a_id in diff.assets_removed:
            lines.append(f"  - {a_id}")
    else:
        lines.append("  (none)")

    if diff.relationships_changed:
        lines.append("\nGraph Topology Changes:")
        for r in diff.relationships_changed:
            lines.append(f"  * {r}")

    return "\n".join(lines)


def format_inventory_json(assets: List[Asset], indent: int = 2) -> str:
    """Format assets in standardized JSON schema."""
    doc = {
        "schema_version": "1.0.0",
        "assets_count": len(assets),
        "assets": [a.to_dict() for a in assets],
    }
    return json.dumps(doc, indent=indent, sort_keys=True)


def format_discovery_result_json(res: DiscoveryResult, indent: int = 2) -> str:
    """Format discovery result in JSON schema."""
    doc = {
        "schema_version": "1.0.0",
        **res.to_dict(),
    }
    return json.dumps(doc, indent=indent, sort_keys=True)
