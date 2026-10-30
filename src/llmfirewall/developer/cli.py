"""CLI handler and formatting for LLMFirewall developer commands."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

from llmfirewall.cli.errors import EXIT_ALLOWED, EXIT_BLOCKED, EXIT_SYSTEM_ERROR, EXIT_USAGE_ERROR
from llmfirewall.developer.detector import RECIPE_CATALOG, detect_project_frameworks
from llmfirewall.developer.templates import generate_scaffold, list_supported_recipes
from llmfirewall.developer.validator import validate_integration


def handle_integrate(
    action: Optional[str] = "detect",
    target_path: str = ".",
    recipe: Optional[str] = None,
    write_app: Optional[str] = None,
    write_test: Optional[str] = None,
    force: bool = False,
    policy_file: Optional[str] = None,
    json_mode: bool = False,
    format_type: str = "human",
    output_file: Optional[str] = None,
) -> int:
    """Execute developer integration subcommand."""
    action = (action or "detect").lower().strip()
    is_json = json_mode or (format_type == "json")

    out_lines: list[str] = []

    try:
        # ACTION 1: DETECT
        if action == "detect":
            res = detect_project_frameworks(target_path)
            if is_json:
                payload = json.dumps(res.to_dict(), indent=2)
                _emit_output(payload, output_file)
                return EXIT_ALLOWED

            out_lines.append("=" * 70)
            out_lines.append("LLMFirewall Integration Framework & Trust Boundary Detection")
            out_lines.append("=" * 70)
            out_lines.append(f"Target Path: {res.target_path}")
            out_lines.append(f"Detected Frameworks: {', '.join(res.detected_frameworks) if res.detected_frameworks else 'None (Generic Python / Pure ASGI)'}")
            if res.manifest_dependencies:
                out_lines.append(f"Dependencies Found:  {', '.join(res.manifest_dependencies[:10])}")

            out_lines.append("\nIdentified Architectural Trust Boundaries:")
            if res.trust_boundaries:
                for b in res.trust_boundaries:
                    out_lines.append(f"  [{b.boundary_type.upper()}] {b.file_path}:{b.line_number} -> {b.description}")
                    out_lines.append(f"    Snippet: {b.snippet}")
            else:
                out_lines.append("  No explicit route handlers or streaming boundaries identified in current directory.")

            out_lines.append("\nRecommended Integration Recipes:")
            for rec in res.recommendations:
                out_lines.append(f"  * {rec.framework} (Recipe: '{rec.recipe_name}')")
                out_lines.append(f"    Documentation: {rec.recipe_doc}")
                out_lines.append(f"    Installation:  {rec.install_command}")
                out_lines.append(f"    Guidance:      {rec.description}")
                out_lines.append("    Canonical Imports:")
                for imp in rec.canonical_imports:
                    out_lines.append(f"      {imp}")
                out_lines.append(f"    To generate boilerplate: llmfirewall integrate scaffold --recipe {rec.recipe_name}")

            out_lines.append("=" * 70)
            _emit_output("\n".join(out_lines), output_file)
            return EXIT_ALLOWED

        # ACTION 2: SCAFFOLD
        elif action in ("scaffold", "recipe", "template"):
            if not recipe:
                recipes_list = ", ".join(list_supported_recipes())
                if is_json:
                    _emit_output(json.dumps({"error": "missing_recipe", "supported_recipes": list_supported_recipes()}), output_file)
                else:
                    print(f"Error: --recipe required for scaffolding. Available recipes: {recipes_list}")
                return EXIT_USAGE_ERROR

            scaffold_res = generate_scaffold(
                recipe_name=recipe,
                app_output=write_app,
                test_output=write_test,
                force=force,
            )

            if is_json:
                data = scaffold_res.to_dict()
                data["app_code"] = scaffold_res.app_code
                data["test_code"] = scaffold_res.test_code
                _emit_output(json.dumps(data, indent=2), output_file)
                return EXIT_ALLOWED

            out_lines.append("=" * 70)
            out_lines.append(f"LLMFirewall Scaffolding: Recipe '{recipe}'")
            out_lines.append("=" * 70)

            if write_app:
                out_lines.append(f"✓ Application boilerplate written to: {scaffold_res.app_path}")
            if write_test:
                out_lines.append(f"✓ Verification test suite written to: {scaffold_res.test_path}")

            if not write_app and not write_test:
                out_lines.append("\n--- Application Boilerplate ---")
                out_lines.append(scaffold_res.app_code)
                out_lines.append("\n--- Verification Test Suite ---")
                out_lines.append(scaffold_res.test_code)
                out_lines.append("\nTo write these files automatically, run:")
                out_lines.append(f"  llmfirewall integrate scaffold --recipe {recipe} --write-app app.py --write-test test_app.py")

            out_lines.append("=" * 70)
            _emit_output("\n".join(out_lines), output_file)
            return EXIT_ALLOWED

        # ACTION 3: VALIDATE
        elif action == "validate":
            report = validate_integration(target_path=target_path, policy_file=policy_file)

            if is_json:
                _emit_output(json.dumps(report.to_dict(), indent=2), output_file)
                return EXIT_ALLOWED if report.passed else EXIT_BLOCKED

            out_lines.append("=" * 70)
            out_lines.append(f"LLMFirewall Integration Validation Report (v{report.version})")
            out_lines.append("=" * 70)
            out_lines.append(f"Target Path: {report.target_path}")
            out_lines.append(f"Overall Status: {'PASSED' if report.passed else 'FAILED'}")
            out_lines.append(f"Summary: {report.pass_count} passed, {report.fail_count} failed, {report.warn_count} warnings ({report.total_checks} total)\n")

            for chk in report.checks:
                badge = f"[{chk.status}]"
                out_lines.append(f"{badge:<8} {chk.name}: {chk.message}")
                if chk.details:
                    out_lines.append(f"         Details: {chk.details}")
                if chk.action_item:
                    out_lines.append(f"         Action:  {chk.action_item}")

            out_lines.append("=" * 70)
            if not report.passed:
                out_lines.append("Action Required: Resolve the FAILED items above before deploying.")
            else:
                out_lines.append("All core security invariants and active enforcement checks passed successfully.")
            out_lines.append("=" * 70)

            _emit_output("\n".join(out_lines), output_file)
            return EXIT_ALLOWED if report.passed else EXIT_BLOCKED

        # ACTION 4: LIST
        elif action == "list":
            recipes = list_supported_recipes()
            if is_json:
                _emit_output(json.dumps({"recipes": recipes}), output_file)
            else:
                print("Available LLMFirewall verified recipes:")
                for r in recipes:
                    print(f"  - {r}")
            return EXIT_ALLOWED

        else:
            print(f"Unknown action '{action}'. Choose from: detect, scaffold, validate, list.")
            return EXIT_USAGE_ERROR

    except Exception as exc:
        if is_json:
            _emit_output(json.dumps({"error": str(exc), "status": "error"}), output_file)
        else:
            print(f"Error executing integrate command: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def _emit_output(text: str, output_file: Optional[str] = None) -> None:
    if output_file:
        p = Path(output_file).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    else:
        print(text)
