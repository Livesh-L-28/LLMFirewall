"""Comprehensive tests for LLMFirewall Developer Experience & Scaffolding Engine."""

import json
from pathlib import Path
import pytest

from llmfirewall.cli.errors import EXIT_ALLOWED, EXIT_BLOCKED, EXIT_USAGE_ERROR
from llmfirewall.cli.main import main
from llmfirewall.developer.detector import detect_project_frameworks
from llmfirewall.developer.templates import generate_scaffold, list_supported_recipes
from llmfirewall.developer.validator import validate_integration


class TestFrameworkDetection:
    """Tests for framework detection and trust boundary identification."""

    def test_detect_fastapi_sample_app(self):
        report = detect_project_frameworks("examples/sample_apps/fastapi_secure_service")
        assert "fastapi" in report.detected_frameworks
        assert any(r.recipe_name == "fastapi" for r in report.recommendations)
        assert len(report.trust_boundaries) > 0
        boundary = report.trust_boundaries[0]
        assert boundary.boundary_type == "input"
        assert "@app.post" in boundary.snippet

    def test_detect_asgi_sample_app(self):
        report = detect_project_frameworks("examples/sample_apps/asgi_secure_gateway")
        assert any(r.recipe_name in ("asgi", "fastapi") for r in report.recommendations)

    def test_detect_streaming_sample_app(self):
        report = detect_project_frameworks("examples/sample_apps/streaming_guard_service")
        assert "streaming" in report.detected_frameworks
        assert any(r.recipe_name == "streaming" for r in report.recommendations)

    def test_detect_tools_sample_app(self):
        report = detect_project_frameworks("examples/sample_apps/agent_tool_sandbox")
        assert "tools" in report.detected_frameworks
        assert any(r.recipe_name == "tools" for r in report.recommendations)

    def test_detect_rag_sample_app(self):
        report = detect_project_frameworks("examples/sample_apps/rag_context_guard")
        assert any(r.recipe_name in ("rag", "asgi") for r in report.recommendations)

    def test_detection_to_dict_serializable(self):
        report = detect_project_frameworks("examples/sample_apps/fastapi_secure_service")
        d = report.to_dict()
        assert isinstance(d, dict)
        serialized = json.dumps(d)
        assert "fastapi" in serialized


class TestScaffoldingGeneration:
    """Tests for verified recipe code generation and safe file writing."""

    def test_list_supported_recipes(self):
        recipes = list_supported_recipes()
        assert "fastapi" in recipes
        assert "asgi" in recipes
        assert "streaming" in recipes
        assert "tools" in recipes
        assert "rag" in recipes

    def test_generate_scaffold_memory(self):
        res = generate_scaffold("fastapi")
        assert "FirewallMiddleware" in res.app_code
        assert "test_benign_prompt_allowed" in res.test_code
        assert res.recipe_name == "fastapi"

    def test_generate_scaffold_unknown_raises(self):
        with pytest.raises(ValueError) as exc:
            generate_scaffold("unknown_nonexistent_framework")
        assert "Unknown recipe" in str(exc.value)

    def test_generate_scaffold_file_writing_protection(self, tmp_path):
        app_file = tmp_path / "app.py"
        test_file = tmp_path / "test_app.py"

        # 1. First write succeeds
        generate_scaffold("asgi", app_output=str(app_file), test_output=str(test_file))
        assert app_file.exists()
        assert test_file.exists()

        # 2. Second write without force raises FileExistsError to prevent accidental overwrite
        with pytest.raises(FileExistsError):
            generate_scaffold("asgi", app_output=str(app_file), force=False)

        # 3. Write with force=True succeeds
        generate_scaffold("streaming", app_output=str(app_file), force=True)
        assert "StreamingTextGuard" in app_file.read_text(encoding="utf-8")


class TestIntegrationValidator:
    """Tests for integration validation and active enforcement health checks."""

    def test_validator_active_enforcement_pass(self):
        report = validate_integration()
        assert report.passed is True
        assert report.fail_count == 0
        assert report.pass_count >= 7

        check_names = {c.name for c in report.checks}
        assert "core_public_apis" in check_names
        assert "enforcement_benign_allow" in check_names
        assert "enforcement_injection_block" in check_names
        assert "enforcement_pii_redaction" in check_names
        assert "enforcement_tool_ssrf_block" in check_names
        assert "enforcement_safe_logging" in check_names

    def test_validator_to_dict_serializable(self):
        report = validate_integration()
        d = report.to_dict()
        assert d["passed"] is True
        assert json.dumps(d)


class TestCLIDeveloperCommands:
    """Functional tests for the `llmfirewall integrate` CLI command."""

    def test_cli_integrate_detect_human(self, capsys):
        code = main(["integrate", "detect", "--path", "examples/sample_apps/fastapi_secure_service"])
        assert code == EXIT_ALLOWED
        captured = capsys.readouterr()
        assert "Framework & Trust Boundary Detection" in captured.out
        assert "FastAPI" in captured.out

    def test_cli_integrate_detect_json(self, capsys):
        code = main(["integrate", "detect", "--path", "examples/sample_apps/fastapi_secure_service", "--json"])
        assert code == EXIT_ALLOWED
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "fastapi" in data["detected_frameworks"]

    def test_cli_integrate_scaffold_stdout(self, capsys):
        code = main(["integrate", "scaffold", "--recipe", "tools"])
        assert code == EXIT_ALLOWED
        captured = capsys.readouterr()
        assert "LLMFirewall Scaffolding: Recipe 'tools'" in captured.out
        assert "protect_tool" in captured.out

    def test_cli_integrate_scaffold_missing_recipe(self, capsys):
        code = main(["integrate", "scaffold"])
        assert code == EXIT_USAGE_ERROR

    def test_cli_integrate_validate_human(self, capsys):
        code = main(["integrate", "validate"])
        assert code == EXIT_ALLOWED
        captured = capsys.readouterr()
        assert "Validation Report" in captured.out
        assert "PASSED" in captured.out

    def test_cli_integrate_validate_json(self, capsys):
        code = main(["integrate", "validate", "--json"])
        assert code == EXIT_ALLOWED
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["passed"] is True
        assert data["fail_count"] == 0

    def test_cli_integrate_list(self, capsys):
        code = main(["integrate", "list"])
        assert code == EXIT_ALLOWED
        captured = capsys.readouterr()
        assert "fastapi" in captured.out
        assert "asgi" in captured.out
