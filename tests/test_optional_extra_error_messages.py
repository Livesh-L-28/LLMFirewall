"""Regression tests for optional extra dependency error messages (OBS-REL-02).

Verifies that all framework integration failure messages cite the correct distribution name:
`llmfirewall-core[<extra>]` matching available extras defined in pyproject.toml.
"""

from __future__ import annotations

import unittest.mock as mock
import pytest


def test_django_missing_dependency_error_message():
    """Verify Django integration error message recommends llmfirewall-core[django]."""
    from llmfirewall.integrations import django as django_integration

    with mock.patch.object(django_integration, "HAS_DJANGO", False):
        with pytest.raises(ImportError) as exc_info:
            django_integration.FirewallMiddleware(get_response=lambda req: None)
        assert "pip install 'llmfirewall-core[django]'" in str(exc_info.value)


def test_flask_missing_dependency_error_message():
    """Verify Flask integration error message recommends llmfirewall-core[flask]."""
    from llmfirewall.integrations import flask as flask_integration

    with mock.patch.object(flask_integration, "HAS_FLASK", False):
        with pytest.raises(ImportError) as exc_info:
            flask_integration.FirewallExtension()
        assert "pip install 'llmfirewall-core[flask]'" in str(exc_info.value)


def test_llamaindex_missing_dependency_error_message():
    """Verify LlamaIndex integration error message recommends llmfirewall-core[llamaindex]."""
    from llmfirewall.integrations import llamaindex as llamaindex_integration

    with mock.patch.object(llamaindex_integration, "HAS_LLAMAINDEX", False):
        with pytest.raises(ImportError) as exc_info:
            llamaindex_integration.FirewallNodePostprocessor()
        assert "pip install 'llmfirewall-core[llamaindex]'" in str(exc_info.value)


def test_langchain_missing_dependency_error_message():
    """Verify LangChain integration error message recommends llmfirewall-core[langchain]."""
    from llmfirewall.integrations import langchain as langchain_integration

    with mock.patch.object(langchain_integration, "HAS_LANGCHAIN", False):
        with pytest.raises(ImportError) as exc_info:
            langchain_integration.LLMFirewallCallbackHandler()
        assert "pip install 'llmfirewall-core[langchain]'" in str(exc_info.value)


def test_fastapi_missing_dependency_error_message():
    """Verify FastAPI integration module error message recommends llmfirewall-core[fastapi]."""
    import builtins
    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name in ("fastapi", "starlette"):
            raise ImportError(f"No module named '{name}'")
        return real_import(name, *args, **kwargs)

    # When imported with simulated missing fastapi
    import sys
    sys_modules_backup = {k: v for k, v in sys.modules.items() if k.startswith("llmfirewall.integrations.fastapi")}
    for k in sys_modules_backup:
        del sys.modules[k]

    try:
        with mock.patch("builtins.__import__", side_effect=mock_import):
            with pytest.raises(ImportError) as exc_info:
                import importlib
                importlib.import_module("llmfirewall.integrations.fastapi")
            assert "pip install 'llmfirewall-core[fastapi]'" in str(exc_info.value)
    finally:
        sys.modules.update(sys_modules_backup)

