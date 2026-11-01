"""Regression test suite for Phase 10.2: Targeted Security Remediation.

Verifies fixes for:
- VULN-01: Dotted-octal and alternative legacy IPv4 SSRF bypasses.
- VULN-02: Case-insensitive sensitive filesystem paths.
- VULN-03: Windows UNC network path injection and NTLM leak prevention.
- VULN-04: Async tool decorator post-execution inspection and coroutine handling.
"""

import asyncio
import inspect
from unittest.mock import MagicMock

import pytest

from llmfirewall import Firewall, SecurityBlockError
from llmfirewall.core.models import ThreatType
from llmfirewall.protection.sdk import protect_tool
from llmfirewall.tools.path_security import is_unc_path, validate_path_safety
from llmfirewall.tools.url_security import (
    _parse_legacy_ipv4,
    is_private_or_restricted_ip,
    validate_url_safety,
)


class TestVuln01DottedOctalIpv4Ssrf:
    """VULN-01: Alternative and dotted-octal IPv4 SSRF bypass tests."""

    def test_parse_legacy_ipv4_formats(self):
        # Dotted octal 127.0.0.1
        assert str(_parse_legacy_ipv4("0177.0.0.1")) == "127.0.0.1"
        assert str(_parse_legacy_ipv4("0177.0.0.01")) == "127.0.0.1"
        # Dotted pair
        assert str(_parse_legacy_ipv4("0177.1")) == "127.0.0.1"
        assert str(_parse_legacy_ipv4("0x7f.1")) == "127.0.0.1"
        assert str(_parse_legacy_ipv4("127.1")) == "127.0.0.1"
        # Dotted tri
        assert str(_parse_legacy_ipv4("127.0.1")) == "127.0.0.1"
        assert str(_parse_legacy_ipv4("0177.0.1")) == "127.0.0.1"
        # Single dword integer
        assert str(_parse_legacy_ipv4("2130706433")) == "127.0.0.1"
        assert str(_parse_legacy_ipv4("0x7f000001")) == "127.0.0.1"
        # Octal 10-net
        assert str(_parse_legacy_ipv4("012.0.0.1")) == "10.0.0.1"
        # Non-IP hostnames return None
        assert _parse_legacy_ipv4("example.com") is None
        assert _parse_legacy_ipv4("localhost") is None
        assert _parse_legacy_ipv4("127.0.0.1.nip.io") is None
        assert _parse_legacy_ipv4("::1") is None

    def test_is_private_or_restricted_ip_alternative_formats(self):
        assert is_private_or_restricted_ip("0177.0.0.1") is True
        assert is_private_or_restricted_ip("0177.1") is True
        assert is_private_or_restricted_ip("0x7f.1") is True
        assert is_private_or_restricted_ip("2130706433") is True
        assert is_private_or_restricted_ip("0x7f000001") is True
        assert is_private_or_restricted_ip("012.0.0.1") is True
        # Public IP should not be marked restricted
        assert is_private_or_restricted_ip("8.8.8.8") is False
        assert is_private_or_restricted_ip("93.184.216.34") is False

    def test_validate_url_safety_blocks_encoded_ipv4_ssrf(self):
        evasion_urls = [
            "http://0177.0.0.1/",
            "http://0177.0.0.01/",
            "http://0177.1/admin",
            "http://0x7f.1/internal",
            "http://127.0.1/status",
            "http://2130706433/secrets",
            "http://0x7f000001/",
            "http://012.0.0.1/config",
        ]
        for url in evasion_urls:
            finding = validate_url_safety(url)
            assert finding is not None, f"Failed to detect SSRF for {url}"
            assert finding.threat_type == ThreatType.MALICIOUS_URL
            assert finding.metadata.get("violation") == "ssrf_encoded_ip"

    def test_standard_ip_literals_preserve_violation_metadata(self):
        standard_urls = [
            "http://127.0.0.1/",
            "http://10.0.0.1/api",
            "http://192.168.1.1/setup",
        ]
        for url in standard_urls:
            finding = validate_url_safety(url)
            assert finding is not None
            assert finding.metadata.get("violation") == "ssrf_restricted_ip"


class TestVuln02CaseInsensitivePaths:
    """VULN-02: Case-insensitive sensitive filesystem paths tests."""

    def test_uppercase_and_mixed_case_sensitive_paths_blocked(self):
        evasion_paths = [
            "/ETC/PASSWD",
            "/etc/SHADOW",
            "/Etc/Sudoers",
            "/ROOT/.SSH/authorized_keys",
            "/Proc/cpuinfo",
            "/Sys/kernel",
            "/Var/log/syslog",
            "C:\\Windows\\System32\\config\\sam",
            "c:\\windows\\system32\\config\\sam",
            "C:\\WINDOWS\\SYSTEM32\\DRIVERS\\ETC\\HOSTS",
        ]
        for path in evasion_paths:
            finding = validate_path_safety(path)
            assert finding is not None, f"Failed to detect sensitive path for {path}"
            assert finding.threat_type == ThreatType.POLICY_VIOLATION
            assert finding.metadata.get("violation") == "sensitive_system_path"

    def test_benign_paths_remain_allowed(self):
        safe_paths = [
            "./data/reports.csv",
            "subfolder/file.json",
            "documents/readme.txt",
        ]
        for path in safe_paths:
            assert validate_path_safety(path) is None


class TestVuln03WindowsUncPaths:
    """VULN-03: Windows UNC network path tests."""

    def test_is_unc_path_detection(self):
        assert is_unc_path("\\\\192.168.1.1\\share\\secret.txt") is True
        assert is_unc_path("//192.168.1.1/share/file.txt") is True
        assert is_unc_path("\\\\attacker.com\\share") is True
        assert is_unc_path("\\\\?\\UNC\\server\\share\\data") is True
        assert is_unc_path("\\??\\UNC\\server\\share\\data") is True
        assert is_unc_path("\\\\?\\C:\\Windows\\System32") is True
        assert is_unc_path("\\\\.\\pipe\\named_pipe") is True

        assert is_unc_path("/etc/passwd") is False
        assert is_unc_path("./relative/path.txt") is False
        assert is_unc_path("relative/path.txt") is False
        assert is_unc_path("C:\\Windows\\System32") is False

    def test_validate_path_safety_blocks_unc_paths(self):
        unc_paths = [
            "\\\\192.168.1.1\\share\\secret.txt",
            "//192.168.1.1/share/file.txt",
            "\\\\attacker.corp.internal\\secrets",
            "\\\\?\\UNC\\10.0.0.1\\c$\\data.txt",
        ]
        for path in unc_paths:
            finding = validate_path_safety(path)
            assert finding is not None, f"Failed to block UNC path: {path}"
            assert finding.threat_type == ThreatType.POLICY_VIOLATION
            assert finding.metadata.get("violation") == "unc_path_forbidden"

    def test_allow_unc_flag(self):
        unc_path = "\\\\192.168.1.1\\share\\secret.txt"
        finding = validate_path_safety(unc_path, allow_unc=True)
        # Should not be blocked for unc_path_forbidden when allow_unc is True
        if finding is not None:
            assert finding.metadata.get("violation") != "unc_path_forbidden"


class TestVuln04AsyncToolDecorator:
    """VULN-04: Async tool decorator inspection tests."""

    def test_async_function_detection(self):
        fw = Firewall()

        @fw.protect_tool(tool_name="async_op")
        async def sample_coro(val: str) -> str:
            return f"Processed {val}"

        assert inspect.iscoroutinefunction(sample_coro) is True

    @pytest.mark.asyncio
    async def test_async_tool_pre_execution_blocking(self):
        fw = Firewall()

        @fw.protect_tool(tool_name="http_fetch")
        async def fetch_async(url: str) -> str:
            await asyncio.sleep(0.001)
            return f"Got {url}"

        # Benign call succeeds
        result = await fetch_async(url="https://api.github.com/repos")
        assert result == "Got https://api.github.com/repos"

        # SSRF call blocked pre-execution with SecurityBlockError
        with pytest.raises(SecurityBlockError) as exc_info:
            await fetch_async(url="http://0177.0.0.1/")
        assert "block" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_async_tool_raise_on_block_false(self):
        fw = Firewall()

        @fw.protect_tool(tool_name="http_fetch", raise_on_block=False)
        async def fetch_async_no_raise(url: str) -> str:
            await asyncio.sleep(0.001)
            return f"Got {url}"

        err = await fetch_async_no_raise(url="http://169.254.169.254/latest/meta-data")
        assert isinstance(err, dict)
        assert err.get("status") == "error"
        assert "block" in err.get("error", "").lower()

    @pytest.mark.asyncio
    async def test_async_tool_cross_step_post_execution_scan(self):
        mock_fw = MagicMock()
        mock_enforcer = MagicMock()
        mock_fw.cross_step_enforcer = mock_enforcer

        @protect_tool(mock_fw, tool_name="db_query", workflow_id="wf-test", tenant_id="tenant-xyz")
        async def async_db(query: str) -> str:
            await asyncio.sleep(0.001)
            return f"Data for {query}"

        res = await async_db(query="SELECT * FROM users")
        assert res == "Data for SELECT * FROM users"

        # Verify pre-execution enforcement called
        assert mock_enforcer.enforce_tool_call.called is True
        assert mock_enforcer.enforce_tool_call.call_args[1]["workflow_id"] == "wf-test"
        assert mock_enforcer.enforce_tool_call.call_args[1]["tenant_id"] == "tenant-xyz"

        # Verify post-execution enforcement scanned the awaited output
        assert mock_enforcer.enforce_tool_result.called is True
        assert mock_enforcer.enforce_tool_result.call_args[1]["output"] == "Data for SELECT * FROM users"
        assert mock_enforcer.enforce_tool_result.call_args[1]["workflow_id"] == "wf-test"

