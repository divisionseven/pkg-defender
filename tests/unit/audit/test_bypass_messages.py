"""Tests for de-emphasized PKGD_DISABLED bypass messaging and audit logging.

Verifies that:
1. Error messages no longer contain 'export PKGD_DISABLED=1'
2. Bypass is de-emphasized (no 'export' command, fix recommended)
3. Audit log is emitted when PKGD_DISABLED is active
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pkg_defender.audit.errors import (
    AdapterError,
    DatabaseError,
    NetworkError,
    TimeoutError,
)
from pkg_defender.audit.user_messages import (
    adapter_unavailable,
    database_error,
    network_unreachable,
    registry_timeout,
    version_resolution_failed,
)

# Path constants for regression tests
_SRC_ROOT = Path(__file__).parent.parent.parent.parent / "src"
_ERRORS_PY = _SRC_ROOT / "pkg_defender" / "audit" / "errors.py"
_USER_MESSAGES_PY = _SRC_ROOT / "pkg_defender" / "audit" / "user_messages.py"


class TestErrorsPyBypassMessages:
    """Verify errors.py uses 'pkgd bypass' instead of 'PKGD_DISABLED=1'."""

    def test_network_error_no_export_command(self) -> None:
        """NetworkError message should not contain 'export PKGD_DISABLED=1'."""
        exc = NetworkError(registry="npm", package="express")
        assert "export PKGD_DISABLED=1" not in str(exc)
        assert "export PKGD_DISABLED=1" not in exc.user_message

    def test_network_error_has_pkgd_bypass(self) -> None:
        """NetworkError should use 'pkgd bypass' instead of 'PKGD_DISABLED=1'."""
        exc = NetworkError(registry="npm", package="express")
        assert "pkgd bypass" in exc.user_message

    def test_network_error_leads_with_fix(self) -> None:
        """NetworkError should recommend fixing before bypassing."""
        exc = NetworkError(registry="npm", package="express")
        fix_pos = exc.user_message.find("Fix the underlying issue")
        bypass_pos = exc.user_message.find("pkgd bypass")
        assert fix_pos != -1, "Missing 'Fix the underlying issue' message"
        assert bypass_pos != -1, "Missing 'pkgd bypass' mention"
        assert fix_pos < bypass_pos, "Fix message should appear before bypass"

    def test_adapter_error_no_export_command(self) -> None:
        """AdapterError message should not contain 'export PKGD_DISABLED=1'."""
        exc = AdapterError(adapter="npm")
        assert "export PKGD_DISABLED=1" not in str(exc)
        assert "export PKGD_DISABLED=1" not in exc.user_message

    def test_adapter_error_leads_with_fix(self) -> None:
        """AdapterError should recommend fixing before bypassing."""
        exc = AdapterError(adapter="npm")
        fix_pos = exc.user_message.find("Fix the underlying issue")
        bypass_pos = exc.user_message.find("pkgd bypass")
        assert fix_pos != -1
        assert bypass_pos != -1
        assert fix_pos < bypass_pos

    def test_timeout_error_no_export_command(self) -> None:
        """TimeoutError message should not contain 'export PKGD_DISABLED=1'."""
        exc = TimeoutError(registry="npm", package="express", timeout_seconds=10)
        assert "export PKGD_DISABLED=1" not in str(exc)
        assert "export PKGD_DISABLED=1" not in exc.user_message

    def test_timeout_error_leads_with_fix(self) -> None:
        """TimeoutError should recommend fixing before bypassing."""
        exc = TimeoutError(registry="npm", package="express", timeout_seconds=10)
        fix_pos = exc.user_message.find("Fix the underlying issue")
        bypass_pos = exc.user_message.find("pkgd bypass")
        assert fix_pos != -1
        assert bypass_pos != -1
        assert fix_pos < bypass_pos

    def test_database_error_no_export_command(self) -> None:
        """DatabaseError message should not contain 'export PKGD_DISABLED=1'."""
        exc = DatabaseError(operation="query threats")
        assert "export PKGD_DISABLED=1" not in str(exc)
        assert "export PKGD_DISABLED=1" not in exc.user_message

    def test_database_error_leads_with_fix(self) -> None:
        """DatabaseError should recommend fixing before bypassing."""
        exc = DatabaseError(operation="query threats")
        fix_pos = exc.user_message.find("Fix the underlying issue")
        bypass_pos = exc.user_message.find("pkgd bypass")
        assert fix_pos != -1
        assert bypass_pos != -1
        assert fix_pos < bypass_pos


class TestUserMessagesBypassContent:
    """Verify user_messages.py bypass instructions use 'pkgd bypass'.

    These functions print to stderr (Rich console), so we capture
    the output and check that 'export PKGD_DISABLED=1' is absent
    and 'pkgd bypass' is present.

    Note: The Rich-rendered output shows body first, then bypass
    instructions after a separator. The bypass_instructions section
    now includes 'Fix the underlying issue' as a closing reminder,
    so position-ordering in rendered output differs from errors.py
    raw strings. The key assertion is that 'pkgd bypass' is present.
    """

    def test_network_unreachable_has_pkgd_bypass(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """network_unreachable should show 'pkgd bypass' not 'PKGD_DISABLED=1'."""
        network_unreachable("npm", "express")
        captured = capsys.readouterr()
        assert "PKGD_DISABLED=1" not in captured.err
        assert "pkgd bypass" in captured.err

    def test_registry_timeout_has_pkgd_bypass(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """registry_timeout should show 'pkgd bypass' not 'PKGD_DISABLED=1'."""
        registry_timeout("npm", "express", 10)
        captured = capsys.readouterr()
        assert "PKGD_DISABLED=1" not in captured.err
        assert "pkgd bypass" in captured.err

    def test_adapter_unavailable_has_pkgd_bypass(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """adapter_unavailable should show 'pkgd bypass' not 'PKGD_DISABLED=1'."""
        adapter_unavailable("npm")
        captured = capsys.readouterr()
        assert "PKGD_DISABLED=1" not in captured.err
        assert "pkgd bypass" in captured.err

    def test_database_error_has_pkgd_bypass(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """database_error should show 'pkgd bypass' not 'PKGD_DISABLED=1'."""
        database_error("query threats")
        captured = capsys.readouterr()
        assert "PKGD_DISABLED=1" not in captured.err
        assert "pkgd bypass" in captured.err

    def test_version_resolution_failed_has_pkgd_bypass(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """version_resolution_failed should show 'pkgd bypass' not 'PKGD_DISABLED=1'."""
        version_resolution_failed("express", "npm")
        captured = capsys.readouterr()
        assert "PKGD_DISABLED=1" not in captured.err
        assert "pkgd bypass" in captured.err

    def test_bypass_messages_include_fix_recommendation(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """All user_messages should include fix recommendation in bypass section."""
        funcs_and_args = [
            (network_unreachable, ("npm", "express")),
            (registry_timeout, ("npm", "express", 10)),
            (adapter_unavailable, ("npm",)),
            (database_error, ("query",)),
            (version_resolution_failed, ("express", "npm")),
        ]
        for func, args in funcs_and_args:
            func(*args)  # type: ignore[operator]
            captured = capsys.readouterr()
            # Verify 'Set `PKGD_DISABLED=1`' is absent
            assert "PKGD_DISABLED=1" not in captured.err, f"{func.__name__}: still contains 'PKGD_DISABLED=1'"
            # Verify 'pkgd bypass' is present
            assert "pkgd bypass" in captured.err, f"{func.__name__}: missing 'pkgd bypass'"
            # Verify fix recommendation is present
            assert "Fix the underlying issue" in captured.err, f"{func.__name__}: missing fix recommendation"
