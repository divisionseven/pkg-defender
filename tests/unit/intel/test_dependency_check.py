"""Tests for the dependency check module."""

from __future__ import annotations

import subprocess
from unittest.mock import Mock, patch

from pkg_defender.cli import _dependency_check


class TestGetToolVersion:
    """Test tool version detection."""

    def test_get_tool_version_python_returns_version(self) -> None:
        """Python version should be detected."""
        result = _dependency_check.get_tool_version("python")
        # Should return major.minor version
        assert result is not None
        assert "." in result

    def test_get_tool_version_invalid_tool_returns_none(self) -> None:
        """Non-existent tool should return None."""
        result = _dependency_check.get_tool_version("nonexistent-tool-xyz")
        assert result is None


class TestVersionLt:
    """Test version comparison."""

    def test_version_lt_less_than(self) -> None:
        """v1 < v2 should return True."""
        assert _dependency_check._version_lt("3.9", "3.10") is True
        assert _dependency_check._version_lt("3.9", "3.9.1") is True

    def test_version_lt_greater_than(self) -> None:
        """v1 > v2 should return False."""
        assert _dependency_check._version_lt("3.11", "3.10") is False
        assert _dependency_check._version_lt("3.10", "3.9") is False

    def test_version_lt_equal(self) -> None:
        """v1 == v2 should return False."""
        assert _dependency_check._version_lt("3.10", "3.10") is False

    def test_version_lt_different_major(self) -> None:
        """Different major versions should compare correctly."""
        assert _dependency_check._version_lt("2.10", "3.10") is True
        assert _dependency_check._version_lt("3.10", "2.10") is False


class TestCheckOutdatedTools:
    """Test outdated tools checking."""

    def test_check_outdated_tools_returns_list(self) -> None:
        """Should return a list of warnings."""
        result = _dependency_check.check_outdated_tools()
        assert isinstance(result, list)

    def test_check_outdated_tools_contains_dicts(self) -> None:
        """List items should be dicts with required keys."""
        result = _dependency_check.check_outdated_tools()
        for item in result:
            assert isinstance(item, dict)
            assert "tool" in item
            assert "installed" in item
            assert "minimum" in item


class TestParseVersion:
    """Test version parsing from command output."""

    def test_parse_version_standard_format(self) -> None:
        """Standard version format should be parsed."""
        assert _dependency_check._parse_version("python 3.10.12") == "3.10.12"
        assert _dependency_check._parse_version("v3.9.1") == "3.9.1"

    def test_parse_version_no_match(self) -> None:
        """No version in output should return None."""
        assert _dependency_check._parse_version("no version here") is None

    def test_parse_version_with_prefix(self) -> None:
        """Version with prefix should be parsed."""
        result = _dependency_check._parse_version("npm version 8.0.0")
        assert result is not None
        assert "8.0" in result


class TestGetToolVersionSubprocessPath:
    """Tests for the subprocess-based version detection path in get_tool_version."""

    def test_get_tool_version_returns_parsed_version_on_success(self) -> None:
        """Mock subprocess success with version in stdout."""
        with (
            patch("pkg_defender.cli._dependency_check.shutil.which", return_value="/usr/bin/pip"),
            patch("pkg_defender.cli._dependency_check.subprocess.run") as mock_run,
        ):
            mock_run.return_value = Mock(returncode=0, stdout="pip 22.0.0 from ...", stderr="")
            result = _dependency_check.get_tool_version("pip")
            assert result == "22.0.0"

    def test_get_tool_version_returns_version_from_stderr_when_stdout_empty(self) -> None:
        """Version in stderr when stdout is empty."""
        with (
            patch("pkg_defender.cli._dependency_check.shutil.which", return_value="/usr/bin/npm"),
            patch("pkg_defender.cli._dependency_check.subprocess.run") as mock_run,
        ):
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="8.5.0")
            result = _dependency_check.get_tool_version("npm")
            assert result == "8.5.0"

    def test_get_tool_version_tries_multiple_flags(self) -> None:
        """Fallback to subsequent flags when first fails."""
        with (
            patch("pkg_defender.cli._dependency_check.shutil.which", return_value="/usr/bin/tool"),
            patch("pkg_defender.cli._dependency_check.subprocess.run") as mock_run,
        ):
            mock_run.side_effect = [
                Mock(returncode=1, stdout="", stderr=""),
                Mock(returncode=0, stdout="tool 3.0.0", stderr=""),
            ]
            result = _dependency_check.get_tool_version("tool")
            assert result == "3.0.0"

    def test_get_tool_version_returns_none_when_all_flags_fail(self) -> None:
        """All version flags return non-zero exit codes."""
        with (
            patch("pkg_defender.cli._dependency_check.shutil.which", return_value="/usr/bin/tool"),
            patch("pkg_defender.cli._dependency_check.subprocess.run") as mock_run,
        ):
            mock_run.return_value = Mock(returncode=1, stdout="", stderr="")
            result = _dependency_check.get_tool_version("tool")
            assert result is None

    def test_get_tool_version_returns_none_on_file_not_found(self) -> None:
        """FileNotFoundError should return None immediately."""
        with (
            patch("pkg_defender.cli._dependency_check.shutil.which", return_value="/usr/bin/tool"),
            patch("pkg_defender.cli._dependency_check.subprocess.run") as mock_run,
        ):
            mock_run.side_effect = FileNotFoundError()
            result = _dependency_check.get_tool_version("tool")
            assert result is None

    def test_get_tool_version_continues_on_timeout(self) -> None:
        """TimeoutExpired on first flag continues to next flag."""
        with (
            patch("pkg_defender.cli._dependency_check.shutil.which", return_value="/usr/bin/tool"),
            patch("pkg_defender.cli._dependency_check.subprocess.run") as mock_run,
        ):
            mock_run.side_effect = [
                subprocess.TimeoutExpired(cmd="tool", timeout=5),
                Mock(returncode=0, stdout="tool 1.0.0", stderr=""),
            ]
            result = _dependency_check.get_tool_version("tool")
            assert result == "1.0.0"

    def test_get_tool_version_continues_on_os_error(self) -> None:
        """OSError on first flag continues to next flag."""
        with (
            patch("pkg_defender.cli._dependency_check.shutil.which", return_value="/usr/bin/tool"),
            patch("pkg_defender.cli._dependency_check.subprocess.run") as mock_run,
        ):
            mock_run.side_effect = [
                OSError(),
                Mock(returncode=0, stdout="tool 1.0.0", stderr=""),
            ]
            result = _dependency_check.get_tool_version("tool")
            assert result == "1.0.0"

    def test_get_tool_version_continues_on_value_error(self) -> None:
        """ValueError on first flag continues to next flag."""
        with (
            patch("pkg_defender.cli._dependency_check.shutil.which", return_value="/usr/bin/tool"),
            patch("pkg_defender.cli._dependency_check.subprocess.run") as mock_run,
        ):
            mock_run.side_effect = [
                ValueError(),
                Mock(returncode=0, stdout="tool 1.0.0", stderr=""),
            ]
            result = _dependency_check.get_tool_version("tool")
            assert result == "1.0.0"


class TestCheckOutdatedToolsMocked:
    """Test check_outdated_tools with mocked get_tool_version."""

    def test_check_outdated_tools_reports_outdated_pip(self) -> None:
        """Pip below minimum version should be reported."""
        with patch.object(_dependency_check, "get_tool_version") as mock_get:
            mock_get.side_effect = lambda tool: {"pip": "20.0", "npm": "999.0", "python": "999.0"}.get(tool)
            result = _dependency_check.check_outdated_tools()
            assert len(result) == 1
            assert result[0] == {"tool": "pip", "installed": "20.0", "minimum": "21.0"}

    def test_check_outdated_tools_returns_empty_when_all_tools_uptodate(self) -> None:
        """All tools at or above minimum should return empty list."""
        with patch.object(_dependency_check, "get_tool_version", return_value="999.0"):
            result = _dependency_check.check_outdated_tools()
            assert result == []
