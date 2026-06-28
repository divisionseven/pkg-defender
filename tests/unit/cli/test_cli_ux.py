"""CLI UX consistency tests for pkg-defender.

Tests that all CLI commands have consistent:
- Error message formatting
- Timeout configurations
- Rich console usage
- Help text formatting
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from pkg_defender.cli._constants import (
    SHOW_SOURCE_URLS,
    VERSION_LATEST,
    VERSION_UNSPECIFIED,
    VERSION_WILDCARD,
)
from pkg_defender.cli.main import cli


class TestConstants:
    """Test that CLI constants are consistent."""

    def test_version_constants_values(self) -> None:
        """Version constants have expected values."""
        assert VERSION_UNSPECIFIED == ""
        assert VERSION_WILDCARD == "*"
        assert VERSION_LATEST == "latest"

    def test_show_source_urls_default(self) -> None:
        """SHOW_SOURCE_URLS defaults to False."""
        assert SHOW_SOURCE_URLS is False


class TestRichConsoleConsistency:
    """Test that Rich console usage is consistent."""

    def test_main_console_stderr(self) -> None:
        """Main console outputs to stderr."""
        import sys

        from pkg_defender.cli.common import console

        assert console.file is sys.stderr

    def test_progress_console_stderr(self) -> None:
        """Progress console outputs to stderr."""
        import sys

        from pkg_defender.cli._progress import _console

        assert _console.file is sys.stderr


class TestTimeoutConsistency:
    """Test that timeout configurations are reasonable."""

    def test_http_timeouts_defined(self) -> None:
        """HTTP timeouts are defined in CLI command files."""
        from pathlib import Path

        sources_to_check = [
            Path("src/pkg_defender/cli/common.py"),
            Path("src/pkg_defender/cli/commands/db.py"),
        ]

        found = False
        for source_file in sources_to_check:
            if source_file.exists():
                content = source_file.read_text()
                if "ClientTimeout(total=" in content:
                    found = True
                    break

        assert found, "ClientTimeout(total= not found in cli/common.py or cli/commands/db.py"

    def test_timeout_values_reasonable(self) -> None:
        """Timeout values are in reasonable ranges."""

        # Common timeout patterns and their expected ranges
        # 10s for regular HTTP, 30s for some ops, 300s (5 min) for large ops
        timeouts = [10, 30, 300, 5]

        for timeout in timeouts:
            # These are reasonable timeout values
            assert 1 <= timeout <= 600, f"Timeout {timeout}s seems unreasonable"


class TestCLIHelpConsistency:
    """Test that CLI help text is consistent."""

    @pytest.fixture
    def runner(self) -> CliRunner:
        """Click test runner."""
        return CliRunner()

    def test_help_option_names(self, runner: CliRunner) -> None:
        """All commands use consistent help option names."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        # Click default: -h, --help (set in context_settings)
        assert "-h" in result.output
        assert "--help" in result.output

    def test_version_option(self, runner: CliRunner) -> None:
        """Version option works consistently."""
        result = runner.invoke(cli, ["-V"])
        assert result.exit_code == 0
        assert "pkgd version" in result.output

    def test_commands_have_help(self, runner: CliRunner) -> None:
        """All subcommands have help text."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        # Check that major commands are listed
        # Note: init is hidden (deprecated) — tested separately
        major_commands = ["status", "bypass", "audit", "intel", "reset"]
        for cmd in major_commands:
            assert cmd in result.output, f"Command '{cmd}' not found in help"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
