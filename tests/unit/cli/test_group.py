"""Tests for ManagerGroup and manager passthrough command."""

from __future__ import annotations

from click.testing import CliRunner

from pkg_defender.cli.group import make_manager_passthrough_command


class TestManagerCommandHelp:
    """Verify that manager command help displays PKGD flags."""

    def test_help_shows_pkgd_flags(self) -> None:
        """--help for a manager command must include PKGD-specific flags."""
        cmd = make_manager_passthrough_command("pip")
        runner = CliRunner()
        result = runner.invoke(cmd, ["--help"])
        assert result.exit_code == 0
        assert "--cooldown" in result.output
        assert "--dry-run" in result.output
