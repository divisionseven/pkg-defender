"""Tests for --fail-on-threat flag on install/upgrade commands."""

from __future__ import annotations

from click.testing import CliRunner

from pkg_defender.cli.main import cli


class TestFailOnThreatFlag:
    """Tests for --fail-on-threat flag on install/upgrade commands."""

    def test_fail_on_threat_flag_exists(self) -> None:
        """Test that --fail-on-threat flag is available on manager commands."""
        runner = CliRunner()
        # Test that --fail-on-threat flag is recognized
        result = runner.invoke(cli, ["pip", "--help"])
        assert "--fail-on-threat" in result.output or "fail-on-threat" in result.output

    def test_fail_on_threat_config_key_exists(self) -> None:
        """Test that fail_on_threat_enabled config key exists."""
        from pkg_defender.config.settings import PKGDConfig

        config = PKGDConfig()
        assert hasattr(config, "fail_on_threat_enabled")
        assert config.fail_on_threat_enabled is True  # Default is True

    def test_fail_on_threat_env_var_exists(self) -> None:
        """Test that PKGD_FAIL_ON_THREAT environment variable is recognized."""
        import os

        # Set env var
        os.environ["PKGD_FAIL_ON_THREAT"] = "false"

        from pkg_defender.config.settings import load_config

        config = load_config()
        assert config.fail_on_threat_enabled is False

        # Clean up
        del os.environ["PKGD_FAIL_ON_THREAT"]
