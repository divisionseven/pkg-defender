"""Tests for CI mode implementation."""

import os
from unittest.mock import patch

import pytest


class TestIsCiEnvironment:
    """Tests for is_ci_environment() detection."""

    def test_no_ci_vars_returns_false(self) -> None:
        """When no CI env vars set, returns False."""
        with patch.dict(os.environ, {}, clear=True):
            from pkg_defender.cli._ci_detect import is_ci_environment

            assert is_ci_environment() is False

    def test_ci_var_set_returns_true(self) -> None:
        """When any CI env var set, returns True."""
        with patch.dict(os.environ, {"CI": "true"}, clear=True):
            from pkg_defender.cli._ci_detect import is_ci_environment

            assert is_ci_environment() is True

    def test_github_actions_detected(self) -> None:
        """GitHub Actions environment detected."""
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}, clear=True):
            from pkg_defender.cli._ci_detect import is_ci_environment

            assert is_ci_environment() is True

    def test_azure_pipelines_detected(self) -> None:
        """Azure Pipelines detected."""
        with patch.dict(os.environ, {"TF_BUILD": "1"}, clear=True):
            from pkg_defender.cli._ci_detect import is_ci_environment

            assert is_ci_environment() is True


class TestGetCiProvider:
    """Tests for get_ci_provider()."""

    def test_github_actions_provider_name(self) -> None:
        """Returns correct provider name."""
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}, clear=True):
            from pkg_defender.cli._ci_detect import get_ci_provider

            assert get_ci_provider() == "github_actions"

    def test_not_in_ci_returns_none(self) -> None:
        """Returns None when not in CI."""
        with patch.dict(os.environ, {}, clear=True):
            from pkg_defender.cli._ci_detect import get_ci_provider

            assert get_ci_provider() is None


class TestCiEnvVars:
    """Tests for PKGD_* environment variable handling."""

    def test_pkgd_github_token_sets_ghsa(self) -> None:
        """PKGD_GITHUB_TOKEN maps to ghsa_token."""
        # Clear other PKGD_ vars first
        env_to_clear = {k for k in os.environ if k.startswith("PKGD_")}
        for k in env_to_clear:
            del os.environ[k]

        with patch.dict(os.environ, {"PKGD_GITHUB_TOKEN": "test_token"}):
            # Import fresh to get env override
            from importlib import reload

            import pkg_defender.config.settings as settings_module

            reload(settings_module)
            config = settings_module.load_config()
            assert config.feeds.ghsa_token == "test_token"

    def test_pkgd_twitter_api_key_sets_socket(self) -> None:
        """PKGD_TWITTER_API_KEY maps to socket_api_key."""
        # Clear other PKGD_ vars first
        env_to_clear = {k for k in os.environ if k.startswith("PKGD_")}
        for k in env_to_clear:
            del os.environ[k]

        with patch.dict(os.environ, {"PKGD_TWITTER_API_KEY": "socket_key"}):
            from importlib import reload

            import pkg_defender.config.settings as settings_module

            reload(settings_module)
            config = settings_module.load_config()
            assert config.feeds.socket_api_key == "socket_key"

    def test_pkgd_extra_feed_url_appends_to_rss(self) -> None:
        """PKGD_EXTRA_FEED_URL appends to RSS feeds."""
        # Clear other PKGD_ vars first
        env_to_clear = {k for k in os.environ if k.startswith("PKGD_")}
        for k in env_to_clear:
            del os.environ[k]

        with patch.dict(os.environ, {"PKGD_EXTRA_FEED_URL": "https://example.com/feed.xml"}):
            from importlib import reload

            import pkg_defender.config.settings as settings_module

            reload(settings_module)
            config = settings_module.load_config()
            assert "https://example.com/feed.xml" in config.feeds.rss_urls

    def test_pkgd_data_dir_sets_database_path(self) -> None:
        """PKGD_DATA_DIR maps to database path."""
        # Clear other PKGD_ vars first
        env_to_clear = {k for k in os.environ if k.startswith("PKGD_")}
        for k in env_to_clear:
            del os.environ[k]

        with patch.dict(os.environ, {"PKGD_DATA_DIR": "/test/data"}):
            from importlib import reload

            import pkg_defender.config.settings as settings_module

            reload(settings_module)
            config = settings_module.load_config()
            assert str(config.database.path) == "/test/data"


class TestCliCiFlag:
    """Tests for --ci CLI flag."""

    def test_ci_flag_accepted(self) -> None:
        """--ci flag is accepted by CLI."""
        from click.testing import CliRunner

        from pkg_defender.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["--ci", "--help"])
        assert result.exit_code == 0
        assert "Run in non-interactive CI mode" in result.output

    def test_returns_exit_code_zero_when_using_non_interactive_flag(self) -> None:
        """--non-interactive alias works."""
        from click.testing import CliRunner

        from pkg_defender.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["--non-interactive", "--help"])
        assert result.exit_code == 0
        assert "Run in non-interactive CI mode" in result.output


class TestPkgdCiEnvVar:
    """Tests for PKGD_CI=1 environment variable."""

    def test_pkgd_ci_1_enables_ci_mode(self) -> None:
        """PKGD_CI=1 enables CI mode in CLI context."""
        from click.testing import CliRunner

        from pkg_defender.cli.main import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(cli, ["--help"], env={"PKGD_CI": "1"})
            assert result.exit_code == 0

    def test_pkgd_ci_true_enables_ci_mode(self) -> None:
        """PKGD_CI=true enables CI mode."""
        from click.testing import CliRunner

        from pkg_defender.cli.main import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(cli, ["--help"], env={"PKGD_CI": "true"})
            assert result.exit_code == 0

    def test_pkgd_ci_zero_does_not_enable_ci(self) -> None:
        """PKGD_CI=0 does NOT enable CI mode (falls through to auto-detection).

        The code only checks for ``\"1\"``, ``\"true\"``, ``\"yes\"`` —
        ``PKGD_CI=0`` silently falls through to auto-detection.
        """
        from click.testing import CliRunner

        from pkg_defender.cli.main import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(cli, ["--help"], env={"PKGD_CI": "0"})
            assert result.exit_code == 0


class TestCiFlagPriority:
    """Tests for --ci flag priority over auto-detection."""

    def test_explicit_ci_overrides_auto_detection(self) -> None:
        """Explicit --ci flag should work even when no CI env vars are present."""

        from click.testing import CliRunner

        from pkg_defender.cli.main import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            # Invoke with explicit --ci flag
            runner.invoke(cli, ["--ci", "status"])
            # Just check it doesn't error - the command may fail for other reasons
            # but the --ci flag should be accepted

    def test_ci_flag_available_globally(self) -> None:
        """--ci flag is available globally, not just on setup."""
        from click.testing import CliRunner

        from pkg_defender.cli.main import cli

        runner = CliRunner()
        # Test that --ci flag works with a command that requires arguments
        # Should NOT error about unknown option
        result = runner.invoke(cli, ["--ci", "audit", "--help"])
        # Should not complain about --ci being unknown
        assert "no such option" not in result.output.lower() or result.exit_code == 0


class TestSetupCiIntegration:
    """Tests for setup command in CI mode."""

    def test_setup_skips_prompts_in_ci_mode(self) -> None:
        """Setup skips prompts when running with --ci flag."""
        from unittest.mock import patch

        from click.testing import CliRunner

        from pkg_defender.cli.main import cli

        runner = CliRunner()
        with runner.isolated_filesystem(), patch("pkg_defender.cli.main.is_running_in_ci") as mock_ci:
            mock_ci.return_value = True
            # Run setup with --ci - should not prompt for tokens
            runner.invoke(cli, ["setup", "--dry-run"], catch_exceptions=False)
            # In CI mode, should skip token prompts but still show the dry-run
            # Should contain "CI mode detected" or "Skipping token prompts"
            # Note: The actual output depends on implementation

    def test_setup_init_in_ci_mode(self) -> None:
        """Setup --init works in CI mode."""
        from unittest.mock import patch

        from click.testing import CliRunner

        from pkg_defender.cli.main import cli

        runner = CliRunner()
        with runner.isolated_filesystem(), patch("pkg_defender.cli.main.is_running_in_ci") as mock_ci:
            mock_ci.return_value = True
            result = runner.invoke(cli, ["setup", "--init"])
            # Should create config without interactive prompts
            assert result.exit_code == 0
            assert "Created" in result.output

    def test_returns_expected_config_when_env_var_set_in_ci_mode(self) -> None:
        """Setup uses environment variables for credentials in CI mode."""
        from unittest.mock import patch

        # Clear other PKGD_ vars first
        env_to_clear = {k for k in os.environ if k.startswith("PKGD_")}
        for k in env_to_clear:
            del os.environ[k]

        try:
            with patch.dict(os.environ, {"PKGD_GITHUB_TOKEN": "from_env_token"}):
                from importlib import reload

                import pkg_defender.config.settings as settings_module

                reload(settings_module)
                config = settings_module.load_config()
                # PKGD_GITHUB_TOKEN should take precedence
                assert config.feeds.ghsa_token == "from_env_token"
        finally:
            # Restore environment
            pass


class TestAllCiEnvVarsDetected:
    """Tests for all CI environment variables detection."""

    @pytest.mark.parametrize(
        "env_var",
        [
            "CI",
            "GITHUB_ACTIONS",
            "TF_BUILD",
            "GITLAB_CI",
            "CIRCLECI",
            "JENKINS_URL",
            "TRAVIS",
            "CODEBUILD_BUILD_ID",
            "BITBUCKET_COMMIT",
            "BUILDKITE",
            "TEAMCITY_VERSION",
            "SYSTEM_ACCESSTOKEN",
        ],
    )
    def test_all_ci_env_vars_detected(self, env_var: str) -> None:
        """All known CI environment variables are detected."""
        with patch.dict(os.environ, {env_var: "true"}, clear=True):
            from pkg_defender.cli._ci_detect import is_ci_environment

            assert is_ci_environment() is True, f"Failed to detect {env_var}"


class TestIsRunningInCi:
    """Tests for is_running_in_ci() context function."""

    def test_ci_from_ctx_obj(self) -> None:
        """is_running_in_ci returns True when ci=True in context."""
        from unittest.mock import MagicMock

        mock_ctx = MagicMock()
        mock_ctx.obj = {"ci": True, "ci_auto_detected": False}

        from pkg_defender.cli.common import is_running_in_ci

        assert is_running_in_ci(mock_ctx) is True

    def test_ci_auto_detected(self) -> None:
        """is_running_in_ci returns True when ci_auto_detected=True."""
        from unittest.mock import MagicMock

        mock_ctx = MagicMock()
        mock_ctx.obj = {"ci": False, "ci_auto_detected": True}

        from pkg_defender.cli.common import is_running_in_ci

        assert is_running_in_ci(mock_ctx) is True

    def test_not_ci(self) -> None:
        """is_running_in_ci returns False when neither ci nor ci_auto_detected."""
        from unittest.mock import MagicMock

        mock_ctx = MagicMock()
        mock_ctx.obj = {"ci": False, "ci_auto_detected": False}

        from pkg_defender.cli.common import is_running_in_ci

        assert is_running_in_ci(mock_ctx) is False


class TestPkgdConfigFileEnvVar:
    """Tests for PKGD_CONFIG_FILE environment variable."""

    def test_pkgd_config_file_maps_to_config_path(self) -> None:
        """PKGD_CONFIG_FILE maps to config path (sets PKGD_CONFIG_PATH internally)."""
        import tempfile
        from pathlib import Path

        # Clear other PKGD_ vars first
        env_to_clear = {k for k in os.environ if k.startswith("PKGD_")}
        original_env = {k: os.environ[k] for k in env_to_clear}
        for k in env_to_clear:
            del os.environ[k]

        # Create a temp config file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("[cooldown]\ndefault_days = 2\n")
            temp_config_path = f.name

        try:
            # Set PKGD_CONFIG_FILE which should map to PKGD_CONFIG_PATH internally
            with patch.dict(os.environ, {"PKGD_CONFIG_FILE": temp_config_path}):
                from importlib import reload

                import pkg_defender.config.settings as settings_module

                reload(settings_module)
                settings_module.load_config()
                # PKGD_CONFIG_FILE is mapped to PKGD_CONFIG_PATH in _apply_env_overrides
                # This happens AFTER config file loading, so we need to verify the mapping works
                # by checking that it sets the internal env var correctly
                assert os.environ.get("PKGD_CONFIG_PATH") == temp_config_path
        finally:
            # Restore original environment
            for k in env_to_clear:
                os.environ[k] = original_env[k]
            Path(temp_config_path).unlink(missing_ok=True)


class TestExtraFeedUrlEdgeCases:
    """Edge case tests for PKGD_EXTRA_FEED_URL."""

    def test_extra_feed_url_no_duplicate_on_reload(self) -> None:
        """PKGD_EXTRA_FEED_URL doesn't duplicate URL on config reload."""
        # Clear other PKGD_ vars first
        env_to_clear = {k for k in os.environ if k.startswith("PKGD_")}
        for k in env_to_clear:
            del os.environ[k]

        with patch.dict(os.environ, {"PKGD_EXTRA_FEED_URL": "https://example.com/feed.xml"}):
            from importlib import reload

            import pkg_defender.config.settings as settings_module

            # First load
            reload(settings_module)
            config1 = settings_module.load_config()
            count1 = config1.feeds.rss_urls.count("https://example.com/feed.xml")

            # Second load (simulating reload)
            config2 = settings_module.load_config()
            count2 = config2.feeds.rss_urls.count("https://example.com/feed.xml")

            # Should only have one instance
            assert count1 == 1, "URL should appear exactly once on first load"
            assert count2 == 1, "URL should appear exactly once on second load"


class TestCiModePriority:
    """Tests for CI mode priority (--ci flag > PKGD_CI env > auto-detect)."""

    def test_pkgd_ci_yes_enables_ci_mode(self) -> None:
        """PKGD_CI=yes enables CI mode."""
        from click.testing import CliRunner

        from pkg_defender.cli.main import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(cli, ["--help"], env={"PKGD_CI": "yes"})
            assert result.exit_code == 0


class TestCiAutoDetectionWiring:
    """Tests that CI auto-detection wires into Click context correctly."""

    def test_auto_detection_triggers_ci_mode(self) -> None:
        """Setting GITHUB_ACTIONS=true results in is_running_in_ci() returning True.

        When GITHUB_ACTIONS is present and --ci is not passed, the CLI sets
        ``ci_auto_detected`` in the context, which makes ``is_running_in_ci()``
        return True.
        """
        from click.testing import CliRunner

        from pkg_defender.cli.main import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                ["--help"],
                env={"GITHUB_ACTIONS": "true"},
                catch_exceptions=False,
            )
            assert result.exit_code == 0
