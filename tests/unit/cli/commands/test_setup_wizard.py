"""Tests for the setup wizard's warning/error handling paths.

Verifies that the B6 fix (per-step warning tracking + conditional success
message) correctly handles non-fatal failures:

- Each failing operation produces a specific warning message
- The wizard does not crash on any failure
- Exit code is ``_EXIT_PARTIAL_FAILURE`` (8) when any operation fails
- Exit code is 0 when all operations succeed
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest import mock

import pytest
from click.testing import CliRunner

from pkg_defender.cli._exit_codes import EXIT_PARTIAL_FAILURE as _EXIT_PARTIAL_FAILURE
from pkg_defender.cli._exit_codes import EXIT_REGISTRY_UNREACHABLE as _EXIT_REGISTRY_UNREACHABLE
from pkg_defender.cli._exit_codes import EXIT_USAGE_ERROR as _EXIT_USAGE_ERROR
from pkg_defender.cli.main import cli

pytestmark = pytest.mark.unit


class TestSetupWizardFailures:
    """Runtime behaviour tests for the setup wizard's warning/error paths.

    Each test verifies that the wizard gracefully handles a specific
    non-fatal operation failure by:
    1. Printing the appropriate warning message
    2. Continuing without crashing
    3. Returning exit code ``_EXIT_PARTIAL_FAILURE`` (8) when any operation fails
    """

    # ------------------------------------------------------------------ #
    # Intel sync failure tests (Tests 1-3)
    # ------------------------------------------------------------------ #

    def test_setup_intel_sync_failure_shows_warning_and_exit_code(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Intel sync raising ``SystemExit(5)`` produces warning and exit code 8."""
        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=True),
            mock.patch("pkg_defender.cli.commands.setup.install_completion"),
            mock.patch("pkg_defender.cli.commands.setup._generate_config_template"),
            mock.patch("pkg_defender.cli.commands.setup._write_config_toml"),
            mock.patch(
                "pkg_defender.cli.commands.setup.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            ),
            mock.patch("pkg_defender.cli.commands.setup.console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.setup.init_db"),
            mock.patch(
                "pkg_defender.cli.commands.intel.intel_sync",
                side_effect=SystemExit(_EXIT_REGISTRY_UNREACHABLE),
            ),
        ):
            result = runner.invoke(cli, ["--ci", "setup"])

        assert result.exit_code == _EXIT_PARTIAL_FAILURE
        assert any("Setup complete with warnings" in str(args) for args, _ in mock_print.call_args_list), (
            "Expected 'Setup complete with warnings' in console.print output"
        )
        assert any("Intel sync failed" in str(args) for args, _ in mock_print.call_args_list), (
            "Expected 'Intel sync failed' in console.print output"
        )

    def test_setup_intel_sync_exception_shows_warning(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Intel sync raising a generic ``Exception`` produces warning and exit code 8."""
        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=True),
            mock.patch("pkg_defender.cli.commands.setup.install_completion"),
            mock.patch("pkg_defender.cli.commands.setup._generate_config_template"),
            mock.patch("pkg_defender.cli.commands.setup._write_config_toml"),
            mock.patch(
                "pkg_defender.cli.commands.setup.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            ),
            mock.patch("pkg_defender.cli.commands.setup.console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.setup.init_db"),
            mock.patch(
                "pkg_defender.cli.commands.intel.intel_sync",
                side_effect=Exception("Network timeout"),
            ),
        ):
            result = runner.invoke(cli, ["--ci", "setup"])

        assert result.exit_code == _EXIT_PARTIAL_FAILURE
        assert any("Setup complete with warnings" in str(args) for args, _ in mock_print.call_args_list), (
            "Expected 'Setup complete with warnings' in console.print output"
        )
        assert any("Intel sync failed" in str(args) for args, _ in mock_print.call_args_list), (
            "Expected 'Intel sync failed' in console.print output"
        )

    def test_setup_intel_sync_success_shows_success(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Intel sync succeeding shows green 'Setup complete!' and exit code 0."""
        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=True),
            mock.patch("pkg_defender.cli.commands.setup.install_completion"),
            mock.patch("pkg_defender.cli.commands.setup._generate_config_template"),
            mock.patch("pkg_defender.cli.commands.setup._write_config_toml"),
            mock.patch(
                "pkg_defender.cli.commands.setup.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            ),
            mock.patch("pkg_defender.cli.commands.setup.console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.setup.init_db"),
            mock.patch("pkg_defender.cli.commands.intel.intel_sync"),
        ):
            result = runner.invoke(cli, ["--ci", "setup"])

        assert result.exit_code == 0
        assert any("Setup complete!" in str(args) for args, _ in mock_print.call_args_list), (
            "Expected 'Setup complete!' in console.print output"
        )
        assert not any("Setup complete with warnings" in str(args) for args, _ in mock_print.call_args_list), (
            "Did not expect 'Setup complete with warnings' in console.print output"
        )

    # ------------------------------------------------------------------ #
    # Config file write failure test (Test 4)
    # ------------------------------------------------------------------ #

    def test_setup_config_file_write_failure_shows_warning(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Config file write failure produces warning and exit code 8 (wizard continues)."""
        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=True),
            mock.patch("pkg_defender.cli.commands.setup.install_completion"),
            mock.patch("pkg_defender.cli.commands.setup._generate_config_template"),
            mock.patch(
                "pkg_defender.cli.commands.setup._write_config_toml",
                side_effect=OSError("Permission denied"),
            ),
            mock.patch(
                "pkg_defender.cli.commands.setup.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            ),
            mock.patch("pkg_defender.cli.commands.setup.console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.setup.init_db"),
            mock.patch("pkg_defender.cli.commands.intel.intel_sync"),
        ):
            result = runner.invoke(cli, ["--ci", "setup"])

        assert result.exit_code == _EXIT_PARTIAL_FAILURE
        assert any("Config file write failed" in str(args) for args, _ in mock_print.call_args_list), (
            "Expected 'Config file write failed' in console.print output"
        )

    # ------------------------------------------------------------------ #
    # DB init failure test (Test 5)
    # ------------------------------------------------------------------ #

    def test_setup_db_init_failure_shows_warning(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Database initialization failure produces warning and exit code 8 (wizard continues)."""
        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=True),
            mock.patch("pkg_defender.cli.commands.setup.install_completion"),
            mock.patch("pkg_defender.cli.commands.setup._generate_config_template"),
            mock.patch("pkg_defender.cli.commands.setup._write_config_toml"),
            mock.patch(
                "pkg_defender.cli.commands.setup.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            ),
            mock.patch("pkg_defender.cli.commands.setup.console.print") as mock_print,
            mock.patch(
                "pkg_defender.cli.commands.setup.init_db",
                side_effect=RuntimeError("DB path invalid"),
            ),
            mock.patch("pkg_defender.cli.commands.intel.intel_sync"),
        ):
            result = runner.invoke(cli, ["--ci", "setup"])

        assert result.exit_code == _EXIT_PARTIAL_FAILURE
        assert any("Database initialization failed" in str(args) for args, _ in mock_print.call_args_list), (
            "Expected 'Database initialization failed' in console.print output"
        )

    # ------------------------------------------------------------------ #
    # Token write failure test (Test 6)
    # ------------------------------------------------------------------ #

    def test_setup_token_write_failure_shows_warning(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Token configuration save failure produces warning (wizard continues)."""
        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=True),
            mock.patch("pkg_defender.cli.commands.setup.install_completion"),
            mock.patch("pkg_defender.cli.commands.setup._generate_config_template"),
            mock.patch("pkg_defender.cli.commands.setup._write_config_toml"),
            mock.patch(
                "pkg_defender.cli.commands.setup.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            ),
            mock.patch("pkg_defender.cli.commands.setup.console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.setup.init_db"),
            mock.patch("pkg_defender.cli.commands.intel.intel_sync"),
            mock.patch(
                "pkg_defender.cli.commands.setup._prompt_for_tokens",
                side_effect=OSError("Read-only filesystem"),
            ),
        ):
            # Use non-CI mode so _prompt_for_tokens() is called; pass "1"
            # (followed by Enter) to accept the default database location.
            result = runner.invoke(cli, ["setup"], input="1\n")

        assert result.exit_code == _EXIT_PARTIAL_FAILURE
        assert any("Token configuration save failed" in str(args) for args, _ in mock_print.call_args_list), (
            "Expected 'Token configuration save failed' in console.print output"
        )

    # ------------------------------------------------------------------ #
    # Clean run test (Test 7)
    # ------------------------------------------------------------------ #

    def test_setup_exit_code_zero_on_clean_run(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """A fully successful setup run produces exit code 0."""
        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=True),
            mock.patch("pkg_defender.cli.commands.setup.install_completion"),
            mock.patch("pkg_defender.cli.commands.setup._generate_config_template"),
            mock.patch("pkg_defender.cli.commands.setup._write_config_toml"),
            mock.patch(
                "pkg_defender.cli.commands.setup.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            ),
            mock.patch("pkg_defender.cli.commands.setup.console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.setup.init_db"),
            mock.patch("pkg_defender.cli.commands.intel.intel_sync"),
        ):
            result = runner.invoke(cli, ["--ci", "setup"])

        assert result.exit_code == 0
        assert any("Setup complete!" in str(args) for args, _ in mock_print.call_args_list), (
            "Expected 'Setup complete!' in console.print output"
        )
        assert not any("Setup complete with warnings" in str(args) for args, _ in mock_print.call_args_list), (
            "Did not expect 'Setup complete with warnings' in console.print output"
        )

    # ------------------------------------------------------------------ #
    # Platform-correct DB path display tests (Tests 8-9)
    # ------------------------------------------------------------------ #

    def test_setup_displays_platform_correct_db_path(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Setup wizard displays the actual platform-correct database path."""
        from pkg_defender.config.settings import get_data_dir, get_db_path

        expected_db_path = str(get_db_path())
        expected_data_dir = str(get_data_dir())

        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=True),
            mock.patch("pkg_defender.cli.commands.setup.install_completion"),
            mock.patch("pkg_defender.cli.commands.setup._generate_config_template"),
            mock.patch("pkg_defender.cli.commands.setup._write_config_toml"),
            mock.patch(
                "pkg_defender.cli.commands.setup.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            ),
            mock.patch("pkg_defender.cli.commands.setup.console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.setup.init_db"),
            mock.patch("pkg_defender.cli.commands.intel.intel_sync"),
            # CRITICAL: must patch _prompt_for_tokens AND _prompt_ossf_exclusion
            # to prevent getpass from triggering GetPassWarning in non-TTY
            # test environments.
            mock.patch("pkg_defender.cli.commands.setup._prompt_for_tokens"),
            mock.patch("pkg_defender.cli.commands.setup._prompt_ossf_exclusion"),
        ):
            # Non-CI mode to trigger the option display; input "1" selects default
            runner.invoke(cli, ["setup"], input="1\n")

        # Collect all printed strings
        all_output = " ".join(str(args) for args, _ in mock_print.call_args_list)

        # Must NOT contain hardcoded Linux path on non-Linux platforms
        import sys

        if sys.platform != "linux":
            assert "~/.local/share/pkg-defender" not in all_output, (
                f"Setup wizard displays hardcoded Linux path on {sys.platform}. "
                f"Expected platform-correct path: {expected_db_path}"
            )

        # Must contain the actual platform-correct path
        assert expected_db_path in all_output or expected_data_dir in all_output, (
            f"Setup wizard does not display platform-correct path. "
            f"Expected one of: {expected_db_path}, {expected_data_dir}"
        )

    def test_setup_ci_mode_displays_platform_correct_db_path(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """CI mode setup displays the actual platform-correct database path."""
        from pkg_defender.config.settings import get_db_path

        expected_db_path = str(get_db_path())

        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=True),
            mock.patch("pkg_defender.cli.commands.setup.install_completion"),
            mock.patch("pkg_defender.cli.commands.setup._generate_config_template"),
            mock.patch("pkg_defender.cli.commands.setup._write_config_toml"),
            mock.patch(
                "pkg_defender.cli.commands.setup.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            ),
            mock.patch("pkg_defender.cli.commands.setup.console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.setup.init_db"),
            mock.patch("pkg_defender.cli.commands.intel.intel_sync"),
        ):
            runner.invoke(cli, ["--ci", "setup"])

        all_output = " ".join(str(args) for args, _ in mock_print.call_args_list)

        # CI mode should display the platform-correct path
        assert expected_db_path in all_output, (
            f"CI mode setup does not display platform-correct path. Expected: {expected_db_path}"
        )


# ------------------------------------------------------------------ #
# OSSF exclusion prompt tests
# ------------------------------------------------------------------ #


class TestSetupOSSFExclusion:
    """Tests for the OSSF exclusion prompt during setup."""

    def test_no_token_shows_prompt(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """When no GHSA token is set, OSSF exclusion prompt appears."""
        import tomllib

        config_path = isolated_env["config_path"]
        config_path.write_text("[feeds]\nossf_malicious_enabled = true\n", encoding="utf-8")

        from pkg_defender.cli.commands.setup import _prompt_ossf_exclusion

        with mock.patch(
            "pkg_defender.cli.commands.setup.Prompt.ask",
            return_value="1",
        ):
            # Should not raise — prompt appears and user chooses Option A
            result = _prompt_ossf_exclusion(config_path=config_path)

        assert result is None

        # Config should still have ossf_malicious_enabled = true
        with open(config_path, "rb") as fh:
            data = tomllib.load(fh)
        assert data["feeds"]["ossf_malicious_enabled"] is True

    def test_has_token_skips_prompt(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """When GHSA token is set, OSSF exclusion prompt is skipped."""
        config_path = isolated_env["config_path"]
        config_path.write_text(
            '[feeds]\nghsa_token = "ghp_test"\nossf_malicious_enabled = true\n',
            encoding="utf-8",
        )

        from pkg_defender.cli.commands.setup import _prompt_ossf_exclusion

        with mock.patch(
            "pkg_defender.cli.commands.setup.Prompt.ask",
        ) as mock_ask:
            _prompt_ossf_exclusion(config_path=config_path)
            # Prompt.ask should NOT have been called
            mock_ask.assert_not_called()

    def test_exclusion_sets_config(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Choosing yes sets ossf_malicious_enabled=False in config."""
        import tomllib

        config_path = isolated_env["config_path"]
        config_path.write_text("[feeds]\nossf_malicious_enabled = true\n", encoding="utf-8")

        from pkg_defender.cli.commands.setup import _prompt_ossf_exclusion

        with mock.patch(
            "pkg_defender.cli.commands.setup.Prompt.ask",
            return_value="3",
        ):
            result = _prompt_ossf_exclusion(config_path=config_path)

        assert result is None

        with open(config_path, "rb") as fh:
            data = tomllib.load(fh)
        assert data["feeds"]["ossf_malicious_enabled"] is False

    def test_inclusion_leaves_config(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Choosing no leaves ossf_malicious_enabled=True (default)."""
        import tomllib

        config_path = isolated_env["config_path"]
        config_path.write_text("[feeds]\nossf_malicious_enabled = true\n", encoding="utf-8")

        from pkg_defender.cli.commands.setup import _prompt_ossf_exclusion

        with mock.patch(
            "pkg_defender.cli.commands.setup.Prompt.ask",
            return_value="1",
        ):
            result = _prompt_ossf_exclusion(config_path=config_path)

        assert result is None

        with open(config_path, "rb") as fh:
            data = tomllib.load(fh)
        assert data["feeds"]["ossf_malicious_enabled"] is True

    def test_already_disabled_skips_prompt(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """When OSSF is already disabled, prompt is skipped."""
        config_path = isolated_env["config_path"]
        config_path.write_text("[feeds]\nossf_malicious_enabled = false\n", encoding="utf-8")

        from pkg_defender.cli.commands.setup import _prompt_ossf_exclusion

        with mock.patch(
            "pkg_defender.cli.commands.setup.Prompt.ask",
        ) as mock_ask:
            _prompt_ossf_exclusion(config_path=config_path)
            mock_ask.assert_not_called()

    def test_exclusion_shows_daemon_instructions(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """When user excludes OSSF, daemon instructions are displayed."""
        config_path = isolated_env["config_path"]
        config_path.write_text("[feeds]\nossf_malicious_enabled = true\n", encoding="utf-8")

        from pkg_defender.cli.commands.setup import _prompt_ossf_exclusion

        with (
            mock.patch(
                "pkg_defender.cli.commands.setup.Prompt.ask",
                return_value="2",
            ),
            mock.patch(
                "pkg_defender.cli.commands.setup.console.print",
            ) as mock_print,
        ):
            result = _prompt_ossf_exclusion(config_path=config_path)

        # Verify function returns the feeds to exclude
        assert result == ["ossf_malicious"]

        # Verify daemon instructions were printed
        printed_text = " ".join(str(args) for args, _ in mock_print.call_args_list)
        assert "daemon" in printed_text.lower()
        assert "excluded from this sync only" in printed_text

    def test_defer_option_returns_feeds_to_exclude(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Option B returns ['ossf_malicious'] and does NOT modify config."""
        import tomllib

        config_path = isolated_env["config_path"]
        config_path.write_text("[feeds]\nossf_malicious_enabled = true\n", encoding="utf-8")

        from pkg_defender.cli.commands.setup import _prompt_ossf_exclusion

        with mock.patch(
            "pkg_defender.cli.commands.setup.Prompt.ask",
            return_value="2",
        ):
            result = _prompt_ossf_exclusion(config_path=config_path)

        assert result == ["ossf_malicious"]

        # Config must remain unchanged (ossf_malicious_enabled stays True)
        with open(config_path, "rb") as fh:
            data = tomllib.load(fh)
        assert data["feeds"]["ossf_malicious_enabled"] is True

    def test_permanent_disable_writes_config(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Option C writes ossf_malicious_enabled=False to config and returns None."""
        import tomllib

        config_path = isolated_env["config_path"]
        config_path.write_text("[feeds]\nossf_malicious_enabled = true\n", encoding="utf-8")

        from pkg_defender.cli.commands.setup import _prompt_ossf_exclusion

        with mock.patch(
            "pkg_defender.cli.commands.setup.Prompt.ask",
            return_value="3",
        ):
            result = _prompt_ossf_exclusion(config_path=config_path)

        assert result is None

        # Config must have ossf_malicious_enabled = False
        with open(config_path, "rb") as fh:
            data = tomllib.load(fh)
        assert data["feeds"]["ossf_malicious_enabled"] is False

    def test_sync_all_leaves_config_unchanged(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Option A returns None and leaves config unchanged."""
        import tomllib

        config_path = isolated_env["config_path"]
        config_path.write_text("[feeds]\nossf_malicious_enabled = true\n", encoding="utf-8")

        from pkg_defender.cli.commands.setup import _prompt_ossf_exclusion

        with mock.patch(
            "pkg_defender.cli.commands.setup.Prompt.ask",
            return_value="1",
        ):
            result = _prompt_ossf_exclusion(config_path=config_path)

        assert result is None

        # Config must remain unchanged
        with open(config_path, "rb") as fh:
            data = tomllib.load(fh)
        assert data["feeds"]["ossf_malicious_enabled"] is True

    def test_ossf_option_c_preserves_comments(self, tmp_path: Path) -> None:
        """OSSF Option C (permanent disable) preserves existing TOML comments."""
        config_path = tmp_path / "pkgd.toml"
        config_path.write_text(
            "# This is a comment\n[feeds]\n# OSSF setting\nossf_malicious_enabled = true\n",
            encoding="utf-8",
        )

        from pkg_defender.cli.commands.setup import _prompt_ossf_exclusion

        with mock.patch(
            "pkg_defender.cli.commands.setup.Prompt.ask",
            return_value="3",
        ):
            _prompt_ossf_exclusion(config_path=config_path)

        raw_content = config_path.read_text(encoding="utf-8")
        assert "# This is a comment" in raw_content, "Comment destroyed by OSSF Option C"
        assert "# OSSF setting" in raw_content, "Comment destroyed by OSSF Option C"

        import tomllib

        with open(config_path, "rb") as fh:
            data = tomllib.load(fh)
        assert data["feeds"]["ossf_malicious_enabled"] is False

    def test_ossf_option_c_preserves_banner(self, tmp_path: Path) -> None:
        """OSSF Option C preserves the full ASCII art banner."""
        from tomlkit import dumps as _tomlkit_dumps

        from pkg_defender.cli.common import _generate_config_template

        config_path = tmp_path / "pkgd.toml"
        doc = _generate_config_template()
        config_path.write_text(_tomlkit_dumps(doc), encoding="utf-8")

        from pkg_defender.cli.commands.setup import _prompt_ossf_exclusion

        with mock.patch(
            "pkg_defender.cli.commands.setup.Prompt.ask",
            return_value="3",
        ):
            _prompt_ossf_exclusion(config_path=config_path)

        raw_content = config_path.read_text(encoding="utf-8")
        assert "_/_/_/" in raw_content, "ASCII art banner destroyed by OSSF Option C"
        assert "PKG-Defender Configuration" in raw_content, "Banner header destroyed by OSSF Option C"


# ------------------------------------------------------------------ #
# _resolve_config_write_path tests
# ------------------------------------------------------------------ #


class TestResolveConfigWritePath:
    """Tests for _resolve_config_write_path path resolution precedence.

    Verifies that ``--config`` > ``PKGD_CONFIG_PATH`` > ``get_default_config_path()``
    precedence is correctly implemented (lines 35–56).
    """

    def test_uses_cli_flag(self) -> None:
        """CLI ``--config`` flag takes highest priority over env var and default."""
        mock_ctx = mock.MagicMock()
        mock_ctx.obj = {"config_file": "/custom/path.toml"}

        from pkg_defender.cli.commands.setup import _resolve_config_write_path

        result = _resolve_config_write_path(mock_ctx)

        assert result == Path("/custom/path.toml")

    def test_uses_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """PKGD_CONFIG_PATH env var is used when no ``--config`` flag."""
        monkeypatch.setenv("PKGD_CONFIG_PATH", "/env/path.toml")
        mock_ctx = mock.MagicMock()
        mock_ctx.obj = {}

        from pkg_defender.cli.commands.setup import _resolve_config_write_path

        result = _resolve_config_write_path(mock_ctx)

        assert result == Path("/env/path.toml")

    def test_falls_back_to_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Default config path returned when neither ``--config`` nor env var."""
        monkeypatch.delenv("PKGD_CONFIG_PATH", raising=False)
        mock_ctx = mock.MagicMock()
        mock_ctx.obj = {}

        from pkg_defender.cli.commands.setup import _resolve_config_write_path
        from pkg_defender.cli.common import get_default_config_path as _default_path

        result = _resolve_config_write_path(mock_ctx)

        assert result == _default_path()


# ------------------------------------------------------------------ #
# _overlay_existing_values tests
# ------------------------------------------------------------------ #


class TestOverlayExistingValues:
    """Tests for _overlay_existing_values recursive merge logic (lines 59–87).

    Verifies that existing config values survive the template overlay,
    sub-tables are merged recursively, and unknown keys are preserved.
    """

    def test_preserves_key_not_in_template(self) -> None:
        """Unknown keys in existing config survive the overlay."""
        from tomlkit import document as _tomlkit_document
        from tomlkit import table as _tomlkit_table

        from pkg_defender.cli.commands.setup import _overlay_existing_values

        template = _tomlkit_document()
        template["feeds"] = _tomlkit_table()
        template["feeds"]["ghsa_token"] = ""

        existing = _tomlkit_document()
        existing["feeds"] = _tomlkit_table()
        existing["feeds"]["ghsa_token"] = "ghp_abc"
        existing["custom_section"] = _tomlkit_table()
        existing["custom_section"]["key"] = "val"

        _overlay_existing_values(template, existing)

        assert template["custom_section"]["key"] == "val"

    def test_recurses_into_sub_tables(self) -> None:
        """Sub-tables merge recursively instead of being overwritten."""
        from tomlkit import document as _tomlkit_document
        from tomlkit import table as _tomlkit_table

        from pkg_defender.cli.commands.setup import _overlay_existing_values

        template = _tomlkit_document()
        template["cooldown"] = _tomlkit_table()
        template["cooldown"]["enabled"] = True
        template["cooldown"]["overrides"] = _tomlkit_table()
        template["cooldown"]["overrides"]["bad-pkg"] = 3600

        existing = _tomlkit_document()
        existing["cooldown"] = _tomlkit_table()
        existing["cooldown"]["enabled"] = True
        existing["cooldown"]["overrides"] = _tomlkit_table()
        existing["cooldown"]["overrides"]["bad-pkg"] = 7200
        existing["cooldown"]["overrides"]["other-pkg"] = 1800

        _overlay_existing_values(template, existing)

        # Existing values win
        assert template["cooldown"]["overrides"]["bad-pkg"] == 7200
        # Unknown key from existing is preserved
        assert template["cooldown"]["overrides"]["other-pkg"] == 1800

    def test_scalar_existing_wins(self) -> None:
        """Existing scalar values overwrite template defaults."""
        from tomlkit import document as _tomlkit_document
        from tomlkit import table as _tomlkit_table

        from pkg_defender.cli.commands.setup import _overlay_existing_values

        template = _tomlkit_document()
        template["feeds"] = _tomlkit_table()
        template["feeds"]["ghsa_token"] = ""

        existing = _tomlkit_document()
        existing["feeds"] = _tomlkit_table()
        existing["feeds"]["ghsa_token"] = "ghp_abc"

        _overlay_existing_values(template, existing)

        assert template["feeds"]["ghsa_token"] == "ghp_abc"


# ------------------------------------------------------------------ #
# _prompt_for_tokens tests
# ------------------------------------------------------------------ #


class TestPromptForTokens:
    """Tests for ``_prompt_for_tokens`` (lines 90–231).

    Verifies early-return when all tokens exist, selection parsing,
    value mismatch handling, and feeds section creation.
    """

    def test_no_missing_tokens_returns_early(self, tmp_path: Path) -> None:
        """When all feeds have tokens, the function returns without prompting."""
        config_path = tmp_path / "pkgd.toml"
        config_path.write_text(
            "[feeds]\n"
            'ghsa_token = "ghp_existing"\n'
            'socket_api_key = "sk_existing"\n'
            'x_twitter_bearer_token = "tw_existing"\n'
            'reddit_client_id = "rc_existing"\n'
            'reddit_client_secret = "rs_existing"\n'
        )

        from pkg_defender.cli.commands.setup import _prompt_for_tokens

        with (
            mock.patch("pkg_defender.cli.commands.setup.console.input") as mock_input,
            mock.patch("pkg_defender.cli.commands.setup.Prompt.ask") as mock_ask,
        ):
            _prompt_for_tokens(config_path=config_path)

        mock_input.assert_not_called()
        mock_ask.assert_not_called()

    def test_empty_selection_returns_early(self, tmp_path: Path) -> None:
        """Empty input (Enter) returns without processing or writing config."""
        config_path = tmp_path / "pkgd.toml"
        config_path.write_text("[feeds]\n")

        from pkg_defender.cli.commands.setup import _prompt_for_tokens

        with (
            mock.patch("pkg_defender.cli.commands.setup.console.input", return_value=""),
            mock.patch("pkg_defender.cli.commands.setup.Prompt.ask") as mock_ask,
            mock.patch("pkg_defender.cli.commands.setup._write_config_toml") as mock_write,
            mock.patch("pkg_defender.cli.commands.setup._print_clipboard_security_tip"),
        ):
            _prompt_for_tokens(config_path=config_path)

        mock_write.assert_not_called()
        mock_ask.assert_not_called()

    def test_invalid_selection_shows_warning(self, tmp_path: Path) -> None:
        """Non-numeric input shows 'Invalid input' warning and returns."""
        config_path = tmp_path / "pkgd.toml"
        config_path.write_text("[feeds]\n")

        from pkg_defender.cli.commands.setup import _prompt_for_tokens

        with (
            mock.patch("pkg_defender.cli.commands.setup.console.input", return_value="abc"),
            mock.patch("pkg_defender.cli.commands.setup.console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.setup._write_config_toml") as mock_write,
            mock.patch("pkg_defender.cli.commands.setup._print_clipboard_security_tip"),
        ):
            _prompt_for_tokens(config_path=config_path)

        mock_write.assert_not_called()
        assert any("Invalid input" in str(args) for args, _ in mock_print.call_args_list)

    def test_value_mismatch_skips_token(self, tmp_path: Path) -> None:
        """When password prompts don't match, the token is skipped with a warning."""
        import tomllib

        config_path = tmp_path / "pkgd.toml"
        config_path.write_text("[feeds]\n")

        from pkg_defender.cli.commands.setup import _prompt_for_tokens

        with (
            mock.patch(
                "pkg_defender.cli.commands.setup.console.input",
                return_value="1",
            ),
            mock.patch(
                "pkg_defender.cli.commands.setup.Prompt.ask",
                side_effect=["token1", "token2"],
            ),
            mock.patch("pkg_defender.cli.commands.setup.console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.setup._print_clipboard_security_tip"),
        ):
            _prompt_for_tokens(config_path=config_path)

        # Verify the warning message is displayed
        assert any("do not match" in str(args).lower() for args, _ in mock_print.call_args_list), (
            "Expected mismatch warning"
        )

        # Verify the token was NOT written to the file
        with open(config_path, "rb") as fh:
            data = tomllib.load(fh)
        feeds = data.get("feeds", {})
        assert feeds.get("ghsa_token") is None, "Token should not have been written"

    def test_only_configures_selected_indices(self, tmp_path: Path) -> None:
        """Only the selected token index is configured; other tokens remain unset."""
        import tomllib

        config_path = tmp_path / "pkgd.toml"
        config_path.write_text("[feeds]\n")

        from pkg_defender.cli.commands.setup import _prompt_for_tokens

        with (
            mock.patch(
                "pkg_defender.cli.commands.setup.console.input",
                return_value="1",
            ),
            mock.patch(
                "pkg_defender.cli.commands.setup.Prompt.ask",
                return_value="ghp_token123",
            ),
            mock.patch("pkg_defender.cli.commands.setup._print_clipboard_security_tip"),
        ):
            _prompt_for_tokens(config_path=config_path)

        with open(config_path, "rb") as fh:
            data = tomllib.load(fh)

        assert data["feeds"]["ghsa_token"] == "ghp_token123"
        assert "socket_api_key" not in data["feeds"]
        assert "x_twitter_bearer_token" not in data["feeds"]
        assert "reddit_client_id" not in data["feeds"]
        assert "reddit_client_secret" not in data["feeds"]

    def test_creates_feeds_section_if_missing(self, tmp_path: Path) -> None:
        """When config has no ``[feeds]`` section, one is created before writing tokens."""
        import tomllib

        config_path = tmp_path / "pkgd.toml"
        config_path.write_text("[other]\nkey = 'val'\n")

        from pkg_defender.cli.commands.setup import _prompt_for_tokens

        with (
            mock.patch(
                "pkg_defender.cli.commands.setup.console.input",
                return_value="1",
            ),
            mock.patch(
                "pkg_defender.cli.commands.setup.Prompt.ask",
                return_value="ghp_token123",
            ),
            mock.patch("pkg_defender.cli.commands.setup._print_clipboard_security_tip"),
        ):
            _prompt_for_tokens(config_path=config_path)

        with open(config_path, "rb") as fh:
            data = tomllib.load(fh)

        assert "feeds" in data
        assert data["feeds"]["ghsa_token"] == "ghp_token123"

    def test_token_write_preserves_comments(self, tmp_path: Path) -> None:
        """Token write preserves existing TOML comments and banner."""
        config_path = tmp_path / "pkgd.toml"
        # Write a config file WITH comments
        config_path.write_text(
            '# This is a comment\n[feeds]\n# API key comment\nghsa_token = ""\n',
            encoding="utf-8",
        )

        from pkg_defender.cli.commands.setup import _prompt_for_tokens

        with (
            mock.patch(
                "pkg_defender.cli.commands.setup.console.input",
                return_value="1",
            ),
            mock.patch(
                "pkg_defender.cli.commands.setup.Prompt.ask",
                return_value="ghp_token123",
            ),
            mock.patch("pkg_defender.cli.commands.setup._print_clipboard_security_tip"),
        ):
            _prompt_for_tokens(config_path=config_path)

        # Read the RAW file content (not parsed dict) to verify comments survived
        raw_content = config_path.read_text(encoding="utf-8")
        assert "# This is a comment" in raw_content, "Comment destroyed by token write"
        assert "# API key comment" in raw_content, "Comment destroyed by token write"

        # Also verify the token was written correctly
        import tomllib

        with open(config_path, "rb") as fh:
            data = tomllib.load(fh)
        assert data["feeds"]["ghsa_token"] == "ghp_token123"

    def test_token_write_preserves_banner(self, tmp_path: Path) -> None:
        """Token write preserves the full ASCII art banner from _generate_config_template."""
        from tomlkit import dumps as _tomlkit_dumps

        from pkg_defender.cli.common import _generate_config_template

        config_path = tmp_path / "pkgd.toml"
        # Write the actual template (with banner)
        doc = _generate_config_template()
        config_path.write_text(_tomlkit_dumps(doc), encoding="utf-8")

        from pkg_defender.cli.commands.setup import _prompt_for_tokens

        with (
            mock.patch(
                "pkg_defender.cli.commands.setup.console.input",
                return_value="1",
            ),
            mock.patch(
                "pkg_defender.cli.commands.setup.Prompt.ask",
                return_value="ghp_token123",
            ),
            mock.patch("pkg_defender.cli.commands.setup._print_clipboard_security_tip"),
        ):
            _prompt_for_tokens(config_path=config_path)

        raw_content = config_path.read_text(encoding="utf-8")
        # Banner lines from _generate_config_template (lines 321-341)
        assert "_/_/_/" in raw_content, "ASCII art banner destroyed by token write"
        assert "PKG-Defender Configuration" in raw_content, "Banner header destroyed by token write"


# ------------------------------------------------------------------ #
# CLI-level --init mode tests
# ------------------------------------------------------------------ #


class TestSetupCLIInitMode:
    """CLI-level tests for ``pkgd setup --init`` mode (lines 394–424)."""

    def test_force_without_init_raises_usage_error(self, runner: CliRunner) -> None:
        """``--force`` without ``--init`` is a usage error."""
        result = runner.invoke(cli, ["setup", "--force"])

        assert result.exit_code == _EXIT_USAGE_ERROR
        assert "--force requires --init" in result.output

    def test_init_mode_creates_config(self, runner: CliRunner) -> None:
        """``--init`` creates a valid ``pkgd.toml`` in CWD and returns exit 0."""
        import tomllib

        with runner.isolated_filesystem():
            result = runner.invoke(cli, ["setup", "--init"])

            assert result.exit_code == 0

            config_file = Path.cwd() / "pkgd.toml"
            assert config_file.exists()

            with open(config_file, "rb") as fh:
                data = tomllib.load(fh)
            assert isinstance(data, dict)
            assert len(data) > 0

    def test_init_mode_existing_config_without_force_errors(self, runner: CliRunner) -> None:
        """``--init`` without ``--force`` on existing ``pkgd.toml``` exits usage error."""
        with runner.isolated_filesystem():
            (Path.cwd() / "pkgd.toml").write_text("# placeholder\n")

            result = runner.invoke(cli, ["setup", "--init"])

            assert result.exit_code == _EXIT_USAGE_ERROR
            assert "already exists" in result.output

    def test_init_mode_with_force_overwrites(self, runner: CliRunner) -> None:
        """``--init --force`` overwrites existing ``pkgd.toml``."""
        with runner.isolated_filesystem():
            (Path.cwd() / "pkgd.toml").write_text("# old placeholder\n")

            result = runner.invoke(cli, ["setup", "--init", "--force"])

            assert result.exit_code == 0

            content = (Path.cwd() / "pkgd.toml").read_text()
            assert "# old placeholder" not in content
            assert len(content.strip()) > 0


# ------------------------------------------------------------------ #
# CLI-level shell detection tests
# ------------------------------------------------------------------ #


class TestSetupCLIShellDetection:
    """CLI-level tests for shell detection and completion installation (lines 437–448)."""

    def test_shell_not_installed_skips_completion(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """When shell is detected but not installed, completion is skipped."""
        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=False),
            mock.patch("pkg_defender.cli.commands.setup.install_completion") as mock_install,
            mock.patch("pkg_defender.cli.commands.setup._generate_config_template"),
            mock.patch("pkg_defender.cli.commands.setup._write_config_toml"),
            mock.patch(
                "pkg_defender.cli.commands.setup.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, "", ""),
            ),
            mock.patch("pkg_defender.cli.commands.setup.console.print"),
            mock.patch("pkg_defender.cli.commands.intel.intel_sync"),
        ):
            result = runner.invoke(cli, ["--ci", "setup"])

        assert result.exit_code == 0
        mock_install.assert_not_called()

    def test_completion_install_failure_shows_warning(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Completion install failure shows warning and continues with partial failure."""
        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=True),
            mock.patch(
                "pkg_defender.cli.commands.setup.install_completion",
                side_effect=PermissionError("Cannot write to /etc"),
            ),
            mock.patch("pkg_defender.cli.commands.setup._generate_config_template"),
            mock.patch("pkg_defender.cli.commands.setup._write_config_toml"),
            mock.patch(
                "pkg_defender.cli.commands.setup.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, "", ""),
            ),
            mock.patch("pkg_defender.cli.commands.setup.console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.intel.intel_sync"),
        ):
            result = runner.invoke(cli, ["--ci", "setup"])

        assert result.exit_code == _EXIT_PARTIAL_FAILURE
        assert any("Completion install failed" in str(args) for args, _ in mock_print.call_args_list)


# ------------------------------------------------------------------ #
# CLI-level manager detection tests
# ------------------------------------------------------------------ #


class TestSetupCLIManagerDetection:
    """CLI-level tests for manager detection timeout and binary-not-found (lines 492–506)."""

    def test_manager_detection_timeout_shows_not_found(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """``subprocess.TimeoutExpired`` shows manager as 'not found'."""
        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=True),
            mock.patch("pkg_defender.cli.commands.setup.install_completion"),
            mock.patch("pkg_defender.cli.commands.setup._generate_config_template"),
            mock.patch("pkg_defender.cli.commands.setup._write_config_toml"),
            mock.patch(
                "pkg_defender.cli.commands.setup.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="npm --version", timeout=5),
            ),
            mock.patch("pkg_defender.cli.commands.setup.console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.intel.intel_sync"),
        ):
            result = runner.invoke(cli, ["--ci", "setup"])

        assert result.exit_code == 0

        # At least one manager should show as "not found"
        not_found_calls = [str(args) for args, _ in mock_print.call_args_list if "not found" in str(args)]
        assert len(not_found_calls) >= 1

    def test_manager_detection_file_not_found_shows_not_found(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """``FileNotFoundError`` from detection commands shows manager as 'not found'."""
        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=True),
            mock.patch("pkg_defender.cli.commands.setup.install_completion"),
            mock.patch("pkg_defender.cli.commands.setup._generate_config_template"),
            mock.patch("pkg_defender.cli.commands.setup._write_config_toml"),
            mock.patch(
                "pkg_defender.cli.commands.setup.subprocess.run",
                side_effect=FileNotFoundError("No such file or directory: 'npm'"),
            ),
            mock.patch("pkg_defender.cli.commands.setup.console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.intel.intel_sync"),
        ):
            result = runner.invoke(cli, ["--ci", "setup"])

        assert result.exit_code == 0

        # All managers should show as "not found"
        not_found_calls = [str(args) for args, _ in mock_print.call_args_list if "not found" in str(args)]
        assert len(not_found_calls) >= 1

    def test_custom_db_path_uses_custom_path(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When user selects option '2' and enters a custom path, PKGD_DATABASE_PATH is set."""
        monkeypatch.delenv("PKGD_DATABASE_PATH", raising=False)

        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=True),
            mock.patch("pkg_defender.cli.commands.setup.install_completion"),
            mock.patch("pkg_defender.cli.commands.setup._generate_config_template"),
            mock.patch("pkg_defender.cli.commands.setup._write_config_toml"),
            mock.patch(
                "pkg_defender.cli.commands.setup.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, "", ""),
            ),
            mock.patch("pkg_defender.cli.commands.setup.console.print"),
            mock.patch("pkg_defender.cli.commands.setup.init_db"),
            mock.patch("pkg_defender.cli.commands.intel.intel_sync"),
            # CRITICAL: must patch _prompt_for_tokens AND _prompt_ossf_exclusion
            # to prevent interactive prompts from consuming piped input
            # before the DB location prompt runs.
            mock.patch("pkg_defender.cli.commands.setup._prompt_for_tokens"),
            mock.patch("pkg_defender.cli.commands.setup._prompt_ossf_exclusion"),
        ):
            result = runner.invoke(
                cli,
                ["setup"],
                input="2\n/custom/db/path\n",
            )

        assert result.exit_code == 0
        assert os.environ.get("PKGD_DATABASE_PATH") == "/custom/db/path"

        # Explicit cleanup: remove the env var to prevent test pollution
        # in xdist workers (os.environ is process-global).
        os.environ.pop("PKGD_DATABASE_PATH", None)
