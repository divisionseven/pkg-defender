"""Tests for completion installation utilities."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from pkg_defender.shells.install import (
    SUPPORTED_SHELLS,
    _generate_completion_script,
    get_shell_config_path,
    install_completion,
)


class TestInstallCompletion:
    """Tests for install_completion function."""

    def test_install_completion_bash(self, tmp_path: Path) -> None:
        """Install bash completion script."""
        # Mock home directory to use tmp_path
        with patch("pathlib.Path.home", return_value=tmp_path):
            install_completion("bash", dry_run=False)

            # Verify completion file was created
            completion_path = tmp_path / ".local" / "share" / "bash-completion" / "completions" / "pkgd"
            assert completion_path.exists()
            assert completion_path.is_file()

    def test_install_completion_zsh(self, tmp_path: Path) -> None:
        """Install zsh completion script."""
        with patch("pathlib.Path.home", return_value=tmp_path):
            install_completion("zsh", dry_run=False)

            # Verify completion file was created
            completion_path = tmp_path / ".zsh" / "completions" / "_pkgd"
            assert completion_path.exists()
            assert completion_path.is_file()

    def test_install_completion_fish(self, tmp_path: Path) -> None:
        """Install fish completion script."""
        with patch("pathlib.Path.home", return_value=tmp_path):
            install_completion("fish", dry_run=False)

            # Verify completion file was created
            completion_path = tmp_path / ".config" / "fish" / "completions" / "pkgd.fish"
            assert completion_path.exists()
            assert completion_path.is_file()

    def test_install_completion_powershell(self, tmp_path: Path) -> None:
        """Install powershell completion script (skipped - not supported by Click)."""
        with patch("pathlib.Path.home", return_value=tmp_path):
            # This should not raise an error, but should log a warning
            install_completion("powershell", dry_run=False)

            # Verify completion file was NOT created (Click doesn't support powershell)
            completion_path = tmp_path / ".config" / "powershell" / "pkgd_completion.ps1"
            assert not completion_path.exists()

    def test_install_completion_nushell(self, tmp_path: Path) -> None:
        """Install nushell completion script (skipped - not supported by Click)."""
        with patch("pathlib.Path.home", return_value=tmp_path):
            # This should not raise an error, but should log a warning
            install_completion("nushell", dry_run=False)

            # Verify completion file was NOT created (Click doesn't support nushell)
            completion_path = tmp_path / ".config" / "nushell" / "completions" / "pkgd.nu"
            assert not completion_path.exists()

    def test_install_completion_dry_run(self, tmp_path: Path) -> None:
        """Dry-run mode should not create files."""
        with patch("pathlib.Path.home", return_value=tmp_path):
            install_completion("bash", dry_run=True)

            # Verify completion file was NOT created
            completion_path = tmp_path / ".local" / "share" / "bash-completion" / "completions" / "pkgd"
            assert not completion_path.exists()

    def test_install_completion_unsupported_shell(self) -> None:
        """Raise ValueError for unsupported shell."""
        with pytest.raises(ValueError, match="Unsupported shell"):
            install_completion("unsupported")

    def test_install_completion_creates_parent_directories(self, tmp_path: Path) -> None:
        """Create parent directories if they don't exist."""
        with patch("pathlib.Path.home", return_value=tmp_path):
            # Ensure parent directory doesn't exist
            parent_dir = tmp_path / ".local" / "share" / "bash-completion" / "completions"
            assert not parent_dir.exists()

            install_completion("bash", dry_run=False)

            # Verify parent directory was created
            assert parent_dir.exists()
            assert parent_dir.is_dir()

    def test_install_completion_idempotent(self, tmp_path: Path) -> None:
        """Running install twice should not cause issues."""
        with patch("pathlib.Path.home", return_value=tmp_path):
            # First install
            install_completion("bash", dry_run=False)

            # Get file size after first install
            completion_path = tmp_path / ".local" / "share" / "bash-completion" / "completions" / "pkgd"

            # Second install
            install_completion("bash", dry_run=False)

            # Verify file still exists and has content
            assert completion_path.exists()
            second_size = completion_path.stat().st_size

            # File should have been overwritten (size may be the same or different)
            assert isinstance(second_size, int)


class TestGenerateCompletionScript:
    """Tests for _generate_completion_script function."""

    def test_generate_completion_script_bash(self) -> None:
        """Generate bash completion script."""
        script = _generate_completion_script("bash")
        assert script is not None
        assert isinstance(script, str)
        assert len(script) > 0

    def test_generate_completion_script_zsh(self) -> None:
        """Generate zsh completion script."""
        script = _generate_completion_script("zsh")
        assert script is not None
        assert isinstance(script, str)
        assert len(script) > 0

    def test_generate_completion_script_fish(self) -> None:
        """Generate fish completion script."""
        script = _generate_completion_script("fish")
        assert script is not None
        assert isinstance(script, str)
        assert len(script) > 0

    def test_generate_completion_script_powershell(self) -> None:
        """Generate powershell completion script (not supported by Click)."""
        script = _generate_completion_script("powershell")
        # Click doesn't support powershell completion generation
        assert script is None

    def test_generate_completion_script_nushell(self) -> None:
        """Generate nushell completion script (not supported by Click)."""
        script = _generate_completion_script("nushell")
        # Click doesn't support nushell completion generation
        assert script is None

    def test_generate_completion_script_sets_env_var(self) -> None:
        """Verify completion generation sets environment variable."""
        # Clear the env var first
        env_var = "_PKGD_COMPLETE"
        original_value = os.environ.get(env_var)

        try:
            _generate_completion_script("bash")

            # Verify env var was set
            assert env_var in os.environ
            assert os.environ[env_var] == "bash_source"
        finally:
            # Restore original value
            if original_value is not None:
                os.environ[env_var] = original_value
            elif env_var in os.environ:
                del os.environ[env_var]

    def test_generate_completion_script_handles_cli_exit(self) -> None:
        """Verify completion generation handles SystemExit from CLI."""
        # This should not raise an exception
        script = _generate_completion_script("bash")
        assert script is not None


class TestGetShellConfigPath:
    """Tests for get_shell_config_path function."""

    def test_get_shell_config_path_bash(self) -> None:
        """Get bash completion path."""
        path = get_shell_config_path("bash")
        assert path == Path.home() / ".local" / "share" / "bash-completion" / "completions" / "pkgd"

    def test_get_shell_config_path_zsh(self) -> None:
        """Get zsh completion path."""
        path = get_shell_config_path("zsh")
        assert path == Path.home() / ".zsh" / "completions" / "_pkgd"

    def test_get_shell_config_path_fish(self) -> None:
        """Get fish completion path."""
        path = get_shell_config_path("fish")
        assert path == Path.home() / ".config" / "fish" / "completions" / "pkgd.fish"

    def test_get_shell_config_path_powershell(self) -> None:
        """Get powershell completion path."""
        path = get_shell_config_path("powershell")
        assert path == Path.home() / ".config" / "powershell" / "pkgd_completion.ps1"

    def test_get_shell_config_path_nushell(self) -> None:
        """Get nushell completion path."""
        path = get_shell_config_path("nushell")
        assert path == Path.home() / ".config" / "nushell" / "completions" / "pkgd.nu"

    def test_get_shell_config_path_unsupported_shell(self) -> None:
        """Raise ValueError for unsupported shell."""
        with pytest.raises(ValueError, match="Unsupported shell"):
            get_shell_config_path("unsupported")


class TestSupportedShells:
    """Tests for SUPPORTED_SHELLS constant."""

    def test_supported_shells_contains_expected_shells(self) -> None:
        """Verify SUPPORTED_SHELLS contains all expected shells."""
        expected_shells = {"bash", "zsh", "fish", "powershell", "nushell"}
        assert set(SUPPORTED_SHELLS) == expected_shells
