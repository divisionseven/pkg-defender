"""Tests for shell detection utilities."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from pkg_defender.shells.detect import (
    SUPPORTED_SHELLS,
    detect_shell,
    get_shell_config_path,
    get_shell_executable,
    is_shell_installed,
)


class TestDetectShell:
    """Tests for detect_shell function."""

    def test_detect_shell_zsh(self) -> None:
        """Detect zsh from SHELL environment variable."""
        with patch.dict(os.environ, {"SHELL": "/bin/zsh"}):
            assert detect_shell() == "zsh"

    def test_detect_shell_bash(self) -> None:
        """Detect bash from SHELL environment variable."""
        with patch.dict(os.environ, {"SHELL": "/bin/bash"}):
            assert detect_shell() == "bash"

    def test_detect_shell_fish(self) -> None:
        """Detect fish from SHELL environment variable."""
        with patch.dict(os.environ, {"SHELL": "/usr/bin/fish"}):
            assert detect_shell() == "fish"

    def test_detect_shell_powershell(self) -> None:
        """Detect powershell from SHELL environment variable."""
        with patch.dict(os.environ, {"SHELL": "/usr/bin/pwsh"}):
            assert detect_shell() == "powershell"

    def test_detect_shell_nushell(self) -> None:
        """Detect nushell from SHELL environment variable."""
        with patch.dict(os.environ, {"SHELL": "/usr/bin/nu"}):
            assert detect_shell() == "nushell"

    def test_detect_shell_unsupported_fallback_to_bash(self) -> None:
        """Fallback to bash for unsupported shells."""
        with patch.dict(os.environ, {"SHELL": "/bin/sh"}):
            assert detect_shell() == "bash"

    def test_detect_shell_no_shell_env_var(self) -> None:
        """Fallback to bash when SHELL environment variable is not set."""
        with patch.dict(os.environ, {}, clear=True):
            assert detect_shell() == "bash"

    def test_detect_shell_local_bin_path(self) -> None:
        """Detect shell from /usr/local/bin path."""
        with patch.dict(os.environ, {"SHELL": "/usr/local/bin/zsh"}):
            assert detect_shell() == "zsh"


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


class TestGetShellExecutable:
    """Tests for get_shell_executable function."""

    def test_get_shell_executable_powershell(self) -> None:
        """Get powershell executable name."""
        assert get_shell_executable("powershell") == "pwsh"

    def test_get_shell_executable_nushell(self) -> None:
        """Get nushell executable name."""
        assert get_shell_executable("nushell") == "nu"


class TestIsShellInstalled:
    """Tests for is_shell_installed function."""

    def test_is_shell_installed_nonexistent(self) -> None:
        """Check if nonexistent shell is installed (should be False)."""
        assert is_shell_installed("nonexistent_shell_12345") is False

    def test_returns_true_when_shutil_which_finds_shell(self) -> None:
        """Verify is_shell_installed uses shutil.which correctly."""
        # Test with a shell that should exist
        with patch("shutil.which", return_value="/bin/bash"):
            assert is_shell_installed("bash") is True

        # Test with a shell that doesn't exist
        with patch("shutil.which", return_value=None):
            assert is_shell_installed("bash") is False


class TestSupportedShells:
    """Tests for SUPPORTED_SHELLS constant."""

    def test_supported_shells_contains_expected_shells(self) -> None:
        """Verify SUPPORTED_SHELLS contains all expected shells."""
        expected_shells = {"bash", "zsh", "fish", "powershell", "nushell"}
        assert set(SUPPORTED_SHELLS) == expected_shells
