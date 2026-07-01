"""Tests for the CLI banner module."""

from __future__ import annotations

import sys
from collections.abc import Generator
from unittest import mock

import pytest

from pkg_defender.cli import banners


@pytest.fixture(autouse=True)
def reset_width_cache() -> Generator[None, None, None]:
    """Reset the terminal width cache before each test."""
    banners.reset_width_cache()
    yield
    banners.reset_width_cache()


# ---------------------------------------------------------------------------
# Terminal Width Detection
# ---------------------------------------------------------------------------


class TestGetTerminalWidth:
    """Test terminal width detection with environment and shutil fallbacks."""

    def test_returns_columns_value_when_columns_env_var_is_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """COLUMNS env var should take priority over shutil."""
        monkeypatch.setenv("COLUMNS", "120")
        result = banners.get_terminal_width()
        assert result == 120

    def test_get_terminal_width_parses_valid_columns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Valid integer in COLUMNS env var should be parsed."""
        monkeypatch.setenv("COLUMNS", "100")
        result = banners.get_terminal_width()
        assert result == 100

    def test_get_terminal_width_invalid_columns_falls_back_to_shutil(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Invalid COLUMNS value should fall through to shutil detection."""
        monkeypatch.setenv("COLUMNS", "not-a-number")
        with mock.patch.object(banners, "shutil") as mock_shutil:
            mock_shutil.get_terminal_size.return_value.columns = 80
            result = banners.get_terminal_width()
        assert result == 80

    def test_get_terminal_width_fallback_to_shutil(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When COLUMNS is not set, should use shutil.get_terminal_size()."""
        monkeypatch.delenv("COLUMNS", raising=False)
        with mock.patch.object(banners, "shutil") as mock_shutil:
            mock_shutil.get_terminal_size.return_value.columns = 100
            result = banners.get_terminal_width()
        assert result == 100

    def test_get_terminal_width_shutil_returns_zero_fallback_to_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When shutil returns 0 columns, should use default 80."""
        monkeypatch.delenv("COLUMNS", raising=False)
        with mock.patch.object(banners, "shutil") as mock_shutil:
            mock_shutil.get_terminal_size.return_value.columns = 0
            result = banners.get_terminal_width()
        assert result == 80

    def test_get_terminal_width_shutil_raises_oserror_fallback_to_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When shutil raises OSError, should use default 80."""
        monkeypatch.delenv("COLUMNS", raising=False)
        with mock.patch.object(banners, "shutil") as mock_shutil:
            mock_shutil.get_terminal_size.side_effect = OSError("no terminal")
            result = banners.get_terminal_width()
        assert result == 80

    def test_get_terminal_width_fallback_to_80(self) -> None:
        """When no detection works, should default to 80."""
        # Clear any env vars - monkeypatch not needed since we mock both paths
        with mock.patch.dict("os.environ", {}, clear=True):
            with mock.patch.object(banners, "shutil") as mock_shutil:
                mock_shutil.get_terminal_size.side_effect = OSError("no terminal")
                result = banners.get_terminal_width()
            assert result == 80


# ---------------------------------------------------------------------------
# NO_COLOR Handling
# ---------------------------------------------------------------------------


class TestShouldUseColor:
    """Test color output preference detection."""

    def test_should_use_color_no_color_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When NO_COLOR is set, should return False (disable color)."""
        monkeypatch.setenv("NO_COLOR", "1")
        assert banners.should_use_color() is False

    def test_should_use_color_no_color_empty_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """NO_COLOR set to empty string should also disable color."""
        monkeypatch.setenv("NO_COLOR", "")
        assert banners.should_use_color() is False

    def test_should_use_color_no_color_takes_precedence(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When both NO_COLOR and FORCE_COLOR are set, NO_COLOR takes precedence.

        Per no-color.org standard, NO_COLOR has priority. FORCE_COLOR is only
        consulted when NO_COLOR is not set.
        """
        monkeypatch.setenv("NO_COLOR", "1")
        monkeypatch.setenv("FORCE_COLOR", "1")
        # NO_COLOR has priority per the standard
        assert banners.should_use_color() is False

    def test_should_use_color_force_color_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """FORCE_COLOR alone should enable color."""
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        monkeypatch.delenv("TERM", raising=False)
        # Mock stdout.isatty() to return True
        mock_stdout = mock.MagicMock()
        mock_stdout.isatty.return_value = True
        monkeypatch.setattr(sys, "stdout", mock_stdout)
        assert banners.should_use_color() is True

    def test_should_use_color_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When neither NO_COLOR nor FORCE_COLOR is set, should default to True."""
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        monkeypatch.delenv("TERM", raising=False)
        # Mock stdout.isatty() to return True
        mock_stdout = mock.MagicMock()
        mock_stdout.isatty.return_value = True
        monkeypatch.setattr(sys, "stdout", mock_stdout)
        assert banners.should_use_color() is True


# ---------------------------------------------------------------------------
# TTY Detection
# ---------------------------------------------------------------------------


class TestShouldUseColorTTY:
    """Test TTY detection in should_use_color()."""

    def test_should_use_color_disables_when_stdout_not_tty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When stdout is not a TTY, should return False."""
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        monkeypatch.delenv("TERM", raising=False)

        # Mock stdout.isatty() to return False
        mock_stdout = mock.MagicMock()
        mock_stdout.isatty.return_value = False
        monkeypatch.setattr(sys, "stdout", mock_stdout)

        assert banners.should_use_color() is False

    def test_should_use_color_enables_when_stdout_is_tty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When stdout is a TTY, should return True (unless other flags set)."""
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        monkeypatch.delenv("TERM", raising=False)

        # Mock stdout.isatty() to return True
        mock_stdout = mock.MagicMock()
        mock_stdout.isatty.return_value = True
        monkeypatch.setattr(sys, "stdout", mock_stdout)

        assert banners.should_use_color() is True

    def test_should_use_color_tty_check_after_no_color(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """NO_COLOR should still take precedence even with TTY."""
        monkeypatch.setenv("NO_COLOR", "1")

        mock_stdout = mock.MagicMock()
        mock_stdout.isatty.return_value = True
        monkeypatch.setattr(sys, "stdout", mock_stdout)

        assert banners.should_use_color() is False


# ---------------------------------------------------------------------------
# TERM=dumb Detection
# ---------------------------------------------------------------------------


class TestShouldUseColorTermDumb:
    """Test TERM=dumb detection in should_use_color()."""

    def test_should_use_color_disables_when_term_dumb(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When TERM=dumb, should return False (POSIX standard)."""
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        monkeypatch.setenv("TERM", "dumb")

        # Ensure stdout is a TTY so TTY check doesn't interfere
        mock_stdout = mock.MagicMock()
        mock_stdout.isatty.return_value = True
        monkeypatch.setattr(sys, "stdout", mock_stdout)

        assert banners.should_use_color() is False

    def test_should_use_color_term_dumb_takes_precedence_over_force_color(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """TERM=dumb should take precedence over FORCE_COLOR."""
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("FORCE_COLOR", "1")
        monkeypatch.setenv("TERM", "dumb")

        mock_stdout = mock.MagicMock()
        mock_stdout.isatty.return_value = True
        monkeypatch.setattr(sys, "stdout", mock_stdout)

        # TERM=dumb is more specific than FORCE_COLOR
        assert banners.should_use_color() is False

    def test_should_use_color_term_dumb_with_non_tty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """TERM=dumb should disable colors even when stdout is not a TTY."""
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        monkeypatch.setenv("TERM", "dumb")

        mock_stdout = mock.MagicMock()
        mock_stdout.isatty.return_value = False
        monkeypatch.setattr(sys, "stdout", mock_stdout)

        assert banners.should_use_color() is False

    def test_should_use_color_term_other_value_enables_color(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """TERM values other than 'dumb' should not affect color."""
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        monkeypatch.setenv("TERM", "xterm-256color")

        mock_stdout = mock.MagicMock()
        mock_stdout.isatty.return_value = True
        monkeypatch.setattr(sys, "stdout", mock_stdout)

        assert banners.should_use_color() is True


# ---------------------------------------------------------------------------
# Banner Width Selection
# ---------------------------------------------------------------------------


class TestSelectWidthCategory:
    """Test banner width category selection based on terminal width."""

    def test_select_width_category_no_banner_under_70(self) -> None:
        """Width < 70 should return empty string (no banner)."""
        assert banners._select_width_category(69) == ""
        assert banners._select_width_category(1) == ""
        assert banners._select_width_category(0) == ""

    def test_select_width_category_60_banner_70_to_94(self) -> None:
        """Width 70-94 should return "60" for 60-column banner."""
        assert banners._select_width_category(70) == "60"
        assert banners._select_width_category(80) == "60"
        assert banners._select_width_category(94) == "60"

    def test_select_width_category_85_banner_95_to_109(self) -> None:
        """Width 95-109 should return "85" for 85-column banner."""
        assert banners._select_width_category(95) == "85"
        assert banners._select_width_category(100) == "85"
        assert banners._select_width_category(109) == "85"

    def test_select_width_category_85_banner_95_and_up(self) -> None:
        """Width >= 95 should return "85" for 85-column banner."""
        assert banners._select_width_category(95) == "85"
        assert banners._select_width_category(110) == "85"
        assert banners._select_width_category(120) == "85"
        assert banners._select_width_category(200) == "85"


# ---------------------------------------------------------------------------
# Banner Loading
# ---------------------------------------------------------------------------


class TestGetBanner:
    """Test banner loading from filesystem."""

    def test_get_banner_returns_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When banner files exist, should return non-empty string."""
        # Mock terminal width and color to return "60" category with color
        monkeypatch.setenv("COLUMNS", "80")
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("FORCE_COLOR", raising=False)

        # Mock the banner file read
        test_banner_content = "Test Banner Content\n"
        with mock.patch.object(banners.Path, "read_text") as mock_read:
            mock_read.return_value = test_banner_content
            result = banners.get_banner()
            assert result == test_banner_content

    def test_get_banner_returns_empty_when_width_category_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When width < 70, should return empty string without file access."""
        # Set narrow terminal width
        monkeypatch.setenv("COLUMNS", "50")

        # Mock to track if file was accessed
        with mock.patch.object(banners.Path, "read_text") as mock_read:
            result = banners.get_banner()
            assert result == ""
            # Should not have tried to read file
            mock_read.assert_not_called()

    def test_get_banner_empty_for_narrow_terminal(self) -> None:
        """Width < 70 should return empty string (no banner shown)."""
        with mock.patch.object(banners, "get_terminal_width", return_value=60):
            result = banners.get_banner()
            assert result == ""

    def test_get_banner_returns_empty_on_file_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When banner file doesn't exist, should return empty string."""
        monkeypatch.setenv("COLUMNS", "80")

        with mock.patch.object(banners.Path, "read_text") as mock_read:
            mock_read.side_effect = OSError("File not found")
            result = banners.get_banner()
            assert result == ""

    def test_returns_color_variant_when_no_color_is_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When COLUMNS=80 and NO_COLOR is unset, should load color variant."""
        monkeypatch.setenv("COLUMNS", "80")
        monkeypatch.delenv("NO_COLOR", raising=False)

        # Mock stdout to appear as TTY
        import sys

        mock_stdout = mock.MagicMock()
        mock_stdout.isatty.return_value = True
        monkeypatch.setattr(sys, "stdout", mock_stdout)

        # Track what path was passed to read_text
        captured_paths: list[str] = []

        def mock_read_text(self: object, **kwargs: object) -> str:
            """Mock read_text that captures the path."""
            captured_paths.append(str(self))
            return "banner"

        with mock.patch.object(banners.Path, "read_text", mock_read_text):
            banners.get_banner()
            assert len(captured_paths) > 0
            assert "pkgd_logo_ascii_color_w60" in captured_paths[0]

    def test_returns_plain_variant_when_no_color_is_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When NO_COLOR is set, should load plain variant (no 'c' suffix)."""
        monkeypatch.setenv("COLUMNS", "80")
        monkeypatch.setenv("NO_COLOR", "1")

        # Mock stdout to appear as TTY so NO_COLOR check passes TTY test
        import sys

        mock_stdout = mock.MagicMock()
        mock_stdout.isatty.return_value = True
        monkeypatch.setattr(sys, "stdout", mock_stdout)

        # Track what path was passed to read_text
        captured_paths: list[str] = []

        def mock_read_text(self: object, **kwargs: object) -> str:
            """Mock read_text that captures the path."""
            captured_paths.append(str(self))
            return "banner"

        with mock.patch.object(banners.Path, "read_text", mock_read_text):
            banners.get_banner()
            assert len(captured_paths) > 0
            assert "pkgd_logo_ascii_plain_w60" in captured_paths[0]
            assert "pkgd_logo_ascii_color_w60" not in captured_paths[0]
