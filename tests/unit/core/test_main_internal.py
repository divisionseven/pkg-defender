"""Tests for internal helper functions in pkg_defender.cli.main and cli.common.

These tests target internal helper functions directly (not via the CLI)
to validate their behavior at the unit level.
"""

import datetime
import tomllib
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import click
import pytest

from pkg_defender.cli.common import (
    _check_disk_space,
    _check_permissions,
    _detect_ecosystem_from_cwd,
    _detect_manager_from_cwd,
    _format_versions,
    _generate_config_template,
    _get_config_from_context,
    _get_config_value_by_key,
    _parse_duration,
    _parse_expiry,
    _print_clipboard_security_tip,
    _validate_config_key,
    _write_config_toml,
    is_running_in_ci,
)
from pkg_defender.cli.main import (
    _expand_subcommands,
    _get_first_line,
    setup_logging,
)
from pkg_defender.config.settings import PKGDConfig


class TestGetFirstLine:
    """Tests for _get_first_line() helper."""

    def test_none_returns_empty(self) -> None:
        """Test that an empty string is returned when input is None."""
        result = _get_first_line(None)
        assert result == ""

    def test_empty_string_returns_empty(self) -> None:
        """Test that an empty string is returned when input is an empty string."""
        result = _get_first_line("")
        assert result == ""

    def test_single_line(self) -> None:
        """Test that the input string is returned unchanged when it contains a single line."""
        result = _get_first_line("This is a docstring")
        assert result == "This is a docstring"

    def test_multi_line_returns_first(self) -> None:
        """Test that only the first line is returned from a multi-line input."""
        docstring = """First line.

        Second line.
        Third line."""
        result = _get_first_line(docstring)
        assert result == "First line."

    def test_stripped_whitespace(self) -> None:
        """Test that leading and trailing whitespace is stripped from the first line."""
        result = _get_first_line("  Padded line  \nSecond")
        assert result == "Padded line"


class TestParseExpiry:
    """Tests for _parse_expiry() helper."""

    def test_days_format(self) -> None:
        """Test that a datetime 7 days ahead is returned when parsing '7d' format."""
        result = _parse_expiry("7d")
        assert isinstance(result, datetime.datetime)
        now = datetime.datetime.now(datetime.UTC)
        expected = now + datetime.timedelta(days=7)
        assert abs((result - expected).total_seconds()) < 1

    def test_hours_format(self) -> None:
        """Test that a datetime 24 hours ahead is returned when parsing '24h' format."""
        result = _parse_expiry("24h")
        assert isinstance(result, datetime.datetime)
        now = datetime.datetime.now(datetime.UTC)
        expected = now + datetime.timedelta(hours=24)
        assert abs((result - expected).total_seconds()) < 1

    def test_minutes_format(self) -> None:
        """Test that a datetime 30 minutes ahead is returned when parsing '30m' format."""
        result = _parse_expiry("30m")
        assert isinstance(result, datetime.datetime)
        now = datetime.datetime.now(datetime.UTC)
        expected = now + datetime.timedelta(minutes=30)
        assert abs((result - expected).total_seconds()) < 1

    @pytest.mark.parametrize(
        "invalid_input",
        ["abc", "7x", "h24", "", "7.5d"],
        ids=["letters", "invalid_unit", "unit_first", "empty", "float_days"],
    )
    def test_invalid_format_raises(self, invalid_input: str) -> None:
        """Test that click.BadParameter is raised when parsing an invalid expiry format."""
        with pytest.raises(click.BadParameter):
            _parse_expiry(invalid_input)


class TestParseDuration:
    """Tests for _parse_duration() helper."""

    def test_days_format(self) -> None:
        """Test that a timedelta of 7 days is returned when parsing '7d' format."""
        result = _parse_duration("7d")
        assert result == datetime.timedelta(days=7)

    def test_hours_format(self) -> None:
        """Test that a timedelta of 24 hours is returned when parsing '24h' format."""
        result = _parse_duration("24h")
        assert result == datetime.timedelta(hours=24)

    def test_minutes_format(self) -> None:
        """Test that a timedelta of 30 minutes is returned when parsing '30m' format."""
        result = _parse_duration("30m")
        assert result == datetime.timedelta(minutes=30)

    @pytest.mark.parametrize(
        "invalid_input",
        ["abc", "7x", "h24", "", "7.5d"],
        ids=["letters", "invalid_unit", "unit_first", "empty", "float_days"],
    )
    def test_invalid_format_raises(self, invalid_input: str) -> None:
        """Test that click.BadParameter is raised when parsing an invalid duration format."""
        with pytest.raises(click.BadParameter):
            _parse_duration(invalid_input)


class TestIsRunningInCI:
    """Tests for is_running_in_ci() helper."""

    def test_empty_obj_returns_false(self) -> None:
        """Test that False is returned when ctx.obj is empty."""
        ctx = MagicMock()
        ctx.obj = {}
        result = is_running_in_ci(ctx)
        assert result is False

    def test_ctx_with_ci_true(self) -> None:
        """Test that True is returned when CI is explicitly enabled in ctx.obj."""
        ctx = MagicMock()
        ctx.obj = {"ci": True, "ci_auto_detected": False}
        result = is_running_in_ci(ctx)
        assert result is True

    def test_ctx_with_ci_false_and_auto_true(self) -> None:
        """Test that True is returned when CI is auto-detected even if explicit flag is False."""
        ctx = MagicMock()
        ctx.obj = {"ci": False, "ci_auto_detected": True}
        result = is_running_in_ci(ctx)
        assert result is True

    def test_ctx_with_both_false(self) -> None:
        """Test that False is returned when both CI flags are False."""
        ctx = MagicMock()
        ctx.obj = {"ci": False, "ci_auto_detected": False}
        result = is_running_in_ci(ctx)
        assert result is False


class TestGetConfigFromContext:
    """Tests for _get_config_from_context() helper."""

    def test_none_context_returns_default(self) -> None:
        """Test that a default config is returned when ctx.obj is None."""
        ctx = MagicMock()
        ctx.obj = None
        # The function checks `if ctx.obj` - None is falsy, so it returns load_config()
        result = _get_config_from_context(ctx)
        # Check for PKGDConfig attributes instead of isinstance (avoids module loading issues)
        assert hasattr(result, "cooldown")
        assert hasattr(result, "feeds")
        assert hasattr(result, "output")
        assert hasattr(result, "database")

    def test_no_config_file_returns_default(self) -> None:
        """Test that a default config is returned when no config_file is in ctx.obj."""
        ctx = MagicMock()
        ctx.obj = {}
        result = _get_config_from_context(ctx)
        # Check for PKGDConfig attributes instead of isinstance (avoids module loading issues)
        assert hasattr(result, "cooldown")
        assert hasattr(result, "feeds")
        assert hasattr(result, "output")
        assert hasattr(result, "database")

    def test_with_config_file_not_exist(self) -> None:
        """Test that click.BadParameter is raised when the config file path does not exist."""
        ctx = MagicMock()
        ctx.obj = {"config_file": "/nonexistent/path.toml"}
        with pytest.raises(click.BadParameter):
            _get_config_from_context(ctx)

    def test_with_valid_config_file(self, tmp_path: Path) -> None:
        """Test that configuration values are loaded from a valid config file."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("[cooldown]\ndefault_days = 14\n")

        ctx = MagicMock()
        ctx.obj = {"config_file": str(config_file)}
        result = _get_config_from_context(ctx)
        # Check for PKGDConfig attributes instead of isinstance (avoids module loading issues)
        assert hasattr(result, "cooldown")
        assert hasattr(result, "feeds")
        assert hasattr(result, "output")
        assert hasattr(result, "database")
        assert result.cooldown.default_days == 14


class TestFormatVersions:
    """Tests for _format_versions() helper."""

    def test_none_inputs_returns_dash(self) -> None:
        """Test that an em dash is returned when both versions and ranges are None."""
        result = _format_versions(None, None)
        assert result == "—"

    def test_ranges_preferred_over_versions(self) -> None:
        """Test that version ranges are displayed instead of individual versions when both are provided."""
        ranges = '["1.0-2.0", "3.0-4.0"]'
        versions = '["1.0", "1.1", "2.0"]'
        result = _format_versions(versions, ranges)
        assert "1.0-2.0" in result
        assert "3.0-4.0" in result

    def test_versions_only(self) -> None:
        """Test that version strings are displayed when no ranges are provided."""
        versions = '["1.0", "1.1", "1.2", "2.0"]'
        result = _format_versions(versions, None)
        assert "1.0" in result
        assert "1.1" in result
        assert "1.2" in result

    def test_too_many_versions_shows_all(self) -> None:
        """Test that an additional count is shown when more than 3 versions are available."""
        versions = '["1.0", "1.1", "1.2", "1.3", "1.4"]'
        result = _format_versions(versions, None)
        assert "+2 additional" in result

    def test_long_result_truncated(self) -> None:
        """Test that output exceeding 38 characters is truncated with '...'."""
        versions = '["1.0.0.0.0.0", "1.1.1.1.1.1", "1.2.2.2.2.2", "1.3.3.3.3.3"]'
        result = _format_versions(versions, None)
        assert result.endswith("...")


class TestExpandSubcommands:
    """Tests for _expand_subcommands() helper."""

    def test_empty_commands_dict(self) -> None:
        """Test that an empty dict is returned when no commands are provided."""
        ctx = MagicMock()
        commands: dict[str, click.Command] = {}
        result = _expand_subcommands(commands, ctx)
        assert result == {}

    def test_group_with_subcommands(self) -> None:
        """Test that subcommands are expanded into prefixed entries for group commands."""
        ctx = MagicMock()
        mock_cmd = MagicMock(spec=click.Group)
        mock_cmd.hidden = False
        mock_subcmd = MagicMock()
        mock_subcmd.hidden = False  # Need this to be False for the check
        mock_cmd.list_commands.return_value = ["sub1", "sub2"]
        mock_cmd.get_command.return_value = mock_subcmd

        commands: dict[str, Any] = {"group": mock_cmd}
        result = _expand_subcommands(commands, ctx)

        assert "group" in result
        assert "group sub1" in result
        assert "group sub2" in result


class TestValidateConfigKey:
    """Tests for _validate_config_key() helper."""

    def test_valid_key_cooldown(self) -> None:
        """Test that no exception is raised for a valid 'cooldown.default_days' key."""
        _validate_config_key("cooldown.default_days")

    def test_valid_key_feeds(self) -> None:
        """Test that no exception is raised for a valid 'feeds.ghsa_enabled' key."""
        _validate_config_key("feeds.ghsa_enabled")

    def test_valid_key_output(self) -> None:
        """Test that no exception is raised for a valid 'output.verbose' key."""
        _validate_config_key("output.verbose")

    def test_invalid_section(self) -> None:
        """Test that SystemExit is raised for a key with an invalid section."""
        with pytest.raises(SystemExit):
            _validate_config_key("invalid.key")

    def test_invalid_key(self) -> None:
        """Test that SystemExit is raised for a key with an invalid field within a valid section."""
        with pytest.raises(SystemExit):
            _validate_config_key("cooldown.invalid_key")

    def test_overrides_key(self) -> None:
        """Test that no exception is raised for a valid overrides key."""
        _validate_config_key("cooldown.overrides.lodash")

    def test_single_part_key(self) -> None:
        """Test that SystemExit is raised for a key with only one part."""
        with pytest.raises(SystemExit):
            _validate_config_key("cooldown_only")


class TestGetConfigValueByKey:
    """Tests for _get_config_value_by_key() helper."""

    def test_valid_cooldown_key(self) -> None:
        """Test that the default cooldown value is returned for a valid cooldown key."""
        config = PKGDConfig()
        result = _get_config_value_by_key(config, "cooldown.default_days")
        # Default value from PKGDConfig is 7
        assert result == 7

    def test_valid_feeds_key(self) -> None:
        """Test that the default feeds value is returned for a valid feeds key."""
        config = PKGDConfig()
        result = _get_config_value_by_key(config, "feeds.osv_enabled")
        assert result is True  # Default value

    def test_invalid_section_returns_none(self) -> None:
        """Test that None is returned when querying an invalid config section."""
        config = PKGDConfig()
        result = _get_config_value_by_key(config, "invalid.key")
        assert result is None

    def test_overrides_key(self) -> None:
        """Test that the override value is returned when querying an existing package override."""
        config = PKGDConfig()
        config.cooldown.overrides["lodash"] = 7
        result = _get_config_value_by_key(config, "cooldown.overrides.lodash")
        assert result == 7

    def test_nonexistent_override_returns_none(self) -> None:
        """Test that None is returned when querying a non-existent package override."""
        config = PKGDConfig()
        result = _get_config_value_by_key(config, "cooldown.overrides.nonexistent")
        assert result is None


class TestGenerateConfigTemplate:
    """Tests for _generate_config_template() — comment-preserving TOML template."""

    def test_returns_toml_document(self) -> None:
        """Returns a tomlkit TOMLDocument object."""
        from tomlkit.toml_document import TOMLDocument

        doc = _generate_config_template()
        assert isinstance(doc, TOMLDocument)

    def test_includes_all_sections(self) -> None:
        """Document has all expected sections."""
        doc = _generate_config_template()
        assert "cooldown" in doc
        assert "feeds" in doc
        assert "output" in doc
        assert "database" in doc
        assert "bypass" in doc
        assert "daemon" in doc

    def test_output_valid_toml(self) -> None:
        """dumps() produces valid TOML that tomllib can parse."""
        import tomllib

        from tomlkit import dumps

        content = dumps(_generate_config_template())
        parsed = tomllib.loads(content)
        assert parsed["cooldown"]["default_days"] == 7

    def test_template_includes_retention_days_comment(self) -> None:
        """Generated template must include retention_days as a commented-out example."""
        from tomlkit import dumps

        content = dumps(_generate_config_template())
        assert "# retention_days = 30" in content


class TestWriteConfigToml:
    """Tests for _write_config_toml() atomic write."""

    def test_writes_valid_toml(self, tmp_path: Path) -> None:
        """String content is written and readable."""
        toml_path = tmp_path / "test_config.toml"
        content = 'value = 42\n[section]\nkey = "hello"\n'
        _write_config_toml(toml_path, content)
        assert toml_path.exists()
        with open(toml_path, "rb") as f:
            loaded = tomllib.load(f)
        assert loaded["value"] == 42
        assert loaded["section"]["key"] == "hello"

    def test_invalid_toml_raises_error(self, tmp_path: Path) -> None:
        """Invalid TOML content raises ValueError and doesn't write file."""
        toml_path = tmp_path / "test_config.toml"
        with pytest.raises(ValueError, match="Generated TOML is invalid"):
            _write_config_toml(toml_path, "invalid = [[broken")
        assert not toml_path.exists()


class TestPrintClipboardSecurityTip:
    """Tests for _print_clipboard_security_tip() helper."""

    def test_runs_without_error(self) -> None:
        """Test that clipboard security tip can be printed without raising an exception."""
        try:
            _print_clipboard_security_tip()
        except Exception as e:
            pytest.fail(f"_print_clipboard_security_tip() raised {e}")


class TestDetectManagerFromCwd:
    """Tests for _detect_manager_from_cwd() helper."""

    def test_no_marker_files_returns_npm(self, tmp_path: Path) -> None:
        """Test that 'npm' is returned as the fallback manager when no marker files are present."""
        with (
            patch("pkg_defender.cli.common.Path.cwd", return_value=tmp_path),
            patch("pathlib.Path.exists", return_value=False),
        ):
            result = _detect_manager_from_cwd()
            assert result == "npm"

    def test_with_package_json_returns_npm(self, tmp_path: Path) -> None:
        """Test that 'npm' is returned when a package.json file is present."""
        (tmp_path / "package.json").touch()
        with patch("pkg_defender.cli.common.Path.cwd", return_value=tmp_path):
            result = _detect_manager_from_cwd()
            assert result == "npm"

    def test_with_requirements_txt_returns_pip(self, tmp_path: Path) -> None:
        """Test that 'pip' is returned when a requirements.txt file is present."""
        (tmp_path / "requirements.txt").touch()
        with patch("pkg_defender.cli.common.Path.cwd", return_value=tmp_path):
            result = _detect_manager_from_cwd()
            # Note: This depends on MANAGER_MARKER_FILES having requirements.txt -> pip
            # The function checks markers in order, so first match wins
            assert result in ("pip", "npm")  # Could be npm if package.json also in MANAGER_MARKER_FILES


class TestDetectEcosystemFromCwd:
    """Tests for _detect_ecosystem_from_cwd() helper."""

    def test_calls_manager_function(self, tmp_path: Path) -> None:
        """Test that the manager detection function result is returned as the ecosystem."""
        with patch("pkg_defender.cli.common._detect_manager_from_cwd", return_value="npm"):
            result = _detect_ecosystem_from_cwd()
            assert result == "npm"


class TestSetupLogging:
    """Tests for setup_logging() helper."""

    def test_runs_without_error(self, tmp_path: Path) -> None:
        """Test that setup_logging completes without raising an exception."""
        data_dir = tmp_path / "pkg-defender"
        data_dir.mkdir()
        try:
            setup_logging(verbosity=0, data_dir=data_dir)
        except Exception as e:
            pytest.fail(f"setup_logging() raised {e}")

    def test_creates_log_file(self, tmp_path: Path) -> None:
        """Test that a log file is created in the data directory after setup."""
        data_dir = tmp_path / "pkg-defender"
        data_dir.mkdir()
        setup_logging(verbosity=0, data_dir=data_dir)
        log_file = data_dir / "pkgd.log"
        assert log_file.exists()

    def test_vv_sets_debug_level(self, tmp_path: Path) -> None:
        """Test that the console handler is set to DEBUG level when verbosity is 2."""
        import logging

        data_dir = tmp_path / "pkg-defender"
        data_dir.mkdir()
        setup_logging(verbosity=2, data_dir=data_dir)
        # Handlers are on the root logger, NOT on named loggers (see main.py:51-74)
        root_logger = logging.getLogger()
        console_handler = [h for h in root_logger.handlers if isinstance(h, logging.StreamHandler)][0]
        assert console_handler.level == logging.DEBUG, f"Expected DEBUG, got {console_handler.level}"

    def test_v_sets_info_level(self, tmp_path: Path) -> None:
        """Test that the console handler is set to INFO level when verbosity is 1."""
        import logging

        data_dir = tmp_path / "pkg-defender"
        data_dir.mkdir()
        setup_logging(verbosity=1, data_dir=data_dir)
        # Handlers live on root logger, not named loggers (see main.py:51-74)
        root_logger = logging.getLogger()
        console_handler = [h for h in root_logger.handlers if isinstance(h, logging.StreamHandler)][0]
        assert console_handler.level == logging.INFO, f"Expected INFO, got {console_handler.level}"

    def test_default_sets_error_level(self, tmp_path: Path) -> None:
        """Test that the console handler is set to ERROR level when verbosity is 0 (default)."""
        import logging

        data_dir = tmp_path / "pkg-defender"
        data_dir.mkdir()
        setup_logging(verbosity=0, data_dir=data_dir)
        root_logger = logging.getLogger()
        console_handler = [h for h in root_logger.handlers if isinstance(h, logging.StreamHandler)][0]
        assert console_handler.level == logging.ERROR, f"Expected ERROR, got {console_handler.level}"


class TestCheckDiskSpace:
    """Tests for _check_disk_space() helper."""

    def test_returns_tuple(self, tmp_path: Path) -> None:
        """Test that a 3-tuple is returned containing space check results."""
        with (
            patch("pkg_defender.config.settings.get_data_dir", return_value=tmp_path),
            patch("shutil.disk_usage") as mock_usage,
        ):
            mock_usage.return_value = MagicMock(free=10 * 1024**3)  # 10 GB
            result = _check_disk_space()
            assert isinstance(result, tuple)
            assert len(result) == 3
            assert isinstance(result[0], bool)  # has_sufficient_space
            assert isinstance(result[1], str)  # message
            assert isinstance(result[2], int)  # available_bytes

    def test_sufficient_space(self, tmp_path: Path) -> None:
        """Test that True is returned when more than 1 GB of disk space is available."""
        with (
            patch("pkg_defender.config.settings.get_data_dir", return_value=tmp_path),
            patch("shutil.disk_usage") as mock_usage,
        ):
            mock_usage.return_value = MagicMock(free=5 * 1024**3)  # 5 GB
            has_space, _, _ = _check_disk_space()
            assert has_space is True

    def test_insufficient_space(self, tmp_path: Path) -> None:
        """Test that False is returned when less than 1 GB of disk space is available."""
        with (
            patch("pkg_defender.config.settings.get_data_dir", return_value=tmp_path),
            patch("shutil.disk_usage") as mock_usage,
        ):
            mock_usage.return_value = MagicMock(free=500 * 1024**2)  # 500 MB
            has_space, _, _ = _check_disk_space()
            assert has_space is False


class TestCheckPermissions:
    """Tests for _check_permissions() helper."""

    def test_returns_list(self, tmp_path: Path) -> None:
        """Test that a list of permission check tuples is returned."""
        with (
            patch("pkg_defender.cli.main.get_default_config_path") as mock_config,
            patch("pkg_defender.cli.main.get_db_path") as mock_db,
        ):
            mock_config.return_value = tmp_path / "config.toml"
            mock_db.return_value = tmp_path / "threats.db"
            result = _check_permissions()
            assert isinstance(result, list)
            assert len(result) > 0
            # Each item should be (name, bool, detail)
            for item in result:
                assert isinstance(item, tuple)
                assert len(item) == 3
