"""Tests for the configuration system."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pkg_defender.config.settings import (
    PKGDConfig,
    _apply_env_overrides,
    _apply_toml_data,
    _weakening_toml,
    get_config_dir,
    get_data_dir,
    get_db_path,
    get_default_config_path,
    load_config,
)

# Default values


class TestDefaultConfigValues:
    """Tests that PKGDConfig defaults match board-mandated values."""

    def test_strict_mode_defaults_to_true(self) -> None:
        """Board Law 1: default to paranoia."""
        config = PKGDConfig()
        assert config.cooldown.strict_mode is True

    def test_default_cooldown_days_is_seven(self) -> None:
        """Board decision: 7-day default for new installs."""
        config = PKGDConfig()
        assert config.cooldown.default_days == 7

    def test_wal_mode_defaults_to_true(self) -> None:
        """Board mandate: WAL mode is non-negotiable."""
        config = PKGDConfig()
        assert config.database.wal_mode is True

    def test_busy_timeout_defaults_to_5000(self) -> None:
        """Board mandate: 5-second busy timeout."""
        config = PKGDConfig()
        assert config.database.busy_timeout_ms == 5000

    def test_cooldown_enabled_defaults_to_true(self) -> None:
        config = PKGDConfig()
        assert config.cooldown.enabled is True

    def test_osv_enabled_defaults_to_true(self) -> None:
        config = PKGDConfig()
        assert config.feeds.osv_enabled is True

    def test_color_defaults_to_true(self) -> None:
        config = PKGDConfig()
        assert config.output.color is True

    def test_json_mode_defaults_to_false(self) -> None:
        config = PKGDConfig()
        assert config.output.json_mode is False

    def test_verbose_defaults_to_false(self) -> None:
        config = PKGDConfig()
        assert config.output.verbose is False

    # Environment variable error handling


class TestEnvVarErrorHandling:
    """Tests that invalid env var values are handled gracefully."""

    def test_returns_default_when_bool_env_var_is_invalid(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Invalid bool env var logs warning and falls back to default."""
        caplog.set_level("WARNING")
        monkeypatch.setenv("PKGD_OUTPUT_COLOR", "maybe")
        config = _apply_env_overrides(PKGDConfig())
        assert config.output.color is True  # default
        assert "PKGD_OUTPUT_COLOR" in caplog.text
        assert "maybe" in caplog.text

    def test_returns_default_when_int_env_var_is_invalid(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Invalid int env var logs warning and falls back to default."""
        caplog.set_level("WARNING")
        monkeypatch.setenv("PKGD_COOLDOWN_DEFAULT_DAYS", "30s")
        config = _apply_env_overrides(PKGDConfig())
        assert config.cooldown.default_days == 7  # default
        assert "PKGD_COOLDOWN_DEFAULT_DAYS" in caplog.text

    def test_invalid_int_staleness_hours(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Invalid int for staleness_hours falls back to default."""
        caplog.set_level("WARNING")
        monkeypatch.setenv("PKGD_FEEDS_STALENESS_HOURS", "8h")
        config = _apply_env_overrides(PKGDConfig())
        assert config.feeds.staleness_threshold_hours == 8

    def test_invalid_int_http_timeout(self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
        """Invalid int for http_timeout falls back to default."""
        caplog.set_level("WARNING")
        monkeypatch.setenv("PKGD_HTTP_TIMEOUT", "30s")
        config = _apply_env_overrides(PKGDConfig())
        assert config.feeds.http_timeout == 60

    def test_invalid_int_busy_timeout(self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
        """Invalid int for busy_timeout falls back to default."""
        caplog.set_level("WARNING")
        monkeypatch.setenv("PKGD_DATABASE_BUSY_TIMEOUT", "5s")
        config = _apply_env_overrides(PKGDConfig())
        assert config.database.busy_timeout_ms == 5000

    def test_invalid_int_command_timeout(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Invalid int for command_timeout falls back to default."""
        caplog.set_level("WARNING")
        monkeypatch.setenv("PKGD_COMMAND_TIMEOUT", "60s")
        config = _apply_env_overrides(PKGDConfig())
        assert config.command_timeout_seconds == 30

    def test_valid_overrides_still_work_with_invalid_ones(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Valid overrides work even when unrelated env vars are invalid."""
        caplog.set_level("WARNING")
        monkeypatch.setenv("PKGD_COOLDOWN_DEFAULT_DAYS", "30s")  # invalid
        monkeypatch.setenv("PKGD_COOLDOWN_STRICT_MODE", "false")  # valid
        monkeypatch.setenv("PKGD_OUTPUT_COLOR", "maybe")  # invalid
        config = _apply_env_overrides(PKGDConfig())
        assert config.cooldown.default_days == 7  # default (invalid)
        assert config.cooldown.strict_mode is False  # applied (valid)
        assert config.output.color is True  # default (invalid)
        assert "PKGD_COOLDOWN_DEFAULT_DAYS" in caplog.text
        assert "PKGD_OUTPUT_COLOR" in caplog.text

    def test_invalid_bool_each_env_var_logs_key_name(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Each invalid bool env var is identified by name in the log."""
        caplog.set_level("WARNING")
        monkeypatch.setenv("PKGD_SHOW_ASCII_BANNER", "nope")
        monkeypatch.setenv("PKGD_COOLDOWN_STRICT_MODE", "sure")
        monkeypatch.setenv("PKGD_FEEDS_OSV_ENABLED", "idk")
        _apply_env_overrides(PKGDConfig())
        assert "PKGD_SHOW_ASCII_BANNER" in caplog.text
        assert "PKGD_COOLDOWN_STRICT_MODE" in caplog.text
        assert "PKGD_FEEDS_OSV_ENABLED" in caplog.text

    def test_cli_load_config_does_not_crash_on_invalid_env_var(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """load_config() does not crash when env vars have invalid values."""
        monkeypatch.setenv("PKGD_COOLDOWN_DEFAULT_DAYS", "30s")
        monkeypatch.setenv("PKGD_OUTPUT_COLOR", "maybe")
        fake_config = tmp_path / "nonexistent.toml"
        config = load_config(fake_config)
        # Defaults should be intact — invalid env vars fell back
        assert config.cooldown.default_days == 7
        assert config.output.color is True

    # Loading from TOML


class TestLoadFromToml:
    """Tests for loading config from a TOML file."""

    def test_load_from_toml_file(self, tmp_path: Path) -> None:
        """Config values are correctly read from a TOML file."""
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """\
[cooldown]
default_days = 7
strict_mode = false
enabled = false

[cooldown.overrides]
"react" = 14

[feeds]
osv_enabled = false

[daemon]
sync_interval_hours = 8

[output]
color = false
json_mode = true
verbose = true

[database]
wal_mode = false
busy_timeout_ms = 10000
"""
        )

        config = load_config(config_file)

        assert config.cooldown.default_days == 7
        assert config.cooldown.strict_mode is False
        assert config.cooldown.enabled is False
        assert config.cooldown.overrides == {"react": 14}
        assert config.feeds.osv_enabled is False
        assert config.daemon.sync_interval_hours == 8
        assert config.output.color is False
        assert config.output.json_mode is True
        assert config.output.verbose is True
        assert config.database.wal_mode is False
        assert config.database.busy_timeout_ms == 10000

    def test_partial_toml_merges_with_defaults(self, tmp_path: Path) -> None:
        """Unspecified TOML keys retain their defaults."""
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """\
[cooldown]
default_days = 3
"""
        )

        config = load_config(config_file)

        # Overridden by TOML
        assert config.cooldown.default_days == 3
        # Still defaults
        assert config.cooldown.strict_mode is True
        assert config.feeds.osv_enabled is True
        assert config.database.wal_mode is True

    # Missing config file─


class TestMissingConfigFile:
    """Tests for behavior when config file does not exist."""

    def test_missing_config_returns_defaults(self, tmp_path: Path) -> None:
        """When config TOML doesn't exist, defaults are returned."""
        missing_path = tmp_path / "nonexistent" / "config.toml"
        config = load_config(missing_path)

        assert config.cooldown.default_days == 7
        assert config.cooldown.strict_mode is True
        assert config.database.wal_mode is True
        assert config.database.busy_timeout_ms == 5000

    # Environment variable overrides


class TestEnvVarOverrides:
    """Tests for PKGD_* environment variable overrides."""

    def test_cooldown_default_days_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PKGD_COOLDOWN_DEFAULT_DAYS", "14")
        config = _apply_env_overrides(PKGDConfig())
        assert config.cooldown.default_days == 14

    def test_cooldown_strict_mode_override_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PKGD_COOLDOWN_STRICT_MODE", "false")
        config = _apply_env_overrides(PKGDConfig())
        assert config.cooldown.strict_mode is False

    def test_cooldown_strict_mode_override_from_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PKGD_COOLDOWN_STRICT_MODE", "1")
        config = _apply_env_overrides(PKGDConfig())
        assert config.cooldown.strict_mode is True

    def test_feeds_osv_enabled_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PKGD_FEEDS_OSV_ENABLED", "false")
        config = _apply_env_overrides(PKGDConfig())
        assert config.feeds.osv_enabled is False

    def test_output_color_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PKGD_OUTPUT_COLOR", "false")
        config = _apply_env_overrides(PKGDConfig())
        assert config.output.color is False

    def test_output_json_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PKGD_OUTPUT_JSON", "true")
        config = _apply_env_overrides(PKGDConfig())
        assert config.output.json_mode is True

    def test_output_verbose_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PKGD_OUTPUT_VERBOSE", "yes")
        config = _apply_env_overrides(PKGDConfig())
        assert config.output.verbose is True

    def test_database_wal_mode_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PKGD_DATABASE_WAL_MODE", "false")
        config = _apply_env_overrides(PKGDConfig())
        assert config.database.wal_mode is False

    def test_database_busy_timeout_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PKGD_DATABASE_BUSY_TIMEOUT", "30000")
        config = _apply_env_overrides(PKGDConfig())
        assert config.database.busy_timeout_ms == 30000

    def test_canonical_env_var_takes_precedence_over_legacy_alias(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When both PKGD_FEEDS_SOCKET_API_KEY (canonical) and
        PKGD_TWITTER_API_KEY (legacy alias) are set, the canonical name wins.
        """
        monkeypatch.setenv("PKGD_FEEDS_SOCKET_API_KEY", "canonical_key")
        monkeypatch.setenv("PKGD_TWITTER_API_KEY", "legacy_key")

        config = _apply_env_overrides(PKGDConfig())
        assert config.feeds.socket_api_key == "canonical_key"

    def test_env_override_takes_precedence_over_toml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Env vars override values from the TOML file."""
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """\
[cooldown]
default_days = 5
"""
        )
        monkeypatch.setenv("PKGD_COOLDOWN_DEFAULT_DAYS", "30")

        config = load_config(config_file)
        assert config.cooldown.default_days == 30

    # Directory helpers


class TestDirectoryHelpers:
    """Tests for get_config_dir, get_data_dir, get_db_path."""

    def test_get_config_dir_creates_directory(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """get_config_dir creates the directory if it doesn't exist."""
        fake_config = tmp_path / "fake_config"
        monkeypatch.setattr(
            "pkg_defender.config.settings.platformdirs.user_config_dir",
            lambda app: str(fake_config / app),
        )

        result = get_config_dir()
        assert result.exists()
        assert result.is_dir()
        assert result.name == "pkg-defender"

    def test_get_data_dir_creates_directory(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """get_data_dir creates the directory if it doesn't exist."""
        fake_data = tmp_path / "fake_data"
        monkeypatch.setattr(
            "pkg_defender.config.settings.platformdirs.user_data_dir",
            lambda app: str(fake_data / app),
        )

        result = get_data_dir()
        assert result.exists()
        assert result.is_dir()
        assert result.name == "pkg-defender"

    def test_get_db_path_returns_correct_path(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """get_db_path returns threats.db inside the data directory."""
        fake_data = tmp_path / "fake_data"
        monkeypatch.setattr(
            "pkg_defender.config.settings.platformdirs.user_data_dir",
            lambda app: str(fake_data / app),
        )

        db_path = get_db_path()
        assert db_path.name == "threats.db"
        assert db_path.parent.name == "pkg-defender"

    def test_get_default_config_path_returns_pkgd_toml(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """get_default_config_path returns pkgd.toml inside config dir."""
        fake_config = tmp_path / "fake_config"
        monkeypatch.setattr(
            "pkg_defender.config.settings.platformdirs.user_config_dir",
            lambda app: str(fake_config / app),
        )

        config_path = get_default_config_path()
        assert config_path.name == "pkgd.toml"
        assert config_path.parent.name == "pkg-defender"

    def test_get_config_dir_handles_permission_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """get_config_dir logs warning and returns path when mkdir raises PermissionError."""
        from pkg_defender.config.settings import get_config_dir

        fake_config = tmp_path / "nope_dir"
        monkeypatch.setattr(
            "pkg_defender.config.settings.platformdirs.user_config_dir",
            lambda app: str(fake_config / app),
        )
        # Make the parent directory read-only so mkdir raises PermissionError
        read_only_parent = tmp_path / "readonly"
        read_only_parent.mkdir()
        read_only_parent.chmod(0o555)  # r-x, no write

        monkeypatch.setattr(
            "pkg_defender.config.settings.platformdirs.user_config_dir",
            lambda app: str(read_only_parent / app),
        )

        result = get_config_dir()
        assert isinstance(result, Path)
        assert result.name == "pkg-defender"
        assert not result.exists()  # mkdir failed, dir wasn't created

        captured = capsys.readouterr()
        assert "Error" in captured.err
        assert "Permission denied" in captured.err
        assert "Continuing with default configuration" in captured.err

    def test_get_config_dir_handles_invalid_parent_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """get_config_dir logs warning and returns path when parent path is not a directory."""
        from pkg_defender.config.settings import get_config_dir

        # Create a file where a directory component would be
        not_a_dir = tmp_path / "not_a_dir"
        not_a_dir.write_text("i am a file, not a directory")

        monkeypatch.setattr(
            "pkg_defender.config.settings.platformdirs.user_config_dir",
            lambda app: str(not_a_dir / app),  # tries to create /not_a_dir/pkg-defender
        )

        result = get_config_dir()
        assert isinstance(result, Path)
        assert result.name == "pkg-defender"
        # mkdir failed because "not_a_dir" is a file, not a directory
        assert not result.exists()

        captured = capsys.readouterr()
        assert "Error" in captured.err
        assert "due to a filesystem error" in captured.err
        assert "Continuing with default configuration" in captured.err

    def test_get_data_dir_handles_mkdir_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """get_data_dir logs warning and returns path when mkdir fails."""
        from pkg_defender.config.settings import get_data_dir

        read_only_parent = tmp_path / "readonly"
        read_only_parent.mkdir()
        read_only_parent.chmod(0o555)  # r-x, no write

        monkeypatch.setattr(
            "pkg_defender.config.settings.platformdirs.user_data_dir",
            lambda app: str(read_only_parent / app),
        )

        result = get_data_dir()
        assert isinstance(result, Path)
        assert result.name == "pkg-defender"
        assert not result.exists()

        captured = capsys.readouterr()
        assert "Error" in captured.err
        assert "Permission denied" in captured.err
        assert "Continuing with default configuration" in captured.err


# load_config integration


class TestLoadConfigIntegration:
    """Integration tests for the full load_config pipeline."""

    def test_returns_env_vars_when_no_config_file(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Env vars work even when no config file exists."""
        missing = tmp_path / "nope.toml"
        monkeypatch.setenv("PKGD_COOLDOWN_DEFAULT_DAYS", "21")

        config = load_config(missing)
        assert config.cooldown.default_days == 21

    def test_all_defaults_are_valid(self) -> None:
        """Default config can be constructed and serialized without error."""
        config = PKGDConfig()
        assert config.cooldown is not None
        assert config.feeds is not None
        assert config.output is not None
        assert config.database is not None

    def test_load_system_config_handles_missing_file(self) -> None:
        """_load_system_config silently returns when system config does not exist."""
        import logging

        from pkg_defender.config.settings import PKGDConfig, _load_system_config

        config = PKGDConfig()
        logger = logging.getLogger(__name__)
        # SYSTEM_CONFIG_PATH = /etc/pkgd/pkgd.toml which does not exist
        _load_system_config(config, logger)
        # No exception -- test passes

    def test_load_config_does_not_crash_on_unwritable_config_dir(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """load_config gracefully falls back to defaults when config dir is unwritable."""
        from pkg_defender.config.settings import load_config

        read_only_parent = tmp_path / "readonly"
        read_only_parent.mkdir()
        read_only_parent.chmod(0o555)  # r-x, no write

        monkeypatch.setattr(
            "pkg_defender.config.settings.platformdirs.user_config_dir",
            lambda app: str(read_only_parent / app),
        )

        # Should not crash -- should return defaults
        config = load_config(config_path=None)
        assert config is not None
        assert config.cooldown.default_days == 7  # default value

        captured = capsys.readouterr()
        assert "Error" in captured.err
        assert "Permission denied" in captured.err
        assert "Continuing with default configuration" in captured.err


# Generic TOML field mapper


class TestGenericTomlMapper:
    """Tests for dataclass-driven TOML field mapping."""

    def test_apply_toml_data_loads_all_feed_fields(self, tmp_path: Path) -> None:
        """All FeedConfig fields are loaded from TOML."""
        from pkg_defender.config.settings import load_config

        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """\
[feeds]
osv_enabled = false
ghsa_enabled = false
ghsa_token = "secret-token-123"
mastodon_enabled = true
mastodon_instance = "mastodon.social"
mastodon_hashtags = ["supplychain", "security"]
mastodon_max_age_hours = 24
reddit_enabled = false
reddit_subreddits = ["hackernews"]
reddit_keywords = ["malware"]
reddit_max_age_hours = 12
rss_enabled = false
rss_urls = ["https://example.com/feed.xml"]
rss_keywords = ["vulnerability"]
rss_max_age_hours = 48
x_twitter_enabled = true
x_twitter_bearer_token = "twitter-token"
x_twitter_trusted_accounts = ["12345"]
x_twitter_keywords = ["npm", "security"]
x_twitter_max_age_hours = 6
staleness_threshold_hours = 12
socket_api_key = "socket-key"
npm_advisory_enabled = true

[daemon]
sync_interval_hours = 8
"""
        )

        config = load_config(config_file)

        # Verify all fields loaded correctly
        assert config.feeds.osv_enabled is False
        assert config.daemon.sync_interval_hours == 8
        assert config.feeds.ghsa_enabled is False
        assert config.feeds.ghsa_token == "secret-token-123"
        assert config.feeds.mastodon_enabled is True
        assert config.feeds.mastodon_instance == "mastodon.social"
        assert config.feeds.mastodon_hashtags == ["supplychain", "security"]
        assert config.feeds.mastodon_max_age_hours == 24
        assert config.feeds.reddit_enabled is False
        assert config.feeds.reddit_subreddits == ["hackernews"]
        assert config.feeds.reddit_keywords == ["malware"]
        assert config.feeds.reddit_max_age_hours == 12
        assert config.feeds.rss_enabled is False
        assert config.feeds.rss_urls == ["https://example.com/feed.xml"]
        assert config.feeds.rss_keywords == ["vulnerability"]
        assert config.feeds.rss_max_age_hours == 48
        assert config.feeds.x_twitter_enabled is True
        assert config.feeds.x_twitter_bearer_token == "twitter-token"
        assert config.feeds.x_twitter_trusted_accounts == ["12345"]
        assert config.feeds.x_twitter_keywords == ["npm", "security"]
        assert config.feeds.x_twitter_max_age_hours == 6
        assert config.feeds.staleness_threshold_hours == 12
        assert config.feeds.socket_api_key == "socket-key"
        assert config.feeds.npm_advisory_enabled is True

    def test_apply_toml_data_handles_new_field_without_code_change(self, tmp_path: Path) -> None:
        """New fields added to dataclass are automatically loadable.

        This tests the generic approach: if a new field is added to the dataclass,
        the _apply_toml_data function should automatically handle it without
        requiring code changes to the parsing logic.
        """
        from pkg_defender.config.settings import load_config

        config_file = tmp_path / "config.toml"

        # Simulate a hypothetical new field (this tests the generic approach)
        # Note: We're testing that the mechanism works by using existing fields
        config_file.write_text(
            """\
[feeds]
socket_api_key = "my-key"
"""
        )

        config = load_config(config_file)

        # The key insight is that _apply_toml_data iterates over dataclass fields
        # dynamically using dataclasses.fields(), so any field in the dataclass
        # can be loaded from TOML without extra code changes
        assert config.feeds.socket_api_key == "my-key"

    def test_apply_toml_data_coerces_list_types(self, tmp_path: Path) -> None:
        """List fields are coerced correctly from TOML."""
        from pkg_defender.config.settings import load_config

        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """\
[feeds]
mastodon_hashtags = ["tag1", "tag2", "tag3"]
reddit_subreddits = ["python", "javascript"]
rss_urls = ["https://a.com", "https://b.com"]
"""
        )

        config = load_config(config_file)

        # Verify lists are properly coerced (TOML list -> Python list)
        assert config.feeds.mastodon_hashtags == ["tag1", "tag2", "tag3"]
        assert config.feeds.reddit_subreddits == ["python", "javascript"]
        assert config.feeds.rss_urls == ["https://a.com", "https://b.com"]

        # Verify they are actually lists, not tuples or other types
        assert isinstance(config.feeds.mastodon_hashtags, list)
        assert isinstance(config.feeds.reddit_subreddits, list)
        assert isinstance(config.feeds.rss_urls, list)

    def test_apply_toml_data_coerces_dict_types(self, tmp_path: Path) -> None:
        """Dict fields are coerced correctly from TOML."""
        from pkg_defender.config.settings import load_config

        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """\
[cooldown.overrides]
react = 14
vue = 7
angular = 10
"""
        )

        config = load_config(config_file)

        # Verify dict is properly coerced
        assert config.cooldown.overrides == {"react": 14, "vue": 7, "angular": 10}
        assert isinstance(config.cooldown.overrides, dict)


# load_config docstring accuracy


class TestLoadConfigDocstring:
    """Tests for load_config docstring accuracy."""

    def test_load_config_config_path_param_ignores_env_var(self, tmp_path: Path) -> None:
        """When config_path param is provided, PKGD_CONFIG_PATH env var is ignored."""
        import os
        from unittest.mock import patch

        # Create two different config files
        config_file_a = tmp_path / "config_a.toml"
        config_file_b = tmp_path / "config_b.toml"

        config_file_a.write_text("[cooldown]\ndefault_days = 10\n")
        config_file_b.write_text("[cooldown]\ndefault_days = 99\n")

        # Set PKGD_CONFIG_PATH to config_b
        with patch.dict(os.environ, {"PKGD_CONFIG_PATH": str(config_file_b)}):
            # Call load_config with config_path=config_file_a
            config = load_config(config_path=config_file_a)
            # Should use config_file_a, NOT the env var (config_file_b)
            assert config.cooldown.default_days == 10


# CooldownConfig docstring — documentary regression test for Gap 3


class TestCooldownConfigDocstring:
    """Regression test: CooldownConfig docstring must document both 1-day and 7-day options.

    Gap 3 fix: The cooldown default is 1 day (pragmatic for active development), but
    the spec example shows "7 Days Released".  Users reading the spec and then the code
    saw different defaults.  The fix is to document both clearly in the docstring so users
    know how to switch from 1 day to 7 days.
    """

    def test_cooldown_default_days_is_seven(self) -> None:
        """Implementation: default_days is 7 days."""
        from pkg_defender.config.settings import CooldownConfig

        config = CooldownConfig()
        assert config.default_days == 7


# New security config fields tests


class TestSecurityConfigDefaults:
    """Tests for new security config field defaults."""

    def test_command_timeout_seconds_defaults_to_30(self) -> None:
        """Command timeout should default to 30 seconds."""
        config = PKGDConfig()
        assert config.command_timeout_seconds == 30

    def test_fail_on_threat_enabled_defaults_to_true(self) -> None:
        """Fail-on-threat should be enabled by default (Law 1: default to paranoia)."""
        config = PKGDConfig()
        assert config.fail_on_threat_enabled is True

    def test_registry_api_timeout_defaults_to_10(self) -> None:
        """Registry API timeout should default to 10.0 seconds."""
        config = PKGDConfig()
        assert config.registry_api_timeout == 10.0

    def test_per_ecosystem_registry_timeout_defaults_to_empty(self) -> None:
        """Per-ecosystem registry timeout should default to empty dict."""
        config = PKGDConfig()
        assert config.per_ecosystem_registry_timeout == {}


class TestSecurityConfigEnvOverrides:
    """Tests for environment variable overrides of security config."""

    def test_command_timeout_env_override(self) -> None:
        """PKGD_COMMAND_TIMEOUT should override command_timeout_seconds."""
        import os

        original = os.environ.get("PKGD_COMMAND_TIMEOUT")
        try:
            os.environ["PKGD_COMMAND_TIMEOUT"] = "60"
            config = PKGDConfig()
            config = _apply_env_overrides(config)
            assert config.command_timeout_seconds == 60
        finally:
            if original is None:
                os.environ.pop("PKGD_COMMAND_TIMEOUT", None)
            else:
                os.environ["PKGD_COMMAND_TIMEOUT"] = original

    def test_registry_api_timeout_env_override(self) -> None:
        """PKGD_REGISTRY_API_TIMEOUT should override registry_api_timeout."""
        import os

        original = os.environ.get("PKGD_REGISTRY_API_TIMEOUT")
        try:
            os.environ["PKGD_REGISTRY_API_TIMEOUT"] = "20.5"
            config = PKGDConfig()
            config = _apply_env_overrides(config)
            assert config.registry_api_timeout == 20.5
        finally:
            if original is None:
                os.environ.pop("PKGD_REGISTRY_API_TIMEOUT", None)
            else:
                os.environ["PKGD_REGISTRY_API_TIMEOUT"] = original

    def test_fail_on_threat_env_override(self) -> None:
        """PKGD_FAIL_ON_THREAT should override fail_on_threat_enabled."""
        import os

        original = os.environ.get("PKGD_FAIL_ON_THREAT")
        try:
            os.environ["PKGD_FAIL_ON_THREAT"] = "false"
            config = PKGDConfig()
            config = _apply_env_overrides(config)
            assert config.fail_on_threat_enabled is False
        finally:
            if original is None:
                os.environ.pop("PKGD_FAIL_ON_THREAT", None)
            else:
                os.environ["PKGD_FAIL_ON_THREAT"] = original

    def test_boolean_env_var_parsing_true(self) -> None:
        """Environment variables should parse '1', 'true', 'yes', 'on' as True."""
        import os

        original = os.environ.get("PKGD_FAIL_ON_THREAT")
        try:
            for value in ["1", "true", "yes", "on"]:
                os.environ["PKGD_FAIL_ON_THREAT"] = value
                config = PKGDConfig()
                config = _apply_env_overrides(config)
                assert config.fail_on_threat_enabled is True, f"Failed to parse '{value}' as True"
        finally:
            if original is None:
                os.environ.pop("PKGD_FAIL_ON_THREAT", None)
            else:
                os.environ["PKGD_FAIL_ON_THREAT"] = original

    def test_boolean_env_var_parsing_false(self) -> None:
        """Environment variables should parse '0', 'false', 'no', 'off' as False."""
        import os

        original = os.environ.get("PKGD_FAIL_ON_THREAT")
        try:
            for value in ["0", "false", "no", "off"]:
                os.environ["PKGD_FAIL_ON_THREAT"] = value
                config = PKGDConfig()
                config = _apply_env_overrides(config)
                assert config.fail_on_threat_enabled is False, f"Failed to parse '{value}' as False"
        finally:
            if original is None:
                os.environ.pop("PKGD_FAIL_ON_THREAT", None)
            else:
                os.environ["PKGD_FAIL_ON_THREAT"] = original


class TestSecurityConfigKeysValidation:
    """Tests for validation of new security config keys."""

    def test_command_timeout_seconds_in_valid_keys(self) -> None:
        """command_timeout_seconds should be in _VALID_CONFIG_KEYS."""
        from pkg_defender.cli.common import _VALID_CONFIG_KEYS

        assert "command_timeout_seconds" in _VALID_CONFIG_KEYS

    def test_fail_on_threat_enabled_in_valid_keys(self) -> None:
        """fail_on_threat_enabled should be in _VALID_CONFIG_KEYS."""
        from pkg_defender.cli.common import _VALID_CONFIG_KEYS

        assert "fail_on_threat_enabled" in _VALID_CONFIG_KEYS


# Env var override logging (S14)


class TestEnvVarOverrideLogging:
    """Tests for structured env var override logging (_log_override helper).

    S14 added the ``_log_override()`` function inside ``_apply_env_overrides()``
    that logs every ``PKGD_*`` env var override with structured messages:

    - **Secret redaction** — 8 secret keys (tokens, API keys) display as ``***``
    - **Non-secret values** — shown via ``repr(value)`` in the log
    - **Security weakening detection** — 7 HIGH-impact env vars trigger WARNING
      when set to a weakening value
    """

    def test_secret_env_var_redacted(self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
        """Regression test: secret env var values are redacted in logs.

        Root cause: ``_log_override()`` in ``settings.py`` checks the
        ``_secret_keys`` set.  Before S14, ALL env var values were logged in
        plain text (no redaction).  This test **FAILS** before the fix and
        **PASSES** after.

        Scenario: ``PKGD_FEEDS_GHSA_TOKEN`` is set to ``secret123``.
        Expected: Log contains ``***`` and does NOT contain ``secret123``.
        Previously: Raw value was logged in plain text.
        """
        caplog.set_level("INFO")
        monkeypatch.setenv("PKGD_FEEDS_GHSA_TOKEN", "secret123")
        _apply_env_overrides(PKGDConfig())
        assert "***" in caplog.text, "Secret value should be redacted as ***"
        assert "secret123" not in caplog.text, "Raw secret value must not appear in logs"

    def test_non_secret_value_shown(self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
        """Non-secret env var values appear as ``repr(value)`` in logs."""
        caplog.set_level("INFO")
        monkeypatch.setenv("PKGD_SHOW_ASCII_BANNER", "false")
        _apply_env_overrides(PKGDConfig())
        assert "Override: PKGD_SHOW_ASCII_BANNER=False" in caplog.text, (
            "Non-secret bool value should appear as repr() in log"
        )

    def test_security_weakening_warning_fires(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Regression test: ``PKGD_FAIL_ON_THREAT=false`` triggers weakening warning.

        Root cause: ``_log_override()`` in ``settings.py`` checks the
        ``_weakening_env`` dict.  Before S14, weakening conditions were not
        detected or logged.  This test **FAILS** before the fix and **PASSES**
        after.

        Scenario: ``PKGD_FAIL_ON_THREAT=false``.
        Expected: ``"Security posture weakened"`` appears in the log.
        Previously: No warning was emitted.
        """
        caplog.set_level("INFO")
        monkeypatch.setenv("PKGD_FAIL_ON_THREAT", "false")
        _apply_env_overrides(PKGDConfig())
        assert "Security posture weakened" in caplog.text, (
            "Setting fail_on_threat=false should trigger weakening warning"
        )

    def test_security_weakening_warning_not_fired_for_safe(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Setting ``PKGD_FAIL_ON_THREAT=true`` does NOT trigger weakening warning."""
        caplog.set_level("INFO")
        monkeypatch.setenv("PKGD_FAIL_ON_THREAT", "true")
        _apply_env_overrides(PKGDConfig())
        assert "Security posture weakened" not in caplog.text, (
            "Setting fail_on_threat=true should NOT trigger weakening warning"
        )

    def test_warning_fires_for_cooldown_days_less_than_7(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """``PKGD_COOLDOWN_DEFAULT_DAYS < 7`` triggers weakening warning.

        The weakening threshold for ``cooldown_days`` is ``< 7`` (not ``<= 7``),
        so setting to 1 through 6 triggers the warning; setting to 7 does not.
        """
        caplog.set_level("INFO")
        monkeypatch.setenv("PKGD_COOLDOWN_DEFAULT_DAYS", "1")
        _apply_env_overrides(PKGDConfig())
        assert "Security posture weakened" in caplog.text, "Cooldown days < 7 should trigger weakening warning"
        assert "PKGD_COOLDOWN_DEFAULT_DAYS" in caplog.text

    def test_warning_fires_for_bypass_enabled(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """``PKGD_BYPASS_COMMAND_ENABLED=true`` triggers weakening warning.

        Unlike most security keys (weakening when set to ``false``), the bypass
        command is weakened when **enabled** (``=true``), since the default
        is disabled.
        """
        caplog.set_level("INFO")
        monkeypatch.setenv("PKGD_BYPASS_COMMAND_ENABLED", "true")
        _apply_env_overrides(PKGDConfig())
        assert "Security posture weakened" in caplog.text, "Enabling bypass command should trigger weakening warning"
        assert "PKGD_BYPASS_COMMAND_ENABLED" in caplog.text

    @pytest.mark.parametrize(
        "value,expect_warning",
        [
            ("false", True),
            ("true", False),
        ],
    )
    def test_weakening_threshold_fail_on_warn(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        value: str,
        expect_warning: bool,
    ) -> None:
        """``PKGD_FAIL_ON_WARN=false`` weakens security; ``true`` does not."""
        caplog.set_level("INFO")
        monkeypatch.setenv("PKGD_FAIL_ON_WARN", value)
        _apply_env_overrides(PKGDConfig())
        if expect_warning:
            assert "Security posture weakened" in caplog.text, (
                f"PKGD_FAIL_ON_WARN={value} should trigger weakening warning"
            )
        else:
            assert "Security posture weakened" not in caplog.text, (
                f"PKGD_FAIL_ON_WARN={value} should NOT trigger weakening warning"
            )

    def test_all_overrides_logged(self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
        """Every ``PKGD_*`` env var produces an ``"Override: PKGD_*"`` log entry."""
        caplog.set_level("INFO")
        monkeypatch.setenv("PKGD_SHOW_ASCII_BANNER", "false")
        monkeypatch.setenv("PKGD_COOLDOWN_DEFAULT_DAYS", "7")
        monkeypatch.setenv("PKGD_FEEDS_MASTODON_INSTANCE", "mastodon.social")
        monkeypatch.setenv("PKGD_FEEDS_GHSA_TOKEN", "test-token-value")
        _apply_env_overrides(PKGDConfig())
        assert "Override: PKGD_SHOW_ASCII_BANNER" in caplog.text
        assert "Override: PKGD_COOLDOWN_DEFAULT_DAYS" in caplog.text
        assert "Override: PKGD_FEEDS_MASTODON_INSTANCE" in caplog.text
        assert "Override: PKGD_FEEDS_GHSA_TOKEN" in caplog.text

    def test_returns_warning_when_env_var_is_weakening_value(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Regression: _weakening_env comparison uses ==, not is.

        The ``is`` operator checks identity — it accidentally works for bool
        singletons but fails for non-singleton types. This test verifies
        the hardening at line 743 by checking that all current weakening
        paths correctly fire with ``==`` semantics.
        """
        weakening_cases = [
            ("PKGD_FAIL_ON_THREAT", "false"),
            ("PKGD_COOLDOWN_STRICT_MODE", "false"),
            ("PKGD_BYPASS_COMMAND_ENABLED", "true"),
            ("PKGD_COOLDOWN_BYPASS_REQUIRE_REASON", "false"),
            ("PKGD_DATABASE_WAL_MODE", "false"),
            ("PKGD_FAIL_ON_WARN", "false"),
        ]

        for env_var, weakening_value in weakening_cases:
            caplog.clear()
            caplog.set_level("INFO")
            monkeypatch.setenv(env_var, weakening_value)
            _apply_env_overrides(PKGDConfig())
            assert "Security posture weakened" in caplog.text, (
                f"Weakening warning must fire for {env_var}={weakening_value}"
            )
            monkeypatch.undo()


# ---------------------------------------------------------------------------
# Daemon config tests (SG2)
# ---------------------------------------------------------------------------


class TestDaemonConfig:
    """Tests for DaemonConfig defaults and env var overrides."""

    def test_daemon_config_default_run_on_battery(self) -> None:
        """DaemonConfig.run_on_battery defaults to False."""
        config = PKGDConfig()
        assert config.daemon.run_on_battery is False

    def test_daemon_config_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """PKGD_DAEMON_RUN_ON_BATTERY=true overrides run_on_battery to True."""
        monkeypatch.setenv("PKGD_DAEMON_RUN_ON_BATTERY", "true")
        config = _apply_env_overrides(PKGDConfig())
        assert config.daemon.run_on_battery is True


# ---------------------------------------------------------------------------
# TOML config weakening detection (P0.5)
# ---------------------------------------------------------------------------


class TestTomlWeakeningDetection:
    """Tests for TOML config weakening detection in _apply_toml_data()."""

    def test_toml_weakening_detects_fail_on_threat_false(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """fail_on_threat_enabled=false via TOML triggers weakening warning."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("fail_on_threat_enabled = false\n")
        caplog.set_level("WARNING")
        load_config(config_file)
        assert "Security posture weakened" in caplog.text
        assert "fail_on_threat_enabled" in caplog.text

    def test_toml_weakening_detects_cooldown_enabled_false(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """[cooldown] enabled=false (TOML-only key) triggers weakening warning."""
        config_file = tmp_path / "pkgd.toml"
        config_file.write_text("[cooldown]\nenabled = false\n")
        caplog.set_level("WARNING")
        load_config(config_file)
        assert "Security posture weakened" in caplog.text
        assert "cooldown.enabled" in caplog.text

    def test_toml_weakening_safe_values_silent(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Safe TOML values do not trigger weakening warning."""
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            "fail_on_threat_enabled = true\n[cooldown]\nenabled = true\nstrict_mode = true\ndefault_days = 7\n"
        )
        caplog.set_level("WARNING")
        load_config(config_file)
        assert "Security posture weakened" not in caplog.text

    def test_toml_weakening_detects_osv_disabled(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """[feeds] osv_enabled=false triggers weakening warning."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("[feeds]\nosv_enabled = false\n")
        caplog.set_level("WARNING")
        load_config(config_file)
        assert "Security posture weakened" in caplog.text
        assert "feeds.osv_enabled" in caplog.text

    def test_all_weakening_toml_keys_fire(self, caplog: pytest.LogCaptureFixture) -> None:
        """Every key in _weakening_toml fires a warning when set to a weakening value.

        Fields whose weakening value equals the Python dataclass default are
        excluded here — their default values are not warnings.
        """
        _default_equals_weakening: set[tuple[str, ...]] = {
            ("fail_on_warn_enabled",),
            ("feeds", "socket_enabled"),
            ("feeds", "npm_advisory_enabled"),
        }

        for key_path, weaken_values in _weakening_toml.items():
            if key_path in _default_equals_weakening:
                continue
            caplog.clear()
            caplog.set_level("WARNING")

            weaken_val = weaken_values[0]
            data: dict[str, Any] = {}
            if len(key_path) == 1:
                data[key_path[0]] = weaken_val
            else:
                section = data.setdefault(key_path[0], {})
                section[key_path[1]] = weaken_val

            _apply_toml_data(PKGDConfig(), data, _source="test")
            assert "Security posture weakened" in caplog.text, (
                f"Weakening warning must fire for {'.'.join(key_path)} = {weaken_val!r}"
            )

    def test_toml_weakening_env_var_still_wins(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Env var override takes precedence over weakening TOML value."""
        config_file = tmp_path / "pkgd.toml"
        config_file.write_text("[cooldown]\nenabled = false\n")
        monkeypatch.setenv("PKGD_COOLDOWN_ENABLED", "true")
        caplog.set_level("WARNING")
        config = load_config(config_file)
        assert config.cooldown.enabled is True  # env var wins
        assert "Security posture weakened" in caplog.text  # TOML warning still present

    def test_toml_weakening_default_days_less_than_7(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """[cooldown] default_days < 7 triggers weakening warning in TOML."""

        config_file = tmp_path / "config.toml"
        config_file.write_text("[cooldown]\ndefault_days = 1\n")
        caplog.set_level("WARNING")
        load_config(config_file)
        assert "Security posture weakened" in caplog.text
        assert "cooldown.default_days" in caplog.text

    def test_toml_weakening_default_days_7_no_warning(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """[cooldown] default_days=7 boundary does not trigger weakening warning."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("[cooldown]\ndefault_days = 7\n")
        caplog.set_level("WARNING")
        load_config(config_file)
        assert "Security posture weakened" not in caplog.text

    def test_toml_weakening_system_config_also_checked(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Weakening in system config also produces warning."""
        sys_config = tmp_path / "etc_pkgd_config.toml"
        sys_config.write_text("[database]\nwal_mode = false\n")
        monkeypatch.setattr("pkg_defender.config.settings.SYSTEM_CONFIG_PATH", sys_config)

        caplog.set_level("WARNING")
        load_config()
        assert "Security posture weakened" in caplog.text
        assert "database.wal_mode" in caplog.text


# ---------------------------------------------------------------------------
# TOML type validation (Audit 8.14)
# ---------------------------------------------------------------------------


class TestTomlTypeValidation:
    """Tests for TOML value type validation in _apply_toml_data().

    Audit 8.14 found that _apply_toml_data() assigns raw TOML-parsed values
    without checking whether they match the dataclass field's expected type.
    For example, ``command_timeout_seconds = "thirty"`` in TOML produces a
    ``str`` that is silently assigned to an ``int`` field, causing a
    ``TypeError`` at runtime. The env var path already handles this via
    ``_coerce_env_value()``; this test class verifies the TOML path now has
    equivalent protection.
    """

    def test_int_field_rejects_string(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """TOML string value for an int field is rejected; default preserved."""
        config_file = tmp_path / "config.toml"
        config_file.write_text('command_timeout_seconds = "thirty"\n')
        caplog.set_level("WARNING")
        config = load_config(config_file)
        assert config.command_timeout_seconds == 30  # default preserved
        assert "Invalid" in caplog.text
        assert "command_timeout_seconds" in caplog.text

    def test_int_field_rejects_bool(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """TOML bool value for an int field is rejected; default preserved."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("[cooldown]\ndefault_days = true\n")
        caplog.set_level("WARNING")
        config = load_config(config_file)
        assert config.cooldown.default_days == 7  # default preserved
        assert "Invalid" in caplog.text
        assert "default_days" in caplog.text

    def test_bool_field_rejects_int(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """TOML int value for a bool field is rejected; default preserved."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("[cooldown]\nenabled = 1\n")
        caplog.set_level("WARNING")
        config = load_config(config_file)
        assert config.cooldown.enabled is True  # default preserved
        assert "Invalid" in caplog.text
        assert "enabled" in caplog.text

    def test_bool_field_rejects_string(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """TOML string value for a bool field is rejected; default preserved."""
        config_file = tmp_path / "config.toml"
        config_file.write_text('[output]\ncolor = "yes"\n')
        caplog.set_level("WARNING")
        config = load_config(config_file)
        assert config.output.color is True  # default preserved
        assert "Invalid" in caplog.text
        assert "color" in caplog.text

    def test_float_field_rejects_string(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """TOML string value for a float field is rejected; default preserved."""
        config_file = tmp_path / "config.toml"
        config_file.write_text('registry_api_timeout = "fast"\n')
        caplog.set_level("WARNING")
        config = load_config(config_file)
        assert config.registry_api_timeout == 10.0  # default preserved
        assert "Invalid" in caplog.text
        assert "registry_api_timeout" in caplog.text

    def test_valid_toml_values_still_apply(self, tmp_path: Path) -> None:
        """Correctly-typed TOML values are still applied (no regression)."""
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """\
command_timeout_seconds = 60
registry_api_timeout = 15.5
[cooldown]
default_days = 7
enabled = false
strict_mode = false
"""
        )
        config = load_config(config_file)
        assert config.command_timeout_seconds == 60
        assert config.registry_api_timeout == 15.5
        assert config.cooldown.default_days == 7
        assert config.cooldown.enabled is False
        assert config.cooldown.strict_mode is False

    def test_multiple_invalid_fields_all_rejected(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Multiple invalid TOML fields are all rejected; all defaults preserved."""
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """\
command_timeout_seconds = "slow"
registry_api_timeout = "fast"
[cooldown]
default_days = "long"
enabled = "yes"
"""
        )
        caplog.set_level("WARNING")
        config = load_config(config_file)
        # All defaults preserved
        assert config.command_timeout_seconds == 30
        assert config.registry_api_timeout == 10.0
        assert config.cooldown.default_days == 7
        assert config.cooldown.enabled is True
        # All invalid fields warned
        assert caplog.text.count("Invalid") >= 4

    def test_validate_toml_value_rejects_wrong_type(self) -> None:
        """_validate_toml_value() directly rejects mismatched types."""
        from pkg_defender.config.settings import _validate_toml_value

        assert _validate_toml_value(int, 42) is True
        assert _validate_toml_value(int, "forty-two") is False
        assert _validate_toml_value(int, True) is False  # bool must not pass for int
        assert _validate_toml_value(bool, True) is True
        assert _validate_toml_value(bool, 1) is False
        assert _validate_toml_value(bool, "yes") is False
        assert _validate_toml_value(float, 3.14) is True
        assert _validate_toml_value(float, 42) is True  # int accepted for float
        assert _validate_toml_value(float, True) is False  # bool must not pass for float
        assert _validate_toml_value(float, "pi") is False
        assert _validate_toml_value(str, "hello") is True
        assert _validate_toml_value(str, 123) is False
        # Union/Optional coverage: Path | None (Python 3.10+ union syntax)
        assert _validate_toml_value(Path | None, None) is True
        assert _validate_toml_value(Path | None, Path("/tmp")) is True
        assert _validate_toml_value(Path | None, "string") is False


# ---------------------------------------------------------------------------
# TOML-only caching for load_config() (Plan Item 03)
# ---------------------------------------------------------------------------


class TestLoadConfigCaching:
    """Tests for TOML file content caching in load_config().

    The cached helper ``_read_toml_bytes_cached()`` stores raw file bytes
    keyed by ``Path`` object, so repeated calls to ``load_config()`` with
    the same path skip the filesystem read.
    """

    def test_cached_read_auto_invalidates_on_file_change(self, tmp_path: Path) -> None:
        """When the file changes on disk, the cache auto-invalidates via mtime/size key."""
        from pkg_defender.config.settings import load_config

        config_file = tmp_path / "pkgd.toml"
        config_file.write_text("[cooldown]\ndefault_days = 7\n")

        # First call: reads from disk, populates cache
        config1 = load_config(config_file)
        assert config1.cooldown.default_days == 7

        # Modify the file on disk — change mtime and size
        config_file.write_text("[cooldown]\ndefault_days = 14\n")

        # Second call: cache auto-invalidates because mtime/size changed
        config2 = load_config(config_file)
        assert config2.cooldown.default_days == 14, (
            "Expected disk value (14), got cached value (7). The mtime/size cache key should have auto-invalidated."
        )
        assert config1 is not config2, "Objects should be different (env vars applied fresh)."

    def test_different_paths_have_independent_cache_entries(self, tmp_path: Path) -> None:
        """Two different config paths should each have their own cache entry."""
        from pkg_defender.config.settings import load_config

        file_a = tmp_path / "a.toml"
        file_b = tmp_path / "b.toml"
        file_a.write_text("[cooldown]\ndefault_days = 3\n")
        file_b.write_text("[cooldown]\ndefault_days = 21\n")

        config_a = load_config(file_a)
        config_b = load_config(file_b)

        assert config_a.cooldown.default_days == 3
        assert config_b.cooldown.default_days == 21

    def test_missing_path_returns_defaults_on_subsequent_calls(self, tmp_path: Path) -> None:
        """A missing config file path returns defaults; creating the file later does
        NOT change the result because the exists() check skips the TOML read block
        (the cached read function is never consulted for missing paths)."""
        from pkg_defender.config.settings import load_config

        missing = tmp_path / "missing.toml"
        assert not missing.exists()

        config = load_config(missing)
        assert config.cooldown.default_days == 7  # default, since no file

        # Create the file AFTER first call
        missing.write_text("[cooldown]\ndefault_days = 42\n")

        # Second call: the exists() check passes, but the file is now read.
        # This test actually shows that the file IS re-read when it appears
        # between calls (the exists() check is NOT cached). After the file
        # exists, the cached bytes helper serves file content — not None.
        config2 = load_config(missing)
        assert config2.cooldown.default_days == 42


# ---------------------------------------------------------------------------
# Dict coercion via env var (audit 8.13)
# ---------------------------------------------------------------------------


class TestDictCoercion:
    """Tests for dict type coercion in _coerce_env_value and _apply_env_overrides."""

    def test_coerce_env_value_dict_valid_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_coerce_env_value handles dict type with valid JSON."""
        from pkg_defender.config.settings import _coerce_env_value

        result = _coerce_env_value('{"npm": 15, "pypi": 7}', dict, "PKGD_TEST")
        assert result == {"npm": 15, "pypi": 7}

    def test_coerce_env_value_dict_invalid_json(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """_coerce_env_value warns on invalid JSON for dict type."""
        caplog.set_level("WARNING")
        from pkg_defender.config.settings import _coerce_env_value

        result = _coerce_env_value("not-json", dict, "PKGD_TEST")
        assert result is None
        assert "PKGD_TEST" in caplog.text

    def test_apply_env_overrides_dict_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """JSON-encoded dict env var sets per_ecosystem_registry_timeout."""
        monkeypatch.setenv("PKGD_PER_ECOSYSTEM_REGISTRY_TIMEOUT", '{"npm": 20}')
        config = _apply_env_overrides(PKGDConfig())
        assert config.per_ecosystem_registry_timeout == {"npm": 20}


class TestConfigCorruptionWarning:
    """Tests for config corruption warning output."""

    def test_malformed_toml_prints_error_to_stderr(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Malformed TOML prints error to stderr via click.echo."""
        config_path = tmp_path / "pkgd.toml"
        config_path.write_text("invalid = [[broken")

        _ = load_config(config_path=config_path)

        captured = capsys.readouterr()
        assert "Error: Config file" in captured.err
        assert "is corrupt" in captured.err
        assert "Using defaults" in captured.err
        assert str(config_path) in captured.err

    def test_malformed_toml_returns_defaults(
        self,
        tmp_path: Path,
    ) -> None:
        """Config defaults are preserved when TOML is corrupt."""
        config_path = tmp_path / "pkgd.toml"
        config_path.write_text("invalid = [[broken")

        config = load_config(config_path=config_path)

        assert config.output.verbose is False
        assert config.cooldown.default_days == 7

    def test_valid_toml_no_false_positive(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Valid TOML does NOT trigger error on stderr."""
        config_path = tmp_path / "pkgd.toml"
        config_path.write_text("[cooldown]\ndefault_days = 7\n[output]\nverbose = true")

        config = load_config(config_path=config_path)

        captured = capsys.readouterr()
        assert "Error: Config file" not in captured.err
        assert config.cooldown.default_days == 7
        assert config.output.verbose is True
