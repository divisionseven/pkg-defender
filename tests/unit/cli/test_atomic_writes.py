"""Tests for atomic write patterns in config and daemon modules."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest


class TestWriteConfigToml:
    """Tests for _write_config_toml atomic write pattern."""

    def test_temp_file_cleaned_up_on_rename_error(self, tmp_path: Path) -> None:
        """When os.replace fails, the temp file is cleaned up."""
        from pkg_defender.cli.common import _write_config_toml

        config_path = tmp_path / "config.toml"
        content = '[section]\nkey = "value"\n'

        with patch("os.replace", side_effect=OSError("rename failed")), pytest.raises(OSError):
            _write_config_toml(config_path, content)

        # Verify no .tmp files remain
        tmp_files = list(tmp_path.glob(".config.*.tmp"))
        assert len(tmp_files) == 0
        # Verify original file was NOT created
        assert not config_path.exists()

    def test_happy_path_no_temp_file_left(self, tmp_path: Path) -> None:
        """Happy path — no temp file remains after successful write."""
        from pkg_defender.cli.common import _write_config_toml

        config_path = tmp_path / "config.toml"
        content = '[section]\nkey = "value"\n'

        _write_config_toml(config_path, content)

        assert config_path.exists()
        tmp_files = list(tmp_path.glob(".config.*.tmp"))
        assert len(tmp_files) == 0

    def test_uses_atomic_rename(self, tmp_path: Path) -> None:
        """_write_config_toml uses os.replace for atomic rename."""
        from pkg_defender.cli.common import _write_config_toml

        config_path = tmp_path / "config.toml"
        content = '[section]\nkey = "value"\n'

        with patch("os.replace") as mock_replace, patch("os.chmod"):
            _write_config_toml(config_path, content)

        mock_replace.assert_called_once()
        call_args = mock_replace.call_args[0]
        assert call_args[1] == config_path  # destination is config_path (Path)


class TestWriteHeartbeat:
    """Tests for write_heartbeat atomic write pattern."""

    def test_temp_file_cleaned_up_on_write_error(self, tmp_path: Path) -> None:
        """When json.dump fails, the temp file is cleaned up."""
        from pkg_defender.daemon.runner import write_heartbeat

        data_dir = tmp_path
        status: dict[str, object] = {
            "last_sync": "2026-01-01T00:00:00",
            "status": "ok",
            "error": None,
            "feeds": {},
        }

        with patch("json.dump", side_effect=TypeError("bad type")), pytest.raises(TypeError):
            write_heartbeat(data_dir, status)

        # Verify no .tmp heartbeat files remain
        tmp_files = list(tmp_path.glob(".heartbeat_*.tmp"))
        assert len(tmp_files) == 0
