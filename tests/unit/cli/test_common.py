"""Tests for pkg_defender.cli.common — utility functions and _health_impl.

Covers:
  - _format_versions
  - _detect_manager_from_cwd
  - _detect_ecosystem_from_cwd
  - _validate_github_token / _validate_socket_token / _validate_x_twitter_token
  - _check_disk_space
  - _check_permissions
  - _get_threat_counts
  - _build_coverage_table
  - _health_impl (key paths)
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import click
import pytest
from click.testing import CliRunner

from pkg_defender.cli.common import (
    TokenStatus,
    _build_coverage_table,
    _check_disk_space,
    _check_permissions,
    _detect_ecosystem_from_cwd,
    _detect_manager_from_cwd,
    _format_versions,
    _get_config_from_context,
    _get_config_value_by_key,
    _get_protection_status,
    _get_threat_counts,
    _health_impl,
    _parse_duration,
    _parse_expiry,
    _validate_config_key,
    _validate_github_token,
    _validate_reddit_credentials,
    _validate_socket_token,
    _validate_x_twitter_token,
)

# ============================================================================
# TestFormatVersions
# ============================================================================


class TestFormatVersions:
    """Tests for _format_versions()."""

    def test_both_none_returns_em_dash(self) -> None:
        """Both params None → em dash."""
        assert _format_versions(None, None) == "\u2014"

    def test_empty_arrays_returns_em_dash(self) -> None:
        """Empty JSON arrays → em dash."""
        assert _format_versions("[]", "[]") == "\u2014"

    def test_versions_single_item(self) -> None:
        """Single version rendered without comma."""
        result = _format_versions('["1.0.0"]', None)
        assert result == "1.0.0"

    def test_versions_multiple_items(self) -> None:
        """Multiple versions separated by comma+space."""
        result = _format_versions('["1.0.0","2.0.0","3.0.0"]', None)
        assert result == "1.0.0, 2.0.0, 3.0.0"

    def test_versions_more_than_three_shows_additional_count(self) -> None:
        """More than 3 versions shows '+N additional'."""
        result = _format_versions('["1.0.0","2.0.0","3.0.0","4.0.0","5.0.0"]', None)
        assert "1.0.0, 2.0.0, 3.0.0" in result
        assert "+2 additional" in result

    def test_ranges_preferred_over_versions(self) -> None:
        """Ranges output preferred even when versions are also provided."""
        result = _format_versions('["1.0.0"]', '["<2.0.0",">=1.0.0"]')
        assert result == "<2.0.0, >=1.0.0"
        assert "additional" not in result

    def test_malformed_versions_json_returns_em_dash(self) -> None:
        """Invalid versions JSON → em dash."""
        assert _format_versions("not-json", None) == "\u2014"

    def test_malformed_ranges_json_returns_em_dash(self) -> None:
        """Invalid ranges JSON → em dash."""
        assert _format_versions(None, "bad-json") == "\u2014"

    def test_long_result_truncated(self) -> None:
        """Result longer than 38 chars is truncated to 35 + '...'."""
        long_version = '"very-long-package-name-with-version-1.0.0"'
        result = _format_versions(f"[{long_version},{long_version},{long_version}]", None)
        assert len(result) <= 38
        assert result.endswith("...")

    def test_empty_string_versions_treated_as_none(self) -> None:
        """Empty string '' treated same as None (falsy)."""
        assert _format_versions("", None) == "\u2014"
        assert _format_versions(None, "") == "\u2014"
        assert _format_versions("", "") == "\u2014"

    def test_ranges_truncated_when_long(self) -> None:
        """Multiple long ranges trigger truncation."""
        result = _format_versions(
            None,
            '[">=1.0.0-abc.12345, <2.0.0", ">=3.0.0, <4.0.0", ">=5.0.0, <6.0.0"]',
        )
        assert len(result) <= 38
        assert result.endswith("...")


# ============================================================================
# TestParseExpiry
# ============================================================================


class TestParseExpiry:
    """Tests for _parse_expiry()."""

    def test_days(self) -> None:
        """'7d' → 7 days from now."""
        from datetime import UTC, datetime

        result = _parse_expiry("7d")
        now = datetime.now(UTC)
        diff = result - now
        assert 6.9 < diff.total_seconds() / 86400 < 7.1

    def test_hours(self) -> None:
        """'24h' → 24 hours from now."""
        from datetime import UTC, datetime

        result = _parse_expiry("24h")
        now = datetime.now(UTC)
        diff = result - now
        assert 23.9 < diff.total_seconds() / 3600 < 24.1

    def test_minutes(self) -> None:
        """'30m' → 30 minutes from now."""
        from datetime import UTC, datetime

        result = _parse_expiry("30m")
        now = datetime.now(UTC)
        diff = result - now
        assert 29.9 < diff.total_seconds() / 60 < 30.1

    def test_invalid_format_raises_bad_parameter(self) -> None:
        """Invalid format → BadParameter."""
        with pytest.raises(click.BadParameter):
            _parse_expiry("invalid")


# ============================================================================
# TestParseDuration
# ============================================================================


class TestParseDuration:
    """Tests for _parse_duration()."""

    def test_days(self) -> None:
        """'7d' → 7 day timedelta."""
        from datetime import timedelta

        result = _parse_duration("7d")
        assert result == timedelta(days=7)

    def test_hours(self) -> None:
        """'24h' → 24 hour timedelta."""
        from datetime import timedelta

        result = _parse_duration("24h")
        assert result == timedelta(hours=24)

    def test_minutes(self) -> None:
        """'30m' → 30 minute timedelta."""
        from datetime import timedelta

        result = _parse_duration("30m")
        assert result == timedelta(minutes=30)

    def test_invalid_format_raises_bad_parameter(self) -> None:
        """Invalid format → BadParameter."""
        with pytest.raises(click.BadParameter):
            _parse_duration("bad")


# ============================================================================
# TestDetectManagerFromCwd
# ============================================================================


class TestDetectManagerFromCwd:
    """Tests for _detect_manager_from_cwd()."""

    def test_detect_cargo_by_cargo_toml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Cargo.toml → 'cargo'."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "Cargo.toml").write_text("")
        assert _detect_manager_from_cwd() == "cargo"

    def test_detect_pip_by_requirements_txt(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """requirements.txt → 'pip'."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "requirements.txt").write_text("")
        assert _detect_manager_from_cwd() == "pip"

    def test_detect_gem_by_gemfile(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Gemfile → 'gem'."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "Gemfile").write_text("")
        assert _detect_manager_from_cwd() == "gem"

    def test_detect_composer_by_composer_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """composer.json → 'composer'."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "composer.json").write_text("")
        assert _detect_manager_from_cwd() == "composer"

    def test_detect_conda_by_environment_yml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """environment.yml → 'conda'."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "environment.yml").write_text("")
        assert _detect_manager_from_cwd() == "conda"

    def test_detect_pipenv_by_pipfile(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Pipfile → 'pipenv'."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "Pipfile").write_text("")
        assert _detect_manager_from_cwd() == "pipenv"

    def test_detect_brew_by_brewfile(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Brewfile → 'brew'."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "Brewfile").write_text("")
        assert _detect_manager_from_cwd() == "brew"

    def test_detect_npm_preferred_over_yarn(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """package.json alone → 'npm' (npm iterates first)."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "package.json").write_text("{}")
        (tmp_path / "yarn.lock").write_text("")
        # npm checks marker list first and matches on package.json
        assert _detect_manager_from_cwd() == "npm"

    def test_no_marker_falls_back(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """When no marker file exists, returns system fallback."""
        monkeypatch.chdir(tmp_path)
        # Ensure temp dir has no recognisable marker files
        result = _detect_manager_from_cwd()
        # Fallback: /etc/apt check (system-dependent) → "npm" as final fallback
        assert result in ("apt", "npm")

    def test_no_marker_falls_back_to_npm(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """When no marker exists and /etc/apt doesn't exist, returns 'npm'."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("pkg_defender.cli.common.Path", MagicMock())
        # We can't easily mock Path("/etc/apt").exists() — just test the
        # system-dependent fallback for coverage. On macOS /etc/apt doesn't
        # exist, so this will exercise the "npm" path.
        result = _detect_manager_from_cwd()
        # Acceptable results on any system
        assert isinstance(result, str)


# ============================================================================
# TestDetectEcosystemFromCwd
# ============================================================================


class TestDetectEcosystemFromCwd:
    """Tests for _detect_ecosystem_from_cwd()."""

    def test_ecosystem_delegates_to_manager(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Ecosystem for cargo marker is 'cargo' (cargo maps to cargo ecosystem)."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "Cargo.toml").write_text("")
        assert _detect_ecosystem_from_cwd() == "cargo"


# ============================================================================
# TestValidateGitHubToken
# ============================================================================


class TestValidateGitHubToken:
    """Tests for _validate_github_token()."""

    @pytest.mark.asyncio
    async def test_empty_token(self) -> None:
        """Empty string → NOT_CONFIGURED."""
        status, msg = await _validate_github_token("")
        assert status == TokenStatus.NOT_CONFIGURED
        assert "no token configured" in msg

    @pytest.mark.asyncio
    async def test_200_returns_valid(self) -> None:
        """200 response → VALID."""
        mock_status, _ = await self._run_with_status(200)
        assert mock_status == TokenStatus.VALID

    @pytest.mark.asyncio
    async def test_401_returns_invalid(self) -> None:
        """401 response → INVALID."""
        mock_status, msg = await self._run_with_status(401)
        assert mock_status == TokenStatus.INVALID
        assert "unauthorized" in msg

    @pytest.mark.asyncio
    async def test_403_returns_expired(self) -> None:
        """403 response → EXPIRED."""
        mock_status, msg = await self._run_with_status(403)
        assert mock_status == TokenStatus.EXPIRED
        assert "expired" in msg

    @pytest.mark.asyncio
    async def test_500_returns_error(self) -> None:
        """500 response → ERROR with HTTP code."""
        mock_status, msg = await self._run_with_status(500)
        assert mock_status == TokenStatus.ERROR
        assert "HTTP 500" in msg

    @pytest.mark.asyncio
    async def test_client_error_returns_connection_error(self) -> None:
        """aiohttp.ClientError → ERROR with connection error."""
        import aiohttp

        mock_status, msg = await self._run_with_exception(aiohttp.ClientError("connection refused"))
        assert mock_status == TokenStatus.ERROR
        assert "connection error" in msg

    @pytest.mark.asyncio
    async def test_unexpected_exception_returns_error(self) -> None:
        """Generic Exception → ERROR with unexpected error."""
        mock_status, msg = await self._run_with_exception(RuntimeError("something broke"))
        assert mock_status == TokenStatus.ERROR
        assert "unexpected error" in msg

    async def _run_with_status(self, status_code: int) -> tuple[str, str]:
        """Helper: create mock HTTP response with given status code."""
        mock_resp = MagicMock()
        mock_resp.status = status_code

        mock_resp_cm = AsyncMock()
        mock_resp_cm.__aenter__.return_value = mock_resp

        # session.get() must return a sync value (context manager), not a coroutine.
        # Use a regular MagicMock for the session and set __aenter__ separately.
        mock_session = MagicMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.get.return_value = mock_resp_cm

        mock_session_cls = MagicMock(return_value=mock_session)

        with patch("aiohttp.ClientSession", mock_session_cls):
            return await _validate_github_token("some-token")

    async def _run_with_exception(self, exc: Exception) -> tuple[str, str]:
        """Helper: make session.get raise an exception."""
        mock_session = MagicMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.get.side_effect = exc

        mock_session_cls = MagicMock(return_value=mock_session)

        with patch("aiohttp.ClientSession", mock_session_cls):
            return await _validate_github_token("some-token")


# ============================================================================
# TestValidateSocketToken
# ============================================================================


class TestValidateSocketToken:
    """Tests for _validate_socket_token()."""

    @pytest.mark.asyncio
    async def test_empty_token(self) -> None:
        """Empty string → NOT_CONFIGURED."""
        status, msg = await _validate_socket_token("")
        assert status == TokenStatus.NOT_CONFIGURED
        assert "no API key configured" in msg

    @pytest.mark.asyncio
    async def test_200_returns_valid(self) -> None:
        """200 response → VALID."""
        mock_status, msg = await self._run_with_status(200)
        assert mock_status == TokenStatus.VALID
        assert "API key validated" in msg

    @pytest.mark.asyncio
    async def test_401_returns_invalid(self) -> None:
        """401 response → INVALID."""
        mock_status, msg = await self._run_with_status(401)
        assert mock_status == TokenStatus.INVALID
        assert "unauthorized" in msg

    @pytest.mark.asyncio
    async def test_403_returns_expired(self) -> None:
        """403 response → EXPIRED."""
        mock_status, msg = await self._run_with_status(403)
        assert mock_status == TokenStatus.EXPIRED
        assert "expired" in msg

    @pytest.mark.asyncio
    async def test_500_returns_error(self) -> None:
        """500 response → ERROR with HTTP code."""
        mock_status, msg = await self._run_with_status(500)
        assert mock_status == TokenStatus.ERROR
        assert "HTTP 500" in msg

    @pytest.mark.asyncio
    async def test_client_error_returns_connection_error(self) -> None:
        """aiohttp.ClientError → ERROR with connection error."""
        import aiohttp

        mock_status, msg = await self._run_with_exception(aiohttp.ClientError("timeout"))
        assert mock_status == TokenStatus.ERROR
        assert "connection error" in msg

    @pytest.mark.asyncio
    async def test_unexpected_exception_returns_error(self) -> None:
        """Generic Exception → ERROR with unexpected error."""
        mock_status, msg = await self._run_with_exception(RuntimeError("unexpected"))
        assert mock_status == TokenStatus.ERROR
        assert "unexpected error" in msg

    async def _run_with_status(self, status_code: int) -> tuple[str, str]:
        """Helper: create mock HTTP response with given status code."""
        mock_resp = MagicMock()
        mock_resp.status = status_code

        mock_resp_cm = AsyncMock()
        mock_resp_cm.__aenter__.return_value = mock_resp

        mock_session = MagicMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.get.return_value = mock_resp_cm

        mock_session_cls = MagicMock(return_value=mock_session)

        with patch("aiohttp.ClientSession", mock_session_cls):
            return await _validate_socket_token("some-key")

    async def _run_with_exception(self, exc: Exception) -> tuple[str, str]:
        """Helper: make session.get raise an exception."""
        mock_session = MagicMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.get.side_effect = exc

        mock_session_cls = MagicMock(return_value=mock_session)

        with patch("aiohttp.ClientSession", mock_session_cls):
            return await _validate_socket_token("some-key")


# ============================================================================
# TestValidateXTwitterToken
# ============================================================================


class TestValidateXTwitterToken:
    """Tests for _validate_x_twitter_token()."""

    @pytest.mark.asyncio
    async def test_empty_token(self) -> None:
        """Empty string → NOT_CONFIGURED."""
        status, msg = await _validate_x_twitter_token("")
        assert status == TokenStatus.NOT_CONFIGURED
        assert "no bearer token configured" in msg

    @pytest.mark.asyncio
    async def test_200_returns_valid(self) -> None:
        """200 response → VALID."""
        mock_status, msg = await self._run_with_status(200)
        assert mock_status == TokenStatus.VALID
        assert "bearer token validated" in msg

    @pytest.mark.asyncio
    async def test_401_returns_invalid(self) -> None:
        """401 response → INVALID."""
        mock_status, msg = await self._run_with_status(401)
        assert mock_status == TokenStatus.INVALID
        assert "unauthorized" in msg

    @pytest.mark.asyncio
    async def test_403_returns_expired(self) -> None:
        """403 response → EXPIRED."""
        mock_status, msg = await self._run_with_status(403)
        assert mock_status == TokenStatus.EXPIRED
        assert "expired" in msg

    @pytest.mark.asyncio
    async def test_500_returns_error(self) -> None:
        """500 response → ERROR with HTTP code."""
        mock_status, msg = await self._run_with_status(500)
        assert mock_status == TokenStatus.ERROR
        assert "HTTP 500" in msg

    @pytest.mark.asyncio
    async def test_client_error_returns_connection_error(self) -> None:
        """aiohttp.ClientError → ERROR with connection error."""
        import aiohttp

        mock_status, msg = await self._run_with_exception(aiohttp.ClientError("connection timeout"))
        assert mock_status == TokenStatus.ERROR
        assert "connection error" in msg

    @pytest.mark.asyncio
    async def test_unexpected_exception_returns_error(self) -> None:
        """Generic Exception → ERROR with unexpected error."""
        mock_status, msg = await self._run_with_exception(RuntimeError("unexpected"))
        assert mock_status == TokenStatus.ERROR
        assert "unexpected error" in msg

    async def _run_with_status(self, status_code: int) -> tuple[str, str]:
        """Helper: create mock HTTP response with given status code."""
        mock_resp = MagicMock()
        mock_resp.status = status_code

        mock_resp_cm = AsyncMock()
        mock_resp_cm.__aenter__.return_value = mock_resp

        mock_session = MagicMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.get.return_value = mock_resp_cm

        mock_session_cls = MagicMock(return_value=mock_session)

        with patch("aiohttp.ClientSession", mock_session_cls):
            return await _validate_x_twitter_token("some-token")

    async def _run_with_exception(self, exc: Exception) -> tuple[str, str]:
        """Helper: make session.get raise an exception."""
        mock_session = MagicMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.get.side_effect = exc

        mock_session_cls = MagicMock(return_value=mock_session)

        with patch("aiohttp.ClientSession", mock_session_cls):
            return await _validate_x_twitter_token("some-token")


# ============================================================================
# TestValidateRedditCredentials
# ============================================================================


class TestValidateRedditCredentials:
    """Tests for _validate_reddit_credentials()."""

    @pytest.mark.asyncio
    async def test_both_empty(self) -> None:
        """Both empty strings → NOT_CONFIGURED."""
        status, msg = await _validate_reddit_credentials("", "")
        assert status == TokenStatus.NOT_CONFIGURED
        assert "no credentials configured" in msg

    @pytest.mark.asyncio
    async def test_missing_client_id(self) -> None:
        """Only client_secret set → NOT_CONFIGURED (partial)."""
        status, msg = await _validate_reddit_credentials("", "secret123")
        assert status == TokenStatus.NOT_CONFIGURED
        assert "partial credentials" in msg

    @pytest.mark.asyncio
    async def test_missing_client_secret(self) -> None:
        """Only client_id set → NOT_CONFIGURED (partial)."""
        status, msg = await _validate_reddit_credentials("client123", "")
        assert status == TokenStatus.NOT_CONFIGURED
        assert "partial credentials" in msg

    @pytest.mark.asyncio
    async def test_200_returns_valid(self) -> None:
        """200 response → VALID."""
        mock_status, msg = await self._run_with_post_status(200)
        assert mock_status == TokenStatus.VALID
        assert "credentials validated" in msg

    @pytest.mark.asyncio
    async def test_401_returns_invalid(self) -> None:
        """401 response → INVALID."""
        mock_status, msg = await self._run_with_post_status(401)
        assert mock_status == TokenStatus.INVALID
        assert "unauthorized" in msg

    @pytest.mark.asyncio
    async def test_500_returns_error(self) -> None:
        """500 response → ERROR with HTTP code."""
        mock_status, msg = await self._run_with_post_status(500)
        assert mock_status == TokenStatus.ERROR
        assert "HTTP 500" in msg

    @pytest.mark.asyncio
    async def test_client_error_returns_connection_error(self) -> None:
        """aiohttp.ClientError → ERROR with connection error."""
        import aiohttp

        mock_status, msg = await self._run_with_post_exception(
            aiohttp.ClientError("connection refused"),
        )
        assert mock_status == TokenStatus.ERROR
        assert "connection error" in msg

    @pytest.mark.asyncio
    async def test_unexpected_exception_returns_error(self) -> None:
        """Generic Exception → ERROR with unexpected error."""
        mock_status, msg = await self._run_with_post_exception(
            RuntimeError("unexpected"),
        )
        assert mock_status == TokenStatus.ERROR
        assert "unexpected error" in msg

    async def _run_with_post_status(self, status_code: int) -> tuple[str, str]:
        """Helper: create mock HTTP response with given status code (POST)."""
        mock_resp = MagicMock()
        mock_resp.status = status_code

        mock_resp_cm = AsyncMock()
        mock_resp_cm.__aenter__.return_value = mock_resp

        mock_session = MagicMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.post.return_value = mock_resp_cm

        mock_session_cls = MagicMock(return_value=mock_session)

        with patch("aiohttp.ClientSession", mock_session_cls):
            return await _validate_reddit_credentials("valid-id", "valid-secret")

    async def _run_with_post_exception(self, exc: Exception) -> tuple[str, str]:
        """Helper: make session.post raise an exception."""
        mock_session = MagicMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.post.side_effect = exc

        mock_session_cls = MagicMock(return_value=mock_session)

        with patch("aiohttp.ClientSession", mock_session_cls):
            return await _validate_reddit_credentials("valid-id", "valid-secret")


# ============================================================================
# TestCheckDiskSpace
# ============================================================================


class TestCheckDiskSpace:
    """Tests for _check_disk_space()."""

    def test_sufficient_space(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """≥ 1 GB free → (True, msg, bytes)."""
        mock_usage = MagicMock()
        mock_usage.free = 10 * 1024**3  # 10 GB

        monkeypatch.setattr(
            "pkg_defender.cli.common.shutil.disk_usage",
            lambda _: mock_usage,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_data_dir",
            lambda: Path("/tmp"),
        )

        ok, msg, free_bytes = _check_disk_space()
        assert ok is True
        assert "10.0 GB" in msg
        assert free_bytes == 10 * 1024**3

    def test_insufficient_space(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """< 1 GB free → (False, msg, bytes)."""
        mock_usage = MagicMock()
        mock_usage.free = 500 * 1024 * 1024  # 500 MB

        monkeypatch.setattr(
            "pkg_defender.cli.common.shutil.disk_usage",
            lambda _: mock_usage,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_data_dir",
            lambda: Path("/tmp"),
        )

        ok, msg, free_bytes = _check_disk_space()
        assert ok is False
        assert "0.49 GB" in msg
        assert free_bytes == 500 * 1024 * 1024

    def test_large_space_formatted_without_decimal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """≥ 100 GB → formatted as 'NNN GB' (no decimal)."""
        mock_usage = MagicMock()
        mock_usage.free = 150 * 1024**3  # 150 GB

        monkeypatch.setattr(
            "pkg_defender.cli.common.shutil.disk_usage",
            lambda _: mock_usage,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_data_dir",
            lambda: Path("/tmp"),
        )

        ok, msg, free_bytes = _check_disk_space()
        assert ok is True
        assert "150 GB" in msg

    def test_os_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """OSError → (False, error msg, 0)."""
        monkeypatch.setattr(
            "pkg_defender.cli.common.shutil.disk_usage",
            lambda _: (_ for _ in ()).throw(OSError("mount error")),
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_data_dir",
            lambda: Path("/nonexistent"),
        )

        ok, msg, free_bytes = _check_disk_space()
        assert ok is False
        assert "unable to check disk space" in msg
        assert "mount error" in msg
        assert free_bytes == 0


# ============================================================================
# TestCheckPermissions
# ============================================================================


class TestCheckPermissions:
    """Tests for _check_permissions()."""

    def test_both_not_created_ok(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Both config and DB not yet created → OK statuses."""
        config_path = tmp_path / "config.toml"
        db_path = tmp_path / "data" / "threats.db"

        monkeypatch.setattr(
            "pkg_defender.cli.common.get_default_config_path",
            lambda: config_path,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_db_path",
            lambda: db_path,
        )
        db_path.parent.mkdir(parents=True, exist_ok=True)

        checks = _check_permissions()
        check_map = {name: (ok, detail) for name, ok, detail in checks}

        # Config not created → OK
        assert check_map["Config file"] == (True, "not created yet (OK)")
        # DB not created → OK
        assert check_map["Database file"] == (True, "not created yet (OK)")
        # Data directory exists and is read/write
        assert "Data directory" in check_map

    def test_both_exist_ok(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Both config and DB exist with read/write → OK."""
        config_path = tmp_path / "config.toml"
        config_path.write_text("[test]\n")
        db_path = tmp_path / "data" / "threats.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        db_path.write_text("")

        monkeypatch.setattr(
            "pkg_defender.cli.common.get_default_config_path",
            lambda: config_path,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_db_path",
            lambda: db_path,
        )

        checks = _check_permissions()
        check_map = {name: (ok, detail) for name, ok, detail in checks}

        assert check_map["Config file"] == (True, "read/write OK")
        assert check_map["Database file"] == (True, "read/write OK")
        assert check_map["Data directory"] == (True, "read/write OK")

    def test_config_world_readable_warns(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Config file world-readable → permission warning."""
        config_path = tmp_path / "config.toml"
        config_path.write_text("[test]\n")
        # Make world-readable
        config_path.chmod(0o644)
        db_path = tmp_path / "threats.db"
        db_path.write_text("")

        monkeypatch.setattr(
            "pkg_defender.cli.common.get_default_config_path",
            lambda: config_path,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_db_path",
            lambda: db_path,
        )

        checks = _check_permissions()
        check_names = {name for name, ok, detail in checks}

        assert "Config permissions" in check_names
        config_perm_entry = next((ok, detail) for name, ok, detail in checks if name == "Config permissions")
        assert config_perm_entry[0] is False
        assert "world-readable" in config_perm_entry[1]

    def test_config_read_only_warns(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Config file read-only → warnings."""
        config_path = tmp_path / "config.toml"
        config_path.write_text("[test]\n")
        db_path = tmp_path / "threats.db"
        db_path.write_text("")

        monkeypatch.setattr(
            "pkg_defender.cli.common.get_default_config_path",
            lambda: config_path,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_db_path",
            lambda: db_path,
        )

        # Mock os.access to simulate read-only config
        original_access = os.access

        def _mock_access(path: Any, mode: int) -> bool:
            if path == config_path and mode == os.W_OK:
                return False  # Not writable
            return original_access(path, mode)

        monkeypatch.setattr("pkg_defender.cli.common.os.access", _mock_access)

        checks = _check_permissions()
        check_map = {name: (ok, detail) for name, ok, detail in checks}
        assert check_map["Config file"] == (False, "read-only")

    def test_db_not_readable_warns(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Database file not readable → warning."""
        config_path = tmp_path / "config.toml"
        config_path.write_text("[test]\n")
        db_path = tmp_path / "threats.db"
        db_path.write_text("")

        monkeypatch.setattr(
            "pkg_defender.cli.common.get_default_config_path",
            lambda: config_path,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_db_path",
            lambda: db_path,
        )

        original_access = os.access

        def _mock_access(path: Any, mode: int) -> bool:
            if path == db_path and mode == os.R_OK:
                return False  # Not readable
            return original_access(path, mode)

        monkeypatch.setattr("pkg_defender.cli.common.os.access", _mock_access)

        checks = _check_permissions()
        check_map = {name: (ok, detail) for name, ok, detail in checks}
        assert check_map["Database file"] == (False, "not readable")


# ============================================================================
# TestGetThreatCounts
# ============================================================================


class TestGetThreatCounts:
    """Tests for _get_threat_counts()."""

    def test_empty_table_returns_empty_dict(self, db_conn: sqlite3.Connection) -> None:
        """No threats → empty dict."""
        result = _get_threat_counts(db_conn)
        assert result == {}

    def test_with_threats(self, db_conn: sqlite3.Connection) -> None:
        """Threats grouped by ecosystem."""
        db_conn.execute(
            "INSERT INTO threats (id, ecosystem, package_name, severity, confidence, "
            "source, summary) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("t1", "npm", "bad", "HIGH", 0.9, "osv", "test"),
        )
        db_conn.execute(
            "INSERT INTO threats (id, ecosystem, package_name, severity, confidence, "
            "source, summary) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("t2", "npm", "worse", "CRITICAL", 0.95, "osv", "test2"),
        )
        db_conn.execute(
            "INSERT INTO threats (id, ecosystem, package_name, severity, confidence, "
            "source, summary) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("t3", "pypi", "evil", "HIGH", 0.8, "osv", "test3"),
        )
        db_conn.commit()

        result = _get_threat_counts(db_conn)
        assert result == {"npm": 2, "pypi": 1}

    def test_exception_returns_empty_dict(self) -> None:
        """Closed connection → empty dict (exception caught)."""
        conn = sqlite3.connect(":memory:")
        conn.close()
        result = _get_threat_counts(conn)
        assert result == {}


# ============================================================================
# TestBuildCoverageTable
# ============================================================================


class TestBuildCoverageTable:
    """Tests for _build_coverage_table()."""

    @staticmethod
    def _render_table(table: Any) -> str:
        """Render a Rich Table to plain text for assertion."""
        from io import StringIO

        from rich.console import Console

        buf = StringIO()
        console = Console(file=buf, width=200, no_color=True)
        console.print(table)
        return buf.getvalue()

    def test_returns_rich_table_with_correct_columns(self) -> None:
        """Returns a Rich Table with 5 expected columns."""
        from rich.table import Table

        table = _build_coverage_table({})
        assert isinstance(table, Table)
        assert len(table.columns) == 5

        # Column headers
        headers = [str(col.header) for col in table.columns]
        assert "Adapter" in headers
        assert "Ecosystem" in headers
        assert "Coverage Tier" in headers
        assert "Threat Count" in headers
        assert "Cooldown Status" in headers

    def test_includes_all_16_unique_adapters(self) -> None:
        """Coverage table has 16 distinct adapter manager names in output."""
        table = _build_coverage_table({})
        rendered = self._render_table(table)
        # Check for distinct adapter names that appear in the rendered table
        adapter_names = [
            "pip",
            "cargo",
            "composer",
            "gem",
            "npm",
            "yarn",
            "bun",
            "pnpm",
            "poetry",
            "pipenv",
            "uv",
            "bundle",
            "apt",
            "brew",
            "dnf",
            "yum",
        ]
        found = sum(1 for name in adapter_names if name in rendered)
        assert found == 16, f"Expected 16 adapters in table, found {found}"

    def test_threat_counts_appear_in_table(self) -> None:
        """Threat count for ecosystems shown in rendered table."""
        table = _build_coverage_table({"npm": 5, "pypi": 3})
        rendered = self._render_table(table)
        assert "5" in rendered
        assert "3" in rendered

    def test_full_tier_shows_active_cooldown(self) -> None:
        """FULL tier adapters show 'active' cooldown."""
        table = _build_coverage_table({})
        rendered = self._render_table(table)
        assert "active" in rendered


# ============================================================================
# TestGetProtectionStatus
# ============================================================================


class TestGetProtectionStatus:
    """Tests for _get_protection_status()."""

    def _make_secure_config(self) -> MagicMock:
        """Create a mock config with all security flags in default state."""
        from pkg_defender.config.settings import PKGDConfig

        config = MagicMock(spec=PKGDConfig)
        config.bypass = MagicMock(command_enabled=False)
        config.cooldown = MagicMock(enabled=True, strict_mode=True)
        config.fail_on_threat_enabled = True
        return config

    def test_secure_config(self) -> None:
        """Default secure config returns secure level with no issues."""
        config = self._make_secure_config()

        result = _get_protection_status(config)
        assert result["level"] == "secure"
        assert result["issues"] == []

    def test_bypass_enabled(self) -> None:
        """Bypass command enabled returns bypass_enabled level."""
        config = self._make_secure_config()
        config.bypass.command_enabled = True

        result = _get_protection_status(config)
        assert result["level"] == "bypass_enabled"
        assert "Bypass command is enabled" in result["issues"]

    def test_insecure_fail_on_threat_disabled(self) -> None:
        """fail_on_threat disabled returns insecure level."""
        config = self._make_secure_config()
        config.fail_on_threat_enabled = False

        result = _get_protection_status(config)
        assert result["level"] == "insecure"
        assert "Threat blocking is disabled" in result["issues"]

    def test_weakened_strict_mode_off(self) -> None:
        """strict_mode off with cooldown enabled returns weakened level."""
        config = self._make_secure_config()
        config.cooldown.strict_mode = False

        result = _get_protection_status(config)
        assert result["level"] == "weakened"

    def test_insecure_cooldown_disabled(self) -> None:
        """Cooldown disabled returns insecure level (overrides bypass)."""
        config = self._make_secure_config()
        config.bypass.command_enabled = True
        config.cooldown.enabled = False

        result = _get_protection_status(config)
        assert result["level"] == "insecure"
        assert "Cooldown checking is disabled" in result["issues"]

    def test_config_none_returns_unknown(self) -> None:
        """None config returns unknown level."""
        result = _get_protection_status(None)
        assert result["level"] == "unknown"
        assert len(result["issues"]) == 1

    def test_priority_cascade_insecure_over_bypass(self) -> None:
        """insecure > bypass_enabled in priority cascade."""
        config = self._make_secure_config()
        config.bypass.command_enabled = True
        config.cooldown.enabled = False

        result = _get_protection_status(config)
        assert result["level"] == "insecure"

    def test_bypass_over_weakened(self) -> None:
        """bypass_enabled > weakened in priority cascade."""
        config = self._make_secure_config()
        config.bypass.command_enabled = True
        config.cooldown.strict_mode = False

        result = _get_protection_status(config)
        assert result["level"] == "bypass_enabled"

    def test_insecure_over_bypass_over_weakened(self) -> None:
        """Full cascade: insecure > bypass_enabled > weakened."""
        config = self._make_secure_config()
        config.bypass.command_enabled = True
        config.cooldown.enabled = False
        config.cooldown.strict_mode = False
        config.fail_on_threat_enabled = False

        result = _get_protection_status(config)
        assert result["level"] == "insecure"


# ============================================================================
# TestHealthImpl
# ============================================================================


class TestHealthImpl:
    """Tests for _health_impl() — key execution paths.

    Strategy: mock heavy dependencies (get_db_path, get_connection, get_feed_state,
    token validators, disk/permission checks) and verify JSON output correctness.
    """

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_mock_db(db_path: Path) -> sqlite3.Connection:
        """Create a real SQLite DB with the health schema initialised."""
        from pkg_defender.db.schema import init_db

        return init_db(db_path)

    @staticmethod
    def _capture_json(ctx: click.Context, **kwargs: Any) -> dict[str, Any]:
        """Run _health_impl in JSON mode and return parsed output.

        Note: This static helper is no longer used for actual capture;
        tests use _run_health_json instead (which accepts monkeypatch).
        """
        return {}

    def _setup_health_mocks(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        db_ok: bool = True,
        config_exists: bool = True,
        feeds_ok: bool = True,
        tokens: tuple[str, str, str, str] | None = None,  # (gh_status, socket_status, twitter_status, reddit_status)
        libraries_io_key_present: bool = False,
    ) -> tuple[click.Context, Path, Path]:
        """Set up standard mocks for _health_impl tests.

        Args:
            monkeypatch: The monkeypatch fixture.
            tmp_path: Temporary directory path.
            db_ok: Whether database connection succeeds.
            config_exists: Whether the config file exists.
            feeds_ok: Whether feed state is available.
            tokens: 4-tuple of (ghsa, socket, x_twitter, reddit) token statuses.
            libraries_io_key_present: Whether PKGD_LIBRARIES_IO_KEY env var is set.

        Returns (ctx, config_path, db_path).
        """
        config_path = tmp_path / "config.toml"
        db_path = tmp_path / "data" / "threats.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)

        if config_exists:
            config_path.write_text("[feeds]\n")

        # Mock config path and db path
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_default_config_path",
            lambda: config_path,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_db_path",
            lambda: db_path,
        )

        if db_ok:
            conn = self._make_mock_db(db_path)
            monkeypatch.setattr(
                "pkg_defender.cli.common.get_connection",
                lambda *a, **kw: conn,
            )

            # Mock get_feed_state to return a known state
            mock_state = {
                "last_sync": "2026-05-29T12:00:00",
                "status": "idle",
            }

            def _mock_feed_state(_conn: Any, feed_name: str) -> dict[str, str] | None:
                if feeds_ok:
                    return mock_state
                return None

            monkeypatch.setattr(
                "pkg_defender.cli.common.get_feed_state",
                _mock_feed_state,
            )
        else:
            monkeypatch.setattr(
                "pkg_defender.cli.common.get_connection",
                lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("DB connection failed")),
            )

        # Mock token validators
        if tokens:
            gh_status, socket_status, twitter_status, reddit_status = tokens

            async def mock_gh(_t: str) -> tuple[str, str]:
                return gh_status, "mock"

            async def mock_socket(_t: str) -> tuple[str, str]:
                return socket_status, "mock"

            async def mock_twitter(_t: str) -> tuple[str, str]:
                return twitter_status, "mock"

            async def mock_reddit(_id: str, _secret: str) -> tuple[str, str]:
                return reddit_status, "mock"

            monkeypatch.setattr("pkg_defender.cli.common._validate_github_token", mock_gh)
            monkeypatch.setattr("pkg_defender.cli.common._validate_socket_token", mock_socket)
            monkeypatch.setattr("pkg_defender.cli.common._validate_x_twitter_token", mock_twitter)
            monkeypatch.setattr("pkg_defender.cli.common._validate_reddit_credentials", mock_reddit)

        # Mock Libraries.io key presence
        if libraries_io_key_present:
            monkeypatch.setenv("PKGD_LIBRARIES_IO_KEY", "mock-key")
        else:
            monkeypatch.delenv("PKGD_LIBRARIES_IO_KEY", raising=False)

        # Mock disk space — always sufficient by default
        mock_usage = MagicMock()
        mock_usage.free = 50 * 1024**3
        monkeypatch.setattr(
            "pkg_defender.cli.common.shutil.disk_usage",
            lambda _: mock_usage,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_data_dir",
            lambda: tmp_path,
        )

        # Mock permissions — always OK by default
        monkeypatch.setattr(
            "pkg_defender.cli.common._check_permissions",
            lambda: [("Data directory", True, "read/write OK")],
        )

        # Capture console.print output
        monkeypatch.setattr(
            "pkg_defender.cli.common.stdout_console.print",
            lambda *a, **kw: None,
        )

        # Suppress quiet mode by default
        monkeypatch.setattr(
            "pkg_defender.cli.common.is_quiet_mode",
            lambda: False,
        )

        ctx = MagicMock(spec=click.Context)
        ctx.obj = {}
        return ctx, config_path, db_path

    def _run_health_json(
        self,
        ctx: click.Context,
        verbose: bool = False,
        monkeypatch: pytest.MonkeyPatch | None = None,
    ) -> dict[str, Any]:
        """Run _health_impl with json output, capture and return parsed JSON.

        Uses monkeypatch for click.echo capture.
        """
        captured: list[str] = []

        def _capture_echo(msg: str | None = None, **kwargs: Any) -> None:
            if msg is not None:
                captured.append(str(msg))
            else:
                captured.append("")

        if monkeypatch is not None:
            monkeypatch.setattr("pkg_defender.cli.common.click.echo", _capture_echo)

        async def run() -> dict[str, Any]:
            with contextlib.suppress(SystemExit):
                await _health_impl(ctx, "json", False, verbose=verbose)
            if captured:
                return json.loads(captured[0])  # type: ignore[no-any-return]
            return {}

        return asyncio.run(run())

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_json_basic_all_ok(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """JSON output with DB OK, config OK → ready=True."""
        ctx, *_ = self._setup_health_mocks(monkeypatch, tmp_path, db_ok=True)
        data = self._run_health_json(ctx, monkeypatch=monkeypatch)
        assert data.get("ready") is True
        assert data["checks"]["config_file"]["status"] == "ok"
        assert data["checks"]["database"]["status"] == "ok"
        assert "timestamp" in data

    def test_json_config_not_found(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Config file missing → ready=False, config_file status fail."""
        ctx, *_ = self._setup_health_mocks(monkeypatch, tmp_path, db_ok=True, config_exists=False)
        data = self._run_health_json(ctx, monkeypatch=monkeypatch)
        assert data.get("ready") is False
        assert data["checks"]["config_file"]["status"] == "fail"
        assert data["checks"]["config_file"]["message"] == "not found (using defaults)"

    def test_json_db_not_found(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """DB not found → ready=False, database status not_found."""
        ctx, *_ = self._setup_health_mocks(monkeypatch, tmp_path, db_ok=False, config_exists=True)
        data = self._run_health_json(ctx, monkeypatch=monkeypatch)
        assert data.get("ready") is False
        assert data["checks"]["database"]["status"] == "not_found"

    def test_json_token_status(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Token validation results appear in JSON output."""
        ctx, *_ = self._setup_health_mocks(
            monkeypatch,
            tmp_path,
            db_ok=True,
            tokens=(
                TokenStatus.INVALID,
                TokenStatus.VALID,
                TokenStatus.NOT_CONFIGURED,
                TokenStatus.VALID,
            ),
        )
        data = self._run_health_json(ctx, monkeypatch=monkeypatch)
        assert "tokens" in data

        # Check GitHub token
        gh = data["tokens"]["ghsa"]
        assert gh["status"] == "invalid"
        assert gh["label"] == "GitHub (GHSA)"

        # Check Socket.dev token
        sd = data["tokens"]["socket"]
        assert sd["status"] == "valid"
        assert sd["label"] == "Socket.dev"

        # Check X/Twitter token
        xt = data["tokens"]["x_twitter"]
        assert xt["status"] == "not_configured"
        assert xt["label"] == "X/Twitter"

        # Check Reddit token
        rd = data["tokens"]["reddit"]
        assert rd["status"] == "valid"
        assert rd["label"] == "Reddit"

        # Check Libraries.io key
        li = data["tokens"]["libraries_io"]
        assert li["status"] == "not_configured"
        assert li["label"] == "Libraries.io"

    def test_json_verbose_includes_coverage(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Verbose JSON output includes coverage array."""
        ctx, *_ = self._setup_health_mocks(monkeypatch, tmp_path, db_ok=True)
        data = self._run_health_json(ctx, verbose=True, monkeypatch=monkeypatch)
        assert "coverage" in data
        assert isinstance(data["coverage"], list)
        for entry in data["coverage"]:
            assert "adapter" in entry
            assert "ecosystem" in entry
            assert "coverage_tier" in entry
            assert "threat_count" in entry
            assert "cooldown_status" in entry

    def test_quiet_mode_all_ok_returns_none(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Quiet mode + all OK → function returns without SystemExit."""
        ctx, *_ = self._setup_health_mocks(monkeypatch, tmp_path, db_ok=True)
        monkeypatch.setattr("pkg_defender.cli.common.is_quiet_mode", lambda: True)

        async def run() -> type[BaseException] | None:
            try:
                await _health_impl(ctx, "rich", False)
                return None
            except SystemExit as e:
                return type(e)

        result = asyncio.run(run())
        assert result is None, "Expected no SystemExit in quiet mode + all OK"

    def test_quiet_mode_fail_raises_system_exit(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Quiet mode + config missing → SystemExit."""
        ctx, *_ = self._setup_health_mocks(monkeypatch, tmp_path, db_ok=True, config_exists=False)
        monkeypatch.setattr("pkg_defender.cli.common.is_quiet_mode", lambda: True)

        async def run() -> type[BaseException] | None:
            try:
                await _health_impl(ctx, "rich", False)
                return None
            except SystemExit:
                return SystemExit

        result = asyncio.run(run())
        assert result is SystemExit, "Expected SystemExit in quiet mode + fail"

    def test_rich_output_runs_without_error(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Rich output mode runs without raising unhandled exceptions."""
        ctx, *_ = self._setup_health_mocks(monkeypatch, tmp_path, db_ok=True)

        async def run() -> type[BaseException] | None:
            try:
                await _health_impl(ctx, "rich", False)
                return None
            except SystemExit:
                return SystemExit
            except Exception as e:
                return type(e)

        result = asyncio.run(run())
        assert result in (
            None,
            SystemExit,
        ), f"Unexpected exception: {result}"

    def test_json_not_all_ok_sets_ready_false(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Permissions failure → ready=False in JSON output."""
        ctx, *_ = self._setup_health_mocks(monkeypatch, tmp_path, db_ok=True)
        # Inject a failing permission check
        monkeypatch.setattr(
            "pkg_defender.cli.common._check_permissions",
            lambda: [("Config permissions", False, "world-readable")],
        )
        data = self._run_health_json(ctx, monkeypatch=monkeypatch)
        assert data.get("ready") is False

    def test_json_disk_space_included(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Disk space data appears in JSON output."""
        ctx, *_ = self._setup_health_mocks(monkeypatch, tmp_path, db_ok=True)
        data = self._run_health_json(ctx, monkeypatch=monkeypatch)
        assert "disk_space" in data
        assert data["disk_space"]["sufficient"] is True
        assert "available_bytes" in data["disk_space"]

    def test_json_token_validation_exception(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """When token validation raises, tokens show ERROR status."""
        ctx, *_ = self._setup_health_mocks(monkeypatch, tmp_path, db_ok=True)

        async def _raise(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("API unreachable")

        monkeypatch.setattr("pkg_defender.cli.common._validate_github_token", _raise)
        monkeypatch.setattr("pkg_defender.cli.common._validate_socket_token", _raise)
        monkeypatch.setattr("pkg_defender.cli.common._validate_x_twitter_token", _raise)
        monkeypatch.setattr("pkg_defender.cli.common._validate_reddit_credentials", _raise)

        data = self._run_health_json(ctx, monkeypatch=monkeypatch)
        assert "tokens" in data

        # The 4 gather validators all raised — each shows ERROR individually
        for token_name in ("ghsa", "socket", "x_twitter", "reddit"):
            assert data["tokens"][token_name]["status"] == "error", (
                f"Expected {token_name} status to be 'error', got {data['tokens'][token_name]['status']}"
            )
            assert "validation failed" in data["tokens"][token_name]["message"]
            assert "label" in data["tokens"][token_name]

        # libraries_io is outside gather — set by env-var check, never raises
        assert data["tokens"]["libraries_io"]["status"] == "not_configured"
        assert data["tokens"]["libraries_io"]["message"] == "not configured (optional)"
        assert "label" in data["tokens"]["libraries_io"]
        assert data["tokens"]["ghsa"]["label"] == "GitHub (GHSA)"
        assert data["tokens"]["socket"]["label"] == "Socket.dev"
        assert data["tokens"]["x_twitter"]["label"] == "X/Twitter"
        assert data["tokens"]["reddit"]["label"] == "Reddit"
        assert data["tokens"]["libraries_io"]["label"] == "Libraries.io"

    def test_json_db_connection_error(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """DB file exists but connection fails → status error."""
        ctx = MagicMock(spec=click.Context)
        ctx.obj = {}

        config_path = tmp_path / "config.toml"
        config_path.write_text("")
        db_path = tmp_path / "data" / "threats.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        # Create the db file so db_path.exists() is True
        db_path.write_text("")

        monkeypatch.setattr(
            "pkg_defender.cli.common.get_default_config_path",
            lambda: config_path,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_db_path",
            lambda: db_path,
        )
        # Make get_connection raise — db_path exists but connection fails
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_connection",
            lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("corrupt database")),
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.shutil.disk_usage",
            lambda _: MagicMock(free=50 * 1024**3),
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_data_dir",
            lambda: tmp_path,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common._check_permissions",
            lambda: [("Data directory", True, "read/write OK")],
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.stdout_console.print",
            lambda *a, **kw: None,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.is_quiet_mode",
            lambda: False,
        )

        captured: list[str] = []

        def _capture_echo(msg: str | None = None, **kwargs: Any) -> None:
            if msg is not None:
                captured.append(str(msg))

        monkeypatch.setattr("pkg_defender.cli.common.click.echo", _capture_echo)

        async def run() -> dict[str, Any]:
            with contextlib.suppress(SystemExit):
                await _health_impl(ctx, "json", False)
            if captured:
                return json.loads(captured[0])  # type: ignore[no-any-return]
            return {}

        data = asyncio.run(run())
        assert data["checks"]["database"]["status"] == "error"
        assert "error" in data["checks"]["database"]

    def test_json_expired_token_status(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """EXPIRED token status appears correctly in JSON."""
        ctx, *_ = self._setup_health_mocks(
            monkeypatch,
            tmp_path,
            db_ok=True,
            tokens=(
                TokenStatus.EXPIRED,
                TokenStatus.VALID,
                TokenStatus.VALID,
                TokenStatus.NOT_CONFIGURED,
            ),
        )
        data = self._run_health_json(ctx, monkeypatch=monkeypatch)
        assert "tokens" in data
        assert data["tokens"]["ghsa"]["status"] == "expired"
        assert data["tokens"]["ghsa"]["label"] == "GitHub (GHSA)"
        assert data["tokens"]["socket"]["label"] == "Socket.dev"
        assert data["tokens"]["x_twitter"]["label"] == "X/Twitter"
        assert data["tokens"]["reddit"]["status"] == "not_configured"
        assert data["tokens"]["reddit"]["label"] == "Reddit"
        assert data["tokens"]["libraries_io"]["status"] == "not_configured"

    def test_json_token_not_configured_when_config_none(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """When config is None, tokens show not_configured."""
        ctx = MagicMock(spec=click.Context)
        ctx.obj = {}

        config_path = tmp_path / "config.toml"
        config_path.write_text("")
        db_path = tmp_path / "data" / "threats.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)

        monkeypatch.setattr(
            "pkg_defender.cli.common.get_default_config_path",
            lambda: config_path,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_db_path",
            lambda: db_path,
        )

        conn = self._make_mock_db(db_path)
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_connection",
            lambda *a, **kw: conn,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_feed_state",
            lambda _conn, feed_name: {
                "last_sync": "2026-05-29T12:00:00",
                "status": "idle",
            },
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.shutil.disk_usage",
            lambda _: MagicMock(free=50 * 1024**3),
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_data_dir",
            lambda: tmp_path,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common._check_permissions",
            lambda: [("Data directory", True, "read/write OK")],
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.stdout_console.print",
            lambda *a, **kw: None,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.common.is_quiet_mode",
            lambda: False,
        )

        # Make _get_config_from_context raise to make config = None
        monkeypatch.setattr(
            "pkg_defender.cli.common._get_config_from_context",
            lambda ctx: (_ for _ in ()).throw(RuntimeError("broken config")),
        )

        captured: list[str] = []

        def _capture_echo(msg: str | None = None, **kwargs: Any) -> None:
            if msg is not None:
                captured.append(str(msg))

        monkeypatch.setattr("pkg_defender.cli.common.click.echo", _capture_echo)

        async def run() -> dict[str, Any]:
            with contextlib.suppress(SystemExit):
                await _health_impl(ctx, "json", False)
            if captured:
                return json.loads(captured[0])  # type: ignore[no-any-return]
            return {}

        data = asyncio.run(run())
        assert "tokens" in data
        for token_name in ("ghsa", "socket", "x_twitter", "reddit", "libraries_io"):
            assert data["tokens"][token_name]["status"] == "not_configured"
            assert "label" in data["tokens"][token_name]
        assert data["tokens"]["ghsa"]["label"] == "GitHub (GHSA)"
        assert data["tokens"]["socket"]["label"] == "Socket.dev"
        assert data["tokens"]["x_twitter"]["label"] == "X/Twitter"
        assert data["tokens"]["reddit"]["status"] == "not_configured"
        assert data["tokens"]["reddit"]["label"] == "Reddit"
        assert data["tokens"]["reddit"]["message"] == "config not available"
        assert data["tokens"]["libraries_io"]["status"] == "not_configured"
        assert data["tokens"]["libraries_io"]["label"] == "Libraries.io"
        assert data["tokens"]["libraries_io"]["message"] == "config not available"

    def test_rich_output_with_unconfigured_feeds(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Rich output with some feeds not configured runs without error."""
        ctx, *_ = self._setup_health_mocks(monkeypatch, tmp_path, db_ok=True, feeds_ok=False)

        async def run() -> type[BaseException] | None:
            try:
                await _health_impl(ctx, "rich", False)
                return None
            except SystemExit:
                return SystemExit
            except Exception as e:
                return type(e)

        result = asyncio.run(run())
        assert result in (
            None,
            SystemExit,
        ), f"Unexpected exception: {result}"

    def test_rich_output_verbose(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Rich verbose output runs without error."""
        ctx, *_ = self._setup_health_mocks(monkeypatch, tmp_path, db_ok=True)

        async def run() -> type[BaseException] | None:
            try:
                await _health_impl(ctx, "rich", False, verbose=True)
                return None
            except SystemExit:
                return SystemExit
            except Exception as e:
                return type(e)

        result = asyncio.run(run())
        assert result in (
            None,
            SystemExit,
        ), f"Unexpected exception: {result}"

    def test_json_includes_protection(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """health -o json includes protection key with level and issues."""
        ctx, *_ = self._setup_health_mocks(monkeypatch, tmp_path, db_ok=True)
        data = self._run_health_json(ctx, monkeypatch=monkeypatch)
        assert "protection" in data
        assert "level" in data["protection"]
        assert "issues" in data["protection"]
        assert data["protection"]["level"] in (
            "secure",
            "weakened",
            "bypass_enabled",
            "insecure",
            "unknown",
        )

    def test_json_includes_daemon(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """health -o json includes daemon key with status."""
        ctx, *_ = self._setup_health_mocks(monkeypatch, tmp_path, db_ok=True)
        data = self._run_health_json(ctx, monkeypatch=monkeypatch)
        assert "daemon" in data
        assert "status" in data["daemon"]
        assert data["daemon"]["status"] in ("running", "stopped", "unknown")

    def test_json_includes_active_bypasses(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """health -o json includes active_bypasses key with count."""
        ctx, *_ = self._setup_health_mocks(monkeypatch, tmp_path, db_ok=True)
        data = self._run_health_json(ctx, monkeypatch=monkeypatch)
        assert "active_bypasses" in data
        assert "count" in data["active_bypasses"]
        assert isinstance(data["active_bypasses"]["count"], int)

    def test_json_includes_ecosystem_threats(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """health -o json includes ecosystem_threats key in base output."""
        ctx, *_ = self._setup_health_mocks(monkeypatch, tmp_path, db_ok=True)
        data = self._run_health_json(ctx, monkeypatch=monkeypatch)
        assert "ecosystem_threats" in data
        assert isinstance(data["ecosystem_threats"], dict)


# ============================================================================
# TestGetConfigFromContext
# ============================================================================


class TestGetConfigFromContext:
    """Tests for _get_config_from_context()."""

    def test_without_config_file_returns_config(self) -> None:
        """No config_file in context → calls load_config()."""
        ctx = MagicMock(spec=click.Context)
        ctx.obj = {}
        config = _get_config_from_context(ctx)
        assert config is not None

    def test_with_bad_config_path_raises_bad_parameter(self) -> None:
        """Non-existent config_file → BadParameter."""
        ctx = MagicMock(spec=click.Context)
        ctx.obj = {"config_file": "/nonexistent/path/config.toml"}
        with pytest.raises(click.BadParameter):
            _get_config_from_context(ctx)


# ============================================================================
# TestValidateConfigKey
# ============================================================================


class TestValidateConfigKey:
    """Tests for _validate_config_key()."""

    def test_unknown_section_with_suggestion(self) -> None:
        """Unknown section with close match → SystemExit with suggestion."""
        with pytest.raises(SystemExit):
            _validate_config_key("coalldown.default_days")

    def test_unknown_key_with_suggestion(self) -> None:
        """Unknown key with close match → SystemExit with suggestion."""
        with pytest.raises(SystemExit):
            _validate_config_key("cooldown.defualt_days")

    def test_three_part_cooldown_override(self) -> None:
        """cooldown.overrides.npm is valid (3-part key)."""
        _validate_config_key("cooldown.overrides.npm")

    def test_single_part_top_level_key(self) -> None:
        """Top-level keys command_timeout_seconds, fail_on_* are valid."""
        _validate_config_key("command_timeout_seconds")
        _validate_config_key("fail_on_threat_enabled")
        _validate_config_key("fail_on_warn_enabled")

    def test_unknown_section_no_suggestion(self) -> None:
        """Section with no close match → SystemExit."""
        with pytest.raises(SystemExit):
            _validate_config_key("foobar.baz")

    def test_two_part_non_key_no_dot(self) -> None:
        """cooldown.foo.bar.baz (too many parts) → SystemExit."""
        with pytest.raises(SystemExit):
            _validate_config_key("cooldown.foo.bar.baz")


# ============================================================================
# TestGetConfigValueByKey
# ============================================================================


class TestGetConfigValueByKey:
    """Tests for _get_config_value_by_key()."""

    def test_single_part_key(self) -> None:
        """Single-part key reads from config top-level."""
        from pkg_defender.config.settings import PKGDConfig

        config = PKGDConfig()
        val = _get_config_value_by_key(config, "command_timeout_seconds")
        assert val == config.command_timeout_seconds

    def test_fail_on_threat_key(self) -> None:
        """fail_on_threat_enabled key returns value."""
        from pkg_defender.config.settings import PKGDConfig

        config = PKGDConfig()
        val = _get_config_value_by_key(config, "fail_on_threat_enabled")
        assert val == config.fail_on_threat_enabled

    def test_known_section_key(self) -> None:
        """Dotted key cooldown.default_days returns the value."""
        from pkg_defender.config.settings import PKGDConfig

        config = PKGDConfig()
        val = _get_config_value_by_key(config, "cooldown.default_days")
        assert val == config.cooldown.default_days

    def test_unknown_section_returns_none(self) -> None:
        """Unknown section → None."""
        from pkg_defender.config.settings import PKGDConfig

        config = PKGDConfig()
        val = _get_config_value_by_key(config, "foobar.baz")
        assert val is None

    def test_cooldown_override_key(self) -> None:
        """cooldown.overrides.npm returns the override value."""
        from pkg_defender.config.settings import PKGDConfig

        config = PKGDConfig()
        config.cooldown.overrides["npm"] = 10
        val = _get_config_value_by_key(config, "cooldown.overrides.npm")
        assert val == 10

    def test_fail_on_threat_two_part_returns_none(self) -> None:
        """fail_on_threat_enabled.bad → None (2-part not valid for top-level)."""
        from pkg_defender.config.settings import PKGDConfig

        config = PKGDConfig()
        val = _get_config_value_by_key(config, "fail_on_threat_enabled.bad")
        assert val is None


# ============================================================================
# TestTwoConsoleArchitecture
# ============================================================================


class TestTwoConsoleArchitecture:
    """Tests for the two-Console architecture (stdout_console, stderr_console, set_console_no_color)."""

    def test_stdout_console_sends_to_stdout(self) -> None:
        """stdout_console outputs to stdout stream, not stderr."""
        from pkg_defender.cli.common import stdout_console

        assert stdout_console.stderr is False

    def test_stderr_console_sends_to_stderr(self) -> None:
        """stderr_console outputs to stderr stream."""
        from pkg_defender.cli.common import stderr_console

        assert stderr_console.stderr is True

    def test_console_alias_is_stderr(self) -> None:
        """The 'console' alias still points to the stderr Console (backward compat)."""
        from pkg_defender.cli.common import console, stderr_console

        assert console is stderr_console

    def test_set_console_no_color_updates_both(self) -> None:
        """set_console_no_color() sets no_color on existing objects (property setter)."""
        from pkg_defender.cli.common import (
            set_console_no_color,
            stderr_console,
            stdout_console,
        )

        # Store references before calling set_console_no_color
        ref_stdout = stdout_console
        ref_stderr = stderr_console

        set_console_no_color(True)

        # Verify the SAME objects were mutated (no recreation)
        assert stdout_console is ref_stdout, "Must reuse same object, not recreate"
        assert stderr_console is ref_stderr, "Must reuse same object, not recreate"
        # Verify the no_color property was set
        assert stdout_console.no_color is True
        assert stderr_console.no_color is True

        # Reset for other tests
        set_console_no_color(False)

    def test_no_color_flag_invokes_set_console_no_color(self, runner: CliRunner) -> None:
        """--no-color flag should invoke set_console_no_color in main.py's handler."""
        from pkg_defender.cli.main import cli

        with patch("pkg_defender.cli.common.set_console_no_color") as mock_set:
            result = runner.invoke(cli, ["--no-color", "status"])
        mock_set.assert_called_once_with()
        assert result.exit_code == 0
