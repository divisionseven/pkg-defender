"""Tests for timeout enforcement on install/upgrade commands."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pkg_defender.cli.dispatcher import ManagerDispatcher
from pkg_defender.models.command import CommandIntent, InstallSource, PackageRef, ParsedCommand


class TestTimeoutEnforcement:
    """Tests for timeout enforcement in dispatcher."""

    @patch("pkg_defender.registry.get_adapter_class_for_manager")
    def test_timeout_not_triggered_for_safe_passthrough(self, mock_get_adapter: MagicMock) -> None:
        """Test that timeout is not triggered for SAFE_PASSTHROUGH commands."""
        mock_adapter = MagicMock()
        mock_parsed = ParsedCommand(intent=CommandIntent.SAFE_PASSTHROUGH, packages=[])
        mock_adapter.parse.return_value = mock_parsed

        mock_get_adapter.return_value = MagicMock(return_value=mock_adapter)

        # Mock exec_cleared_command to avoid actual exec
        with patch("pkg_defender.cli.exec.exec_cleared_command"):
            dispatcher = ManagerDispatcher("pip")
            # Should not raise timeout error
            dispatcher.run(["--version"], MagicMock())

    @patch("pkg_defender.registry.get_adapter_class_for_manager")
    def test_timeout_not_triggered_for_remove(self, mock_get_adapter: MagicMock) -> None:
        """Test that timeout is not triggered for REMOVE commands."""
        mock_adapter = MagicMock()
        mock_parsed = ParsedCommand(intent=CommandIntent.REMOVE, packages=[])
        mock_adapter.parse.return_value = mock_parsed

        mock_get_adapter.return_value = MagicMock(return_value=mock_adapter)

        # Mock exec_cleared_command to avoid actual exec
        with patch("pkg_defender.cli.exec.exec_cleared_command"):
            dispatcher = ManagerDispatcher("pip")
            # Should not raise timeout error
            dispatcher.run(["uninstall", "requests"], MagicMock())

    @patch("pkg_defender.registry.get_adapter_class_for_manager")
    def test_timeout_configurable_via_env_var(
        self,
        mock_get_adapter: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that timeout is configurable via environment variable."""
        # Verify env var override path works — 60s timeout via env var
        monkeypatch.setenv("PKGD_COMMAND_TIMEOUT", "60")

        mock_adapter = MagicMock()
        mock_parsed = ParsedCommand(
            intent=CommandIntent.INSTALL,
            packages=[],
        )
        mock_adapter.parse.return_value = mock_parsed

        mock_get_adapter.return_value = MagicMock(return_value=mock_adapter)

        # Prevent file leak: redirect get_db_path to a temp path
        db_path = tmp_path / "threats.db"
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda: db_path,
        )

        # Create dispatcher
        dispatcher = ManagerDispatcher("pip")

        # Mock _run_pre_install_check_async to complete quickly
        async def fast_check(*args: object, **kwargs: object) -> None:
            await asyncio.sleep(0.1)  # Complete quickly

        with (
            patch.object(dispatcher, "_run_pre_install_check_async", side_effect=fast_check),
            patch("pkg_defender.cli.exec.exec_cleared_command"),
        ):
            # Should not raise timeout error with 60s timeout
            dispatcher.run(["install", "requests"], MagicMock())

    def test_timeout_raises_system_exit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_run_pre_install_with_timeout raises SystemExit(1) on TimeoutError."""
        # Set a very short timeout so the test completes quickly
        monkeypatch.setenv("PKGD_COMMAND_TIMEOUT", "0")

        dispatcher = ManagerDispatcher("pip")

        # Mock the adapter so ecosystem resolution doesn't fail
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.ecosystem = "pypi"

        # Mock _ensure_db_fresh to be a no-op (it's synchronous)
        with patch.object(dispatcher, "_ensure_db_fresh", return_value=True):
            # Mock _run_pre_install_check_async to sleep forever (will timeout)
            async def _never_return(*args: object, **kwargs: object) -> None:
                await asyncio.sleep(999)

            dispatcher._run_pre_install_check_async = _never_return  # type: ignore[assignment]

            parsed = MagicMock(spec=ParsedCommand)
            parsed.intent = CommandIntent.EXECUTE
            parsed.pkgd_flags = {}
            parsed.manager_args = ["run", "script.py"]
            parsed.original_manager = None
            parsed.args = []
            parsed.flag_args = []
            parsed.separator_index = None
            parsed.dlx_name = None
            ctx = MagicMock()

            with pytest.raises(SystemExit) as exc_info:
                dispatcher._run_pre_install_with_timeout(parsed, ctx)

            assert exc_info.value.code == 1

    def test_input_not_called_inside_timeout(self) -> None:
        """Detection phase returns BlockDecision — blocking is deferred, not executed."""
        from pkg_defender.models.command import BlockReason

        # Build a real dispatcher with a mocked adapter that triggers LOCAL_PATH
        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = MagicMock()

        parsed = ParsedCommand(
            packages=[PackageRef(name="mypkg", version="1.0", source=InstallSource.LOCAL_PATH)],
            pkgd_flags={},
        )
        ctx = MagicMock()

        with patch("pkg_defender.cli.exec.handle_blocked_command") as mock_hbc:
            result = dispatcher._run_pre_install_check(parsed, ctx)

        # handle_blocked_command must NOT be called during detection
        mock_hbc.assert_not_called()
        # The result must contain a BlockDecision for LOCAL_PATH
        assert len(result) == 1
        assert result[0].reason == BlockReason.LOCAL_PATH
        assert result[0].package.name == "mypkg"

    def test_block_decision_propagated_after_timeout(self) -> None:
        """Block decisions from detection are processed after timeout scope, not inside it."""
        from pkg_defender.models.command import BlockReason

        # Build a real dispatcher with a mocked adapter that triggers LOCAL_PATH
        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = MagicMock()

        parsed = ParsedCommand(
            packages=[PackageRef(name="mypkg", version="1.0", source=InstallSource.LOCAL_PATH)],
            pkgd_flags={},
        )
        ctx = MagicMock()

        # Patch _ensure_db_fresh and _check_protection_warning to skip DB/sync work
        with (
            patch.object(dispatcher, "_ensure_db_fresh"),
            patch.object(dispatcher, "_check_protection_warning"),
            patch("pkg_defender.config.load_config") as mock_config,
            patch("pkg_defender.cli.exec.handle_blocked_command") as mock_hbc,
        ):
            mock_config.return_value.command_timeout_seconds = 30
            dispatcher._run_pre_install_with_timeout(parsed, ctx)

        # handle_blocked_command IS called AFTER the timeout scope
        mock_hbc.assert_called_once()
        args = mock_hbc.call_args
        assert args[0][1] == BlockReason.LOCAL_PATH
        assert args[0][2].name == "mypkg"

    def test_vcs_input_outside_timeout(self) -> None:
        """VCS source detection returns BlockDecision — not acted on during detection."""
        from pkg_defender.models.command import BlockReason

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = MagicMock()

        parsed = ParsedCommand(
            packages=[PackageRef(name="mypkg", version=None, source=InstallSource.VCS)],
            pkgd_flags={},
        )
        ctx = MagicMock()

        with patch("pkg_defender.cli.exec.handle_blocked_command") as mock_hbc:
            result = dispatcher._run_pre_install_check(parsed, ctx)

        # handle_blocked_command must NOT be called during detection
        mock_hbc.assert_not_called()
        # The result must contain a BlockDecision for VCS_SOURCE
        assert len(result) == 1
        assert result[0].reason == BlockReason.VCS_SOURCE
        assert result[0].package.name == "mypkg"
        assert result[0].package.version is None
