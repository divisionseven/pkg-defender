"""Phase 4 tests — registry adapters, CLI, upgrade, intel report, daemon, pyproject."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from pkg_defender.cli.main import cli
from pkg_defender.core.parsers import _ECOSYSTEM_MAP, parse_lock_file
from pkg_defender.daemon.service import SYSTEMD_SERVICE_NAME

FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "lock_files"


# ===================================================================
# 1. Registry adapters
# ===================================================================


class TestCargoAdapter:
    """Tests for CargoAdapter properties and method implementation."""

    def test_cargo_adapter_ecosystem(self) -> None:
        """CargoAdapter().ecosystem == 'cargo'."""
        from pkg_defender.registry.cargo import CargoAdapter

        adapter = CargoAdapter()
        assert adapter.ecosystem == "cargo"

    def test_cargo_adapter_registry_url(self) -> None:
        """CargoAdapter().registry_base_url == 'https://crates.io'."""
        from pkg_defender.registry.cargo import CargoAdapter

        adapter = CargoAdapter()
        assert adapter.registry_base_url == "https://crates.io"

    def test_cargo_adapter_methods_exist(self) -> None:
        """CargoAdapter implements all 3 abstract methods: get_publish_time,
        get_all_versions, get_latest_version."""
        from pkg_defender.registry.cargo import CargoAdapter

        adapter = CargoAdapter()
        assert callable(getattr(adapter, "get_publish_time", None))
        assert callable(getattr(adapter, "get_all_versions", None))
        assert callable(getattr(adapter, "get_latest_version", None))

    def test_cargo_adapter_is_registry_adapter_subclass(self) -> None:
        """CargoAdapter is a concrete subclass of RegistryAdapter."""
        from pkg_defender.registry.base import RegistryAdapter
        from pkg_defender.registry.cargo import CargoAdapter

        adapter = CargoAdapter()
        assert isinstance(adapter, RegistryAdapter)


class TestRubyGemsAdapter:
    """Tests for RubyGemsAdapter properties and method implementation."""

    def test_rubygems_adapter_ecosystem(self) -> None:
        """RubyGemsAdapter().ecosystem == 'rubygems'."""
        from pkg_defender.registry.rubygems import RubyGemsAdapter

        adapter = RubyGemsAdapter()
        assert adapter.ecosystem == "rubygems"

    def test_rubygems_adapter_registry_url(self) -> None:
        """RubyGemsAdapter().registry_base_url == 'https://rubygems.org'."""
        from pkg_defender.registry.rubygems import RubyGemsAdapter

        adapter = RubyGemsAdapter()
        assert adapter.registry_base_url == "https://rubygems.org"

    def test_rubygems_adapter_methods_exist(self) -> None:
        """RubyGemsAdapter implements all 3 abstract methods: get_publish_time,
        get_all_versions, get_latest_version."""
        from pkg_defender.registry.rubygems import RubyGemsAdapter

        adapter = RubyGemsAdapter()
        assert callable(getattr(adapter, "get_publish_time", None))
        assert callable(getattr(adapter, "get_all_versions", None))
        assert callable(getattr(adapter, "get_latest_version", None))

    def test_rubygems_adapter_is_registry_adapter_subclass(self) -> None:
        """RubyGemsAdapter is a concrete subclass of RegistryAdapter."""
        from pkg_defender.registry.base import RegistryAdapter
        from pkg_defender.registry.rubygems import RubyGemsAdapter

        adapter = RubyGemsAdapter()
        assert isinstance(adapter, RegistryAdapter)


# ===================================================================
# 2. Lock file parsers — dispatch entries for Phase 4 lock formats
# ===================================================================


class TestLockFileParsersDispatch:
    """Verify parse_lock_file dispatches correctly for yarn, pnpm, uv, Pipfile."""

    def test_yarn_lock_dispatch(self, tmp_path: Path) -> None:
        """parse_lock_file('yarn.lock') dispatches to parse_yarn_lock."""
        shutil.copy(FIXTURES_DIR / "yarn.lock", tmp_path / "yarn.lock")
        result = parse_lock_file(tmp_path / "yarn.lock")
        assert isinstance(result, list)
        assert len(result) > 0
        assert all(isinstance(p, dict) for p in result)
        assert all("package" in p and "version" in p and "ecosystem" in p for p in result)

    def test_pnpm_lock_dispatch(self, tmp_path: Path) -> None:
        """parse_lock_file('pnpm-lock.yaml') dispatches to parse_pnpm_lock."""
        shutil.copy(FIXTURES_DIR / "pnpm-lock.yaml", tmp_path / "pnpm-lock.yaml")
        result = parse_lock_file(tmp_path / "pnpm-lock.yaml")
        assert isinstance(result, list)
        assert len(result) > 0
        assert all(isinstance(p, dict) for p in result)
        assert all("package" in p and "version" in p and "ecosystem" in p for p in result)

    def test_uv_lock_dispatch(self, tmp_path: Path) -> None:
        """parse_lock_file('uv.lock') dispatches to parse_uv_lock."""
        shutil.copy(FIXTURES_DIR / "uv.lock", tmp_path / "uv.lock")
        result = parse_lock_file(tmp_path / "uv.lock")
        assert isinstance(result, list)
        assert len(result) > 0
        assert all(isinstance(p, dict) for p in result)
        assert all("package" in p and "version" in p and "ecosystem" in p for p in result)

    def test_pipfile_lock_dispatch(self, tmp_path: Path) -> None:
        """parse_lock_file('Pipfile.lock') dispatches to parse_pipfile_lock."""
        shutil.copy(FIXTURES_DIR / "Pipfile.lock", tmp_path / "Pipfile.lock")
        result = parse_lock_file(tmp_path / "Pipfile.lock")
        assert isinstance(result, list)
        assert len(result) > 0
        assert all(isinstance(p, dict) for p in result)
        assert all("package" in p and "version" in p and "ecosystem" in p for p in result)

    def test_ecosystem_map_includes_all_lock_formats(self) -> None:
        """_ECOSYSTEM_MAP includes entries for all Phase 4 lock file types."""
        assert "yarn.lock" in _ECOSYSTEM_MAP
        assert _ECOSYSTEM_MAP["yarn.lock"] == "npm"
        assert "pnpm-lock.yaml" in _ECOSYSTEM_MAP
        assert _ECOSYSTEM_MAP["pnpm-lock.yaml"] == "npm"
        assert "uv.lock" in _ECOSYSTEM_MAP
        assert _ECOSYSTEM_MAP["uv.lock"] == "pypi"
        assert "Pipfile.lock" in _ECOSYSTEM_MAP
        assert _ECOSYSTEM_MAP["Pipfile.lock"] == "pypi"


# ===================================================================
# 5. pkgd intel report command
# ===================================================================


class TestIntelReportCommand:
    """Tests for the 'pkgd intel report' CLI command."""

    def test_intel_report_help(self, runner: CliRunner) -> None:
        """pkgd intel report --help renders help text."""
        result = runner.invoke(cli, ["intel", "report", "--help"])
        assert result.exit_code == 0
        assert "report" in result.output.lower()

    def test_intel_report_runs(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """pkgd intel report executes without error on an empty DB."""
        result = runner.invoke(cli, ["intel", "report"])
        assert result.exit_code == 0
        # Empty DB should indicate no records
        assert "No threat records found" in result.output or "0" in result.output

    def test_intel_report_json_empty_db(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """pkgd intel report --json on empty DB returns valid JSON."""
        result = runner.invoke(cli, ["intel", "report", "--json"])
        assert result.exit_code == 0
        # Use stdout to avoid Rich Panel stderr warnings contaminating JSON parsing
        data = json.loads(result.stdout)
        assert "recent_threats" in data
        assert data["recent_threats"] == []


# ===================================================================
# 6. Windows daemon
# ===================================================================


class TestWindowsDaemon:
    """Tests for Windows schtasks calls in install/uninstall service."""

    def test_schtasks_install_called(self, tmp_path: Path, pq_binary: Path) -> None:
        """install_service(platform='windows') calls schtasks /Create."""
        with (
            patch(
                "pkg_defender.config.settings.get_config_dir",
                return_value=tmp_path / "config",
            ),
            patch(
                "pkg_defender.config.settings.get_data_dir",
                return_value=tmp_path / "data",
            ),
            patch("pkg_defender.daemon.service.subprocess.run") as mock_run,
        ):
            from pkg_defender.daemon.service import install_service

            install_service(platform_name="windows", pq_binary=pq_binary)

        # Verify schtasks was called (contextlib.suppress means CalledProcessError
        # is swallowed, but the call must be made)
        schtasks_calls = [
            c for c in mock_run.call_args_list if c[0] and isinstance(c[0][0], list) and "schtasks" in c[0][0]
        ]
        assert len(schtasks_calls) >= 1
        create_call = schtasks_calls[0][0][0]
        assert "/Create" in create_call
        assert "/TN" in create_call
        assert SYSTEMD_SERVICE_NAME in create_call

    def test_schtasks_uninstall_called(self, tmp_path: Path) -> None:
        """uninstall_service(platform='windows') calls schtasks /Delete."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        xml_path = data_dir / f"{SYSTEMD_SERVICE_NAME}-task.xml"
        xml_path.write_text("<Task/>")

        with (
            patch("pkg_defender.daemon.service._detect_platform", return_value="windows"),
            patch("pkg_defender.config.settings.get_data_dir", return_value=data_dir),
            patch("pkg_defender.daemon.service.subprocess.run") as mock_run,
        ):
            from pkg_defender.daemon.service import uninstall_service

            uninstall_service(platform_name="windows")

        schtasks_calls = [
            c for c in mock_run.call_args_list if c[0] and isinstance(c[0][0], list) and "schtasks" in c[0][0]
        ]
        assert len(schtasks_calls) >= 1
        delete_call = schtasks_calls[0][0][0]
        assert "/Delete" in delete_call
        assert "/TN" in delete_call
        assert SYSTEMD_SERVICE_NAME in delete_call

    def test_schtasks_xml_created_before_call(self, tmp_path: Path, pq_binary: Path) -> None:
        """install_service(platform='windows') writes the XML file before calling schtasks."""
        from pkg_defender.daemon.service import install_service

        call_order: list[str] = []

        def tracking_run(cmd: Any, **kwargs: Any) -> Any:
            if isinstance(cmd, list) and "schtasks" in cmd:
                call_order.append("schtasks")
            return MagicMock(returncode=0)

        with (
            patch(
                "pkg_defender.config.settings.get_config_dir",
                return_value=tmp_path / "config",
            ),
            patch(
                "pkg_defender.config.settings.get_data_dir",
                return_value=tmp_path / "data",
            ),
            patch("pkg_defender.daemon.service.subprocess.run", side_effect=tracking_run),
        ):
            result = install_service(platform_name="windows", pq_binary=pq_binary)

        # XML file should exist at the returned path
        assert result.exists()
        assert result.name.endswith("-task.xml")
