"""Tests for lock file parsers."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from pkg_defender.core.parsers import (
    detect_lock_file,
    find_lock_files,
    parse_lock_file,
    parse_package_lock,
    parse_pipfile_lock,
    parse_pnpm_lock,
    parse_poetry_lock,
    parse_requirements_txt,
    parse_uv_lock,
    parse_yarn_lock,
)

FIXTURES_DIR = Path(__file__).parent.parent.parent.parent / "fixtures" / "lock_files"


# ---------------------------------------------------------------------------
# detect_lock_file
# ---------------------------------------------------------------------------


class TestDetectLockFile:
    """Tests for detect_lock_file."""

    def test_detects_package_lock(self, tmp_path: Path) -> None:
        """package-lock.json is detected when present."""
        (tmp_path / "package-lock.json").write_text("{}")
        result = detect_lock_file(tmp_path)
        assert result is not None
        assert result.name == "package-lock.json"

    def test_detects_poetry_lock(self, tmp_path: Path) -> None:
        """poetry.lock is detected when present."""
        (tmp_path / "poetry.lock").write_text("")
        result = detect_lock_file(tmp_path)
        assert result is not None
        assert result.name == "poetry.lock"

    def test_detects_requirements_txt(self, tmp_path: Path) -> None:
        """requirements.txt is detected when present."""
        (tmp_path / "requirements.txt").write_text("")
        result = detect_lock_file(tmp_path)
        assert result is not None
        assert result.name == "requirements.txt"

    def test_detects_yarn_lock(self, tmp_path: Path) -> None:
        """yarn.lock is detected when present."""
        (tmp_path / "yarn.lock").write_text("")
        result = detect_lock_file(tmp_path)
        assert result is not None
        assert result.name == "yarn.lock"

    def test_detects_pnpm_lock(self, tmp_path: Path) -> None:
        """pnpm-lock.yaml is detected when present."""
        (tmp_path / "pnpm-lock.yaml").write_text("")
        result = detect_lock_file(tmp_path)
        assert result is not None
        assert result.name == "pnpm-lock.yaml"

    def test_detects_pipfile_lock(self, tmp_path: Path) -> None:
        """Pipfile.lock is detected when present."""
        (tmp_path / "Pipfile.lock").write_text("{}")
        result = detect_lock_file(tmp_path)
        assert result is not None
        assert result.name == "Pipfile.lock"

    def test_detects_uv_lock(self, tmp_path: Path) -> None:
        """uv.lock is detected when present."""
        (tmp_path / "uv.lock").write_text("")
        result = detect_lock_file(tmp_path)
        assert result is not None
        assert result.name == "uv.lock"

    def test_returns_none_when_no_lock_file(self, tmp_path: Path) -> None:
        """Returns None when no lock file exists."""
        result = detect_lock_file(tmp_path)
        assert result is None

    def test_priority_order(self, tmp_path: Path) -> None:
        """package-lock.json takes priority over poetry.lock."""
        (tmp_path / "poetry.lock").write_text("")
        (tmp_path / "package-lock.json").write_text("{}")
        result = detect_lock_file(tmp_path)
        assert result is not None
        assert result.name == "package-lock.json"

    def test_priority_order_requirements_last(self, tmp_path: Path) -> None:
        """poetry.lock takes priority over requirements.txt."""
        (tmp_path / "requirements.txt").write_text("")
        (tmp_path / "poetry.lock").write_text("")
        result = detect_lock_file(tmp_path)
        assert result is not None
        assert result.name == "poetry.lock"

    def test_empty_directory(self, tmp_path: Path) -> None:
        """Returns None for an empty directory."""
        result = detect_lock_file(tmp_path)
        assert result is None


# ---------------------------------------------------------------------------
# find_lock_files
# ---------------------------------------------------------------------------


class TestFindLockFiles:
    """Tests for find_lock_files."""

    def test_finds_nothing_in_empty_dir(self, tmp_path: Path) -> None:
        """Empty directory returns empty list."""
        result = find_lock_files(tmp_path)
        assert result == []

    def test_finds_single_lock_file(self, tmp_path: Path) -> None:
        """Single lock file in root is found."""
        (tmp_path / "package-lock.json").write_text("{}")
        result = find_lock_files(tmp_path)
        assert len(result) == 1
        assert result[0].name == "package-lock.json"

    def test_finds_multiple_lock_files(self, tmp_path: Path) -> None:
        """Multiple lock files across subdirs are all found."""
        (tmp_path / "package-lock.json").write_text("{}")
        sub = tmp_path / "backend"
        sub.mkdir()
        (sub / "requirements.txt").write_text("requests==2.31.0")
        result = find_lock_files(tmp_path)
        assert len(result) == 2

    @pytest.mark.parametrize("skip_dir", [".venv", "node_modules", "__pycache__", ".git"])
    def test_skips_excluded_dirs(self, tmp_path: Path, skip_dir: str) -> None:
        """Excluded directories are skipped."""
        excluded = tmp_path / skip_dir
        excluded.mkdir(parents=True)
        (excluded / "package-lock.json").write_text("{}")
        result = find_lock_files(tmp_path)
        assert result == []

    def test_normalizes_resolve_path(self, tmp_path: Path) -> None:
        """Relative paths are normalized via .resolve()."""
        (tmp_path / "package-lock.json").write_text("{}")
        old_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)
            result = find_lock_files(Path("."))
            assert len(result) == 1
            assert result[0].name == "package-lock.json"
            assert result[0].is_absolute()
        finally:
            os.chdir(old_cwd)

    def test_sort_order(self, tmp_path: Path) -> None:
        """Results sorted: shallow first, then LOCK_FILE_NAMES priority."""
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "package-lock.json").write_text("{}")
        (tmp_path / "requirements.txt").write_text("")
        result = find_lock_files(tmp_path)
        assert len(result) == 2
        assert result[0].name == "requirements.txt"  # depth 0 first
        assert result[1].name == "package-lock.json"  # depth 1 second


# ---------------------------------------------------------------------------
# parse_package_lock — v3 format
# ---------------------------------------------------------------------------


class TestParsePackageLockV3:
    """Tests for parse_package_lock with v3 format."""

    def test_v3_basic(self) -> None:
        """v3 lock file with packages key is parsed correctly."""
        path = FIXTURES_DIR / "package-lock-v3.json"
        result = parse_package_lock(path)

        names = {p["package"] for p in result}
        assert "express" in names
        assert "lodash" in names
        assert "accepts" in names
        assert "body-parser" in names

    def test_v3_versions(self) -> None:
        """Versions are extracted correctly from v3 format."""
        path = FIXTURES_DIR / "package-lock-v3.json"
        result = parse_package_lock(path)

        pkg_map = {p["package"]: p["version"] for p in result}
        assert pkg_map["express"] == "4.18.2"
        assert pkg_map["lodash"] == "4.17.21"

    def test_v3_scoped_package(self) -> None:
        """Scoped packages (@scope/name) are handled correctly."""
        path = FIXTURES_DIR / "package-lock-v3.json"
        result = parse_package_lock(path)

        pkg_map = {p["package"]: p["version"] for p in result}
        assert "@scope/scoped-pkg" in pkg_map
        assert pkg_map["@scope/scoped-pkg"] == "2.0.0"

    def test_v3_ecosystem(self) -> None:
        """All packages have ecosystem='npm'."""
        path = FIXTURES_DIR / "package-lock-v3.json"
        result = parse_package_lock(path)
        assert all(p["ecosystem"] == "npm" for p in result)

    def test_v3_root_package_excluded(self) -> None:
        """The root package (empty key) is excluded."""
        path = FIXTURES_DIR / "package-lock-v3.json"
        result = parse_package_lock(path)

        names = {p["package"] for p in result}
        assert "" not in names
        assert "test-project" not in names


# ---------------------------------------------------------------------------
# parse_package_lock — v2 format (nested dependencies)
# ---------------------------------------------------------------------------


class TestParsePackageLockV2:
    """Tests for parse_package_lock with v2 nested format."""

    def test_v2_basic(self) -> None:
        """v2 lock file with nested dependencies is parsed."""
        path = FIXTURES_DIR / "package-lock-v2.json"
        result = parse_package_lock(path)

        names = {p["package"] for p in result}
        assert "express" in names
        assert "lodash" in names
        assert "accepts" in names
        assert "body-parser" in names

    def test_v2_versions(self) -> None:
        """Versions are extracted correctly from v2 format."""
        path = FIXTURES_DIR / "package-lock-v2.json"
        result = parse_package_lock(path)

        pkg_map = {p["package"]: p["version"] for p in result}
        assert pkg_map["express"] == "4.18.2"
        assert pkg_map["lodash"] == "4.17.21"
        assert pkg_map["accepts"] == "1.3.8"

    def test_v2_ecosystem(self) -> None:
        """All packages have ecosystem='npm'."""
        path = FIXTURES_DIR / "package-lock-v2.json"
        result = parse_package_lock(path)
        assert all(p["ecosystem"] == "npm" for p in result)


# ---------------------------------------------------------------------------
# parse_poetry_lock
# ---------------------------------------------------------------------------


class TestParsePoetryLock:
    """Tests for parse_poetry_lock."""

    def test_returns_expected_packages_when_parsing_poetry_lock(self) -> None:
        """Poetry lock file is parsed and expected packages are present."""
        path = FIXTURES_DIR / "poetry.lock"
        result = parse_poetry_lock(path)

        names = {p["package"] for p in result}
        assert "requests" in names
        assert "certifi" in names
        assert "charset-normalizer" in names
        assert "idna" in names
        assert "urllib3" in names

    def test_versions(self) -> None:
        """Versions are extracted correctly."""
        path = FIXTURES_DIR / "poetry.lock"
        result = parse_poetry_lock(path)

        pkg_map = {p["package"]: p["version"] for p in result}
        assert pkg_map["requests"] == "2.31.0"
        assert pkg_map["certifi"] == "2024.2.2"

    def test_ecosystem(self) -> None:
        """All packages have ecosystem='pypi'."""
        path = FIXTURES_DIR / "poetry.lock"
        result = parse_poetry_lock(path)
        assert all(p["ecosystem"] == "pypi" for p in result)

    def test_package_count(self) -> None:
        """Correct number of packages extracted."""
        path = FIXTURES_DIR / "poetry.lock"
        result = parse_poetry_lock(path)
        assert len(result) == 5


# ---------------------------------------------------------------------------
# parse_requirements_txt
# ---------------------------------------------------------------------------


class TestParseRequirementsTxt:
    """Tests for parse_requirements_txt."""

    def test_exact_pins(self) -> None:
        """Exact version pins (==) are extracted."""
        path = FIXTURES_DIR / "requirements.txt"
        result = parse_requirements_txt(path)

        pkg_map = {p["package"]: p["version"] for p in result}
        assert pkg_map["requests"] == "2.31.0"
        assert pkg_map["flask"] == "3.0.0"
        assert pkg_map["numpy"] == "1.26.4"

    def test_skips_ranges(self) -> None:
        """Range specifiers (>=, ~=) are skipped."""
        path = FIXTURES_DIR / "requirements.txt"
        result = parse_requirements_txt(path)

        names = {p["package"] for p in result}
        assert "click" not in names
        assert "rich" not in names
        assert "packaging" not in names

    def test_skips_comments(self) -> None:
        """Comment lines are skipped."""
        path = FIXTURES_DIR / "requirements.txt"
        result = parse_requirements_txt(path)
        for entry in result:
            assert not entry["package"].startswith("#")

    def test_skips_options(self) -> None:
        """Option lines (--index-url, etc.) are skipped."""
        path = FIXTURES_DIR / "requirements.txt"
        result = parse_requirements_txt(path)
        names = {p["package"] for p in result}
        assert "index-url" not in names
        assert "trusted-host" not in names

    def test_skips_includes(self) -> None:
        """-r includes are skipped."""
        path = FIXTURES_DIR / "requirements.txt"
        result = parse_requirements_txt(path)
        names = {p["package"] for p in result}
        assert "r" not in names
        assert "dev-requirements.txt" not in names

    def test_extras(self) -> None:
        """Packages with extras (sqlalchemy[asyncio]) are extracted."""
        path = FIXTURES_DIR / "requirements.txt"
        result = parse_requirements_txt(path)

        pkg_map = {p["package"]: p["version"] for p in result}
        assert pkg_map["sqlalchemy"] == "2.0.29"

    def test_environment_markers(self) -> None:
        """Packages with environment markers are extracted."""
        path = FIXTURES_DIR / "requirements.txt"
        result = parse_requirements_txt(path)

        pkg_map = {p["package"]: p["version"] for p in result}
        assert pkg_map["importlib-metadata"] == "7.0.0"

    def test_ecosystem(self) -> None:
        """All packages have ecosystem='pypi'."""
        path = FIXTURES_DIR / "requirements.txt"
        result = parse_requirements_txt(path)
        assert all(p["ecosystem"] == "pypi" for p in result)

    def test_total_count(self) -> None:
        """Only exact-pinned packages are counted."""
        path = FIXTURES_DIR / "requirements.txt"
        result = parse_requirements_txt(path)
        # requests, flask, numpy, sqlalchemy[asyncio], importlib-metadata
        assert len(result) == 5


# ---------------------------------------------------------------------------
# parse_yarn_lock
# ---------------------------------------------------------------------------


class TestParseYarnLock:
    """Tests for parse_yarn_lock."""

    def test_returns_expected_packages_when_parsing_yarn_lock(self) -> None:
        """yarn.lock is parsed and expected packages are present."""
        path = FIXTURES_DIR / "yarn.lock"
        result = parse_yarn_lock(path)

        names = {p["package"] for p in result}
        assert "accepts" in names
        assert "body-parser" in names
        assert "express" in names
        assert "lodash" in names

    def test_scoped_package(self) -> None:
        """Scoped @babel/core and @babel/helper-module-imports are extracted."""
        path = FIXTURES_DIR / "yarn.lock"
        result = parse_yarn_lock(path)

        pkg_map = {p["package"]: p["version"] for p in result}
        assert "@babel/core" in pkg_map
        assert pkg_map["@babel/core"] == "7.24.0"
        assert "@babel/helper-module-imports" in pkg_map
        assert pkg_map["@babel/helper-module-imports"] == "7.22.15"

    def test_versions(self) -> None:
        """Versions are extracted correctly."""
        path = FIXTURES_DIR / "yarn.lock"
        result = parse_yarn_lock(path)

        pkg_map = {p["package"]: p["version"] for p in result}
        assert pkg_map["express"] == "4.18.2"
        assert pkg_map["lodash"] == "4.17.21"
        assert pkg_map["accepts"] == "1.3.8"
        assert pkg_map["body-parser"] == "1.20.1"

    def test_ecosystem(self) -> None:
        """All packages have ecosystem='npm'."""
        path = FIXTURES_DIR / "yarn.lock"
        result = parse_yarn_lock(path)
        assert all(p["ecosystem"] == "npm" for p in result)

    def test_package_count(self) -> None:
        """Correct number of packages extracted."""
        path = FIXTURES_DIR / "yarn.lock"
        result = parse_yarn_lock(path)
        assert len(result) == 6

    def test_empty_file(self, tmp_path: Path) -> None:
        """Empty yarn.lock returns no packages."""
        lock = tmp_path / "yarn.lock"
        lock.write_text("")
        result = parse_yarn_lock(lock)
        assert result == []


# ---------------------------------------------------------------------------
# parse_pnpm_lock
# ---------------------------------------------------------------------------


class TestParsePnpmLock:
    """Tests for parse_pnpm_lock."""

    def test_returns_expected_packages_when_parsing_pnpm_lock(self) -> None:
        """pnpm-lock.yaml is parsed and expected packages are present."""
        path = FIXTURES_DIR / "pnpm-lock.yaml"
        result = parse_pnpm_lock(path)

        names = {p["package"] for p in result}
        assert "accepts" in names
        assert "express" in names
        assert "lodash" in names
        assert "body-parser" in names

    def test_scoped_package(self) -> None:
        """Scoped @babel/core and @babel/helper-module-imports are extracted."""
        path = FIXTURES_DIR / "pnpm-lock.yaml"
        result = parse_pnpm_lock(path)

        pkg_map = {p["package"]: p["version"] for p in result}
        assert "@babel/core" in pkg_map
        assert pkg_map["@babel/core"] == "7.24.0"
        assert "@babel/helper-module-imports" in pkg_map
        assert pkg_map["@babel/helper-module-imports"] == "7.22.15"

    def test_versions(self) -> None:
        """Versions are extracted correctly."""
        path = FIXTURES_DIR / "pnpm-lock.yaml"
        result = parse_pnpm_lock(path)

        pkg_map = {p["package"]: p["version"] for p in result}
        assert pkg_map["express"] == "4.18.2"
        assert pkg_map["lodash"] == "4.17.21"
        assert pkg_map["accepts"] == "1.3.8"
        assert pkg_map["body-parser"] == "1.20.1"

    def test_ecosystem(self) -> None:
        """All packages have ecosystem='npm'."""
        path = FIXTURES_DIR / "pnpm-lock.yaml"
        result = parse_pnpm_lock(path)
        assert all(p["ecosystem"] == "npm" for p in result)

    def test_package_count(self) -> None:
        """Correct number of packages extracted."""
        path = FIXTURES_DIR / "pnpm-lock.yaml"
        result = parse_pnpm_lock(path)
        assert len(result) == 6


# ---------------------------------------------------------------------------
# parse_uv_lock
# ---------------------------------------------------------------------------


class TestParseUvLock:
    """Tests for parse_uv_lock."""

    def test_returns_expected_packages_when_parsing_uv_lock(self) -> None:
        """uv.lock is parsed and expected packages are present."""
        path = FIXTURES_DIR / "uv.lock"
        result = parse_uv_lock(path)

        names = {p["package"] for p in result}
        assert "requests" in names
        assert "certifi" in names
        assert "charset-normalizer" in names
        assert "idna" in names
        assert "urllib3" in names
        assert "flask" in names

    def test_versions(self) -> None:
        """Versions are extracted correctly."""
        path = FIXTURES_DIR / "uv.lock"
        result = parse_uv_lock(path)

        pkg_map = {p["package"]: p["version"] for p in result}
        assert pkg_map["requests"] == "2.31.0"
        assert pkg_map["certifi"] == "2024.2.2"
        assert pkg_map["flask"] == "3.0.0"

    def test_ecosystem(self) -> None:
        """All packages have ecosystem='pypi'."""
        path = FIXTURES_DIR / "uv.lock"
        result = parse_uv_lock(path)
        assert all(p["ecosystem"] == "pypi" for p in result)

    def test_package_count(self) -> None:
        """Correct number of packages extracted."""
        path = FIXTURES_DIR / "uv.lock"
        result = parse_uv_lock(path)
        assert len(result) == 6


# ---------------------------------------------------------------------------
# parse_pipfile_lock
# ---------------------------------------------------------------------------


class TestParsePipfileLock:
    """Tests for parse_pipfile_lock."""

    def test_returns_expected_packages_when_parsing_pipfile_lock(self) -> None:
        """Pipfile.lock is parsed and expected packages are present."""
        path = FIXTURES_DIR / "Pipfile.lock"
        result = parse_pipfile_lock(path)

        names = {p["package"] for p in result}
        assert "requests" in names
        assert "flask" in names
        assert "jinja2" in names

    def test_versions(self) -> None:
        """Versions are extracted correctly (== prefix stripped)."""
        path = FIXTURES_DIR / "Pipfile.lock"
        result = parse_pipfile_lock(path)

        pkg_map = {p["package"]: p["version"] for p in result}
        assert pkg_map["requests"] == "2.31.0"
        assert pkg_map["flask"] == "3.0.0"

    def test_develop_deps_included(self) -> None:
        """Develop dependencies are included alongside default deps."""
        path = FIXTURES_DIR / "Pipfile.lock"
        result = parse_pipfile_lock(path)

        names = {p["package"] for p in result}
        assert "pytest" in names
        assert "ruff" in names

    def test_ecosystem(self) -> None:
        """All packages have ecosystem='pypi'."""
        path = FIXTURES_DIR / "Pipfile.lock"
        result = parse_pipfile_lock(path)
        assert all(p["ecosystem"] == "pypi" for p in result)

    def test_package_count(self) -> None:
        """Correct total count (default + develop)."""
        path = FIXTURES_DIR / "Pipfile.lock"
        result = parse_pipfile_lock(path)
        # 3 default + 2 develop = 5
        assert len(result) == 5


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestParserEdgeCases:
    """Edge-case tests across parsers."""

    def test_empty_requirements_file(self, tmp_path: Path) -> None:
        """Empty requirements.txt returns no packages."""
        req = tmp_path / "requirements.txt"
        req.write_text("")
        result = parse_requirements_txt(req)
        assert result == []

    def test_requirements_only_comments(self, tmp_path: Path) -> None:
        """File with only comments returns no packages."""
        req = tmp_path / "requirements.txt"
        req.write_text("# just a comment\n# another comment\n")
        result = parse_requirements_txt(req)
        assert result == []

    def test_malformed_json_lock_file(self, tmp_path: Path) -> None:
        """Malformed JSON in package-lock.json raises JSONDecodeError."""
        lock = tmp_path / "package-lock.json"
        lock.write_text("{invalid json")
        with pytest.raises(json.JSONDecodeError):
            parse_package_lock(lock)

    def test_empty_json_lock_file(self, tmp_path: Path) -> None:
        """Empty JSON object in package-lock.json returns no packages."""
        lock = tmp_path / "package-lock.json"
        lock.write_text("{}")
        result = parse_package_lock(lock)
        assert result == []

    def test_returns_results_when_dispatched_by_filename(self, tmp_path: Path) -> None:
        """parse_lock_file dispatches to the right parser by filename."""
        import shutil

        # Copy fixtures with canonical filenames for dispatch
        shutil.copy(FIXTURES_DIR / "poetry.lock", tmp_path / "poetry.lock")
        shutil.copy(FIXTURES_DIR / "package-lock-v3.json", tmp_path / "package-lock.json")
        shutil.copy(FIXTURES_DIR / "requirements.txt", tmp_path / "requirements.txt")
        shutil.copy(FIXTURES_DIR / "yarn.lock", tmp_path / "yarn.lock")
        shutil.copy(FIXTURES_DIR / "pnpm-lock.yaml", tmp_path / "pnpm-lock.yaml")
        shutil.copy(FIXTURES_DIR / "uv.lock", tmp_path / "uv.lock")

        poetry_result = parse_lock_file(tmp_path / "poetry.lock")
        npm_result = parse_lock_file(tmp_path / "package-lock.json")
        req_result = parse_lock_file(tmp_path / "requirements.txt")
        yarn_result = parse_lock_file(tmp_path / "yarn.lock")
        pnpm_result = parse_lock_file(tmp_path / "pnpm-lock.yaml")
        uv_result = parse_lock_file(tmp_path / "uv.lock")

        assert len(poetry_result) > 0
        assert all(p["ecosystem"] == "pypi" for p in poetry_result)
        assert len(npm_result) > 0
        assert all(p["ecosystem"] == "npm" for p in npm_result)
        assert len(req_result) > 0
        assert all(p["ecosystem"] == "pypi" for p in req_result)
        assert len(yarn_result) > 0
        assert all(p["ecosystem"] == "npm" for p in yarn_result)
        assert len(pnpm_result) > 0
        assert all(p["ecosystem"] == "npm" for p in pnpm_result)
        assert len(uv_result) > 0
        assert all(p["ecosystem"] == "pypi" for p in uv_result)

    def test_parse_lock_file_unknown_format(self, tmp_path: Path) -> None:
        """Unknown lock file format returns empty list."""
        unknown = tmp_path / "unknown.lock"
        unknown.write_text("some content")
        result = parse_lock_file(unknown)
        assert result == []

    def test_poetry_lock_empty_packages(self, tmp_path: Path) -> None:
        """Poetry lock with no [[package]] sections returns empty list."""
        lock = tmp_path / "poetry.lock"
        lock.write_text('[metadata]\nlock-version = "2.0"\n')
        result = parse_poetry_lock(lock)
        assert result == []

    def test_empty_package_lock_dependencies(self, tmp_path: Path) -> None:
        """package-lock.json with empty dependencies object returns no packages.

        Edge case: A valid JSON lock file that has a ``dependencies`` key
        but no entries inside it (v2 format without ``packages``).
        """
        lock = tmp_path / "package-lock.json"
        lock.write_text('{"name": "empty-project", "version": "1.0.0", "lockfileVersion": 2, "dependencies": {}}')
        result = parse_package_lock(lock)
        assert result == []

    def test_empty_pipfile_lock_sections(self, tmp_path: Path) -> None:
        """Pipfile.lock with no default or develop packages returns empty list.

        Edge case: A valid Pipfile.lock that contains _meta but no
        packages in default or develop sections.
        """
        lock = tmp_path / "Pipfile.lock"
        lock.write_text('{"_meta": {"source": [{"url": "https://pypi.org/simple"}]}, "default": {}, "develop": {}}')
        result = parse_pipfile_lock(lock)
        assert result == []

    def test_malformed_requirements_lines_skipped(self, tmp_path: Path) -> None:
        """Malformed lines in requirements.txt are silently skipped.

        Edge case: Lines that don't match any known pattern (random text,
        invalid operators, bare package names) should not crash the parser.
        Only valid exact pins are extracted.
        """
        req = tmp_path / "requirements.txt"
        req.write_text("some random text\n===invalid\nno-version-pkg\nrequests==2.31.0\n")
        result = parse_requirements_txt(req)
        assert len(result) == 1
        assert result[0]["package"] == "requests"
        assert result[0]["version"] == "2.31.0"

    def test_malformed_pipfile_lock_invalid_json(self, tmp_path: Path) -> None:
        """Pipfile.lock with invalid JSON raises JSONDecodeError.

        Edge case: A file named Pipfile.lock that contains invalid JSON
        should raise json.JSONDecodeError rather than silently failing.
        """
        lock = tmp_path / "Pipfile.lock"
        lock.write_text("{invalid json content")
        with pytest.raises(json.JSONDecodeError):
            parse_pipfile_lock(lock)

    def test_scoped_package_pnpm_double_at(self, tmp_path: Path) -> None:
        """Scoped packages in pnpm-lock.yaml preserve the @scope/ prefix.

        Edge case: Scoped packages like @babel/core use the format
        /@scope/name@version in pnpm lock files. The parser must
        correctly separate the scope prefix from the version suffix
        using the second @ sign, not the first.
        """
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(
            "lockfileVersion: '6.0'\npackages:\n  /@types/node@20.11.0:\n    resolution: {integrity: sha512-abc==}\n"
        )
        result = parse_pnpm_lock(lock)
        assert len(result) == 1
        assert result[0]["package"] == "@types/node"
        assert result[0]["version"] == "20.11.0"

    def test_scoped_package_yarn_preserved(self, tmp_path: Path) -> None:
        """Scoped packages in yarn.lock preserve the @scope/ prefix.

        Edge case: yarn.lock entries like "@babel/core@^7.20.0" must
        extract the full scoped name @babel/core, not just babel/core.
        """
        lock = tmp_path / "yarn.lock"
        lock.write_text('"@types/node@^20.0.0":\n  version "20.11.0"\n')
        result = parse_yarn_lock(lock)
        assert len(result) == 1
        assert result[0]["package"] == "@types/node"
        assert result[0]["version"] == "20.11.0"

    def test_complex_version_ranges_skipped(self, tmp_path: Path) -> None:
        """Complex version specifiers in requirements.txt are skipped.

        Edge case: Lines with compound range specifiers like
        >=1.0.0,<3.0.0,!=2.0.0 are not exact pins and should be
        skipped by the parser. Only == pins are extracted.
        """
        req = tmp_path / "requirements.txt"
        req.write_text("requests>=1.0.0,<3.0.0,!=2.0.0\nflask>=2.0\ndjango[async]>=4.0,<5.0\nnumpy==1.26.4\n")
        result = parse_requirements_txt(req)
        assert len(result) == 1
        assert result[0]["package"] == "numpy"
        assert result[0]["version"] == "1.26.4"

    def test_non_existent_package_lock_raises_filenotfound(self, tmp_path: Path) -> None:
        """Parsing a non-existent package-lock.json raises FileNotFoundError.

        Edge case: When the lock file path does not exist, the parser
        should raise FileNotFoundError rather than returning an empty
        list or a misleading result.
        """
        missing = tmp_path / "nonexistent" / "package-lock.json"
        with pytest.raises(FileNotFoundError):
            parse_package_lock(missing)

    def test_non_existent_requirements_raises_filenotfound(self, tmp_path: Path) -> None:
        """Parsing a non-existent requirements.txt raises FileNotFoundError.

        Edge case: When the requirements file path does not exist, the
        parser should raise FileNotFoundError rather than silently
        returning an empty list.
        """
        missing = tmp_path / "nonexistent" / "requirements.txt"
        with pytest.raises(FileNotFoundError):
            parse_requirements_txt(missing)
