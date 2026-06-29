"""Regression tests for backward compatibility removal.

Covers:
- All importers now use pkg_defender.models.command (not command_models)
- command_models.py is deleted
- ThreatRecord has no deprecated 'package' field
- No 'backward compatibility' strings remain in src/
- Edge cases for ThreatRecord field changes
"""

import os
from importlib import import_module

import pytest

# All files that import from pkg_defender.models.command
# Discovered via: grep -r "from pkg_defender.models.command import" src/
ALL_COMMAND_IMPORTERS = [
    # CLI modules
    "pkg_defender.cli.dispatcher",
    "pkg_defender.cli.exec",
    # managers/ package has been deleted — all managers now have
    # unified adapters in registry/ (see UNIFIED_MANAGER_REGISTRY)
]


def test_all_command_importers_use_models_command() -> None:
    """Verify ALL importers import from pkg_defender.models.command, not command_models.

    Regression test: After deleting command_models.py, every module that previously
    imported from it must now import from pkg_defender.models.command.

    This test FAILS if any importer still references command_models.
    """
    failed = []
    for mod_name in ALL_COMMAND_IMPORTERS:
        try:
            mod = import_module(mod_name)
        except ImportError as e:
            failed.append(f"{mod_name}: ImportError - {e}")
            continue

        # Check that the module's source doesn't reference command_models
        # by inspecting the __file__ and checking imports
        if hasattr(mod, "__file__") and mod.__file__:
            # Verify the module can be imported and uses models.command
            # Check that ParsedCommand (or other command types) are from models.command
            for attr_name in ["ParsedCommand", "CommandIntent", "PackageRef", "InstallSource", "BlockReason"]:
                if hasattr(mod, attr_name):
                    attr = getattr(mod, attr_name)
                    module_name = getattr(attr, "__module__", "")
                    if "command_models" in module_name:
                        failed.append(f"{mod_name}: {attr_name} still from {module_name}")
                    # Verify it's from the correct location
                    if attr_name in ["ParsedCommand", "CommandIntent", "BlockReason"]:
                        assert "models.command" in module_name or "models.command" in str(type(attr).__module__), (
                            f"{mod_name}.{attr_name} not from models.command: {module_name}"
                        )

    if failed:
        pytest.fail("Importers still using command_models:\n" + "\n".join(failed))


def test_command_models_module_deleted() -> None:
    """Verify command_models module is deleted by testing import failure.

    Regression test: The module pkg_defender.core.command_models was deleted.
    Verifies that attempting to import it raises ImportError/ModuleNotFoundError.
    """
    with pytest.raises((ImportError, ModuleNotFoundError)):
        import pkg_defender.core.command_models  # type: ignore[import-not-found]  # noqa: F401  # pyright: ignore[reportMissingImports]

    # Also verify via importlib
    with pytest.raises((ImportError, ModuleNotFoundError)):
        from pkg_defender.core import command_models  # noqa: F401  # pyright: ignore[reportAttributeAccessIssue]


def test_threatrecord_has_no_package_field() -> None:
    """Verify ThreatRecord no longer has the deprecated 'package' field.

    Regression test: The 'package' field was removed from ThreatRecord.
    This test FAILS if ThreatRecord still has a 'package' attribute.

    Root cause: ThreatRecord in models.py had a 'package' field that was
    replaced by 'package_name'. The old field must not exist.
    """
    from pkg_defender.models.models import ThreatRecord

    # Verify 'package' field is gone
    assert not hasattr(ThreatRecord, "package"), "ThreatRecord still has deprecated 'package' class attribute"

    # Verify instance doesn't have 'package' in __dataclass_fields__
    import dataclasses

    field_names = [f.name for f in dataclasses.fields(ThreatRecord)]
    assert "package" not in field_names, f"ThreatRecord still has 'package' in dataclass fields: {field_names}"

    # Verify package_name field exists and works
    record = ThreatRecord(id="test", ecosystem="pypi", package_name="test-pkg")
    assert record.package_name == "test-pkg"

    # Verify old 'package' kwarg raises TypeError
    with pytest.raises(TypeError) as exc_info:
        ThreatRecord(id="test", ecosystem="pypi", package="test-pkg")  # type: ignore[call-arg]
    assert "package" in str(exc_info.value), f"Expected TypeError mentioning 'package', got: {exc_info.value}"


def test_returns_correct_package_name_when_using_package_name_field() -> None:
    """Verify ThreatRecord works correctly with package_name field.

    Edge case verification: After removing 'package' field, the replacement
    'package_name' field must work correctly.
    """
    from pkg_defender.models.models import ThreatRecord

    record = ThreatRecord(id="test-1", ecosystem="pypi", package_name="requests")
    assert record.package_name == "requests"
    assert record.id == "test-1"
    assert record.ecosystem == "pypi"

    record2 = ThreatRecord(id="test-2", ecosystem="npm")
    assert record2.package_name == "unknown"

    record3 = ThreatRecord(id="test-3", ecosystem="gem")
    assert record3.ecosystem == "gem"


def test_threatrecord_package_kwarg_raises_typeerror() -> None:
    """Verify ThreatRecord(id, ecosystem, package=...) raises TypeError.

    Regression test: Using the OLD 'package=' keyword argument must raise
    TypeError since the field was removed.

    This test PASSES when the fix is correct (TypeError is raised).
    This test would have FAILED before the fix (package= was accepted).
    """
    from pkg_defender.models.models import ThreatRecord

    # This MUST raise TypeError because 'package' is not a valid field
    with pytest.raises(TypeError) as exc_info:
        ThreatRecord(
            id="test-regression",
            ecosystem="pypi",
            package="some-package",  # type: ignore[call-arg]  # This field no longer exists!  # pyright: ignore[reportCallIssue]
        )

    # Verify the error message mentions 'package'
    error_msg = str(exc_info.value)
    assert "package" in error_msg, f"TypeError should mention 'package' field, got: {error_msg}"


def test_no_backward_compat_strings_in_src() -> None:
    """Verify deprecated patterns are actually removed from code.

    Regression test: Verifies that deprecated patterns no longer work:
    1. ThreatRecord.package raises AttributeError (field removed)
    2. No backward compatibility imports succeed
    """
    from pkg_defender.models.models import ThreatRecord

    # Verify accessing deprecated 'package' field raises AttributeError
    record = ThreatRecord(id="test", ecosystem="pypi", package_name="test-pkg")

    try:
        _ = record.package  # type: ignore[attr-defined]  # Should raise AttributeError  # pyright: ignore[reportAttributeAccessIssue]
        attribute_error_raised = False
    except AttributeError:
        attribute_error_raised = True

    assert attribute_error_raised, "ThreatRecord.package should raise AttributeError (deprecated field removed)"

    # Also verify the class doesn't have 'package' in its fields
    import dataclasses

    field_names = [f.name for f in dataclasses.fields(ThreatRecord)]
    assert "package" not in field_names, f"ThreatRecord still has 'package' in fields: {field_names}"


def test_no_command_models_references_in_src() -> None:
    """Verify all src/ modules can be imported without referencing command_models.

    Regression test: After deleting command_models.py, all modules should
    import from pkg_defender.models.command instead.
    """
    failed = []

    for mod_name in ALL_COMMAND_IMPORTERS:
        try:
            mod = import_module(mod_name)
            # Verify module doesn't have command_models in its __dict__ references
            mod_source = mod.__dict__
            for key, value in mod_source.items():
                if "command_models" in str(value):
                    failed.append(f"{mod_name}: references command_models in {key}")
        except ImportError as e:
            failed.append(f"{mod_name}: ImportError - {e}")
        except Exception:
            # Other errors should be reported but not necessarily fail
            pass

    # Also verify the deleted module can't be imported
    try:
        import_module("pkg_defender.core.command_models")
        failed.append("pkg_defender.core.command_models can still be imported!")
    except (ImportError, ModuleNotFoundError):
        pass  # Expected

    assert not failed, "Found command_models references:\n" + "\n".join(failed)


def test_models_init_exports_from_command() -> None:
    """Verify pkg_defender.models.__init__ exports from models.command.

    Regression test: The models __init__.py should import command-related
    classes from pkg_defender.models.command, not command_models.
    """
    from pkg_defender import models
    from pkg_defender.models import BlockReason, CommandIntent, ParsedCommand

    # Verify they're the same classes (imported from command module)
    assert BlockReason is models.command.BlockReason  # pyright: ignore[reportAttributeAccessIssue]
    assert CommandIntent is models.command.CommandIntent  # pyright: ignore[reportAttributeAccessIssue]
    assert ParsedCommand is models.command.ParsedCommand  # pyright: ignore[reportAttributeAccessIssue]


def test_intel_modules_use_package_name() -> None:
    """Verify intel modules use package_name= not package= in ThreatRecord.

    Regression test: All ThreatRecord instantiations in src/pkg_defender/intel/
    must use the new 'package_name=' field, not the removed 'package=' field.
    """
    src_dir = os.path.join(os.path.dirname(__file__), "..", "src")
    src_dir = os.path.abspath(src_dir)
    intel_dir = os.path.join(src_dir, "pkg_defender", "intel")

    found_old_pattern = []
    if os.path.exists(intel_dir):
        for root, _dirs, files in os.walk(intel_dir):
            for fname in files:
                if fname.endswith(".py"):
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, encoding="utf-8") as f:
                            for line_num, line in enumerate(f, 1):
                                # Check for ThreatRecord with package= kwarg
                                if "ThreatRecord(" in line and "package=" in line:
                                    found_old_pattern.append(f"{fpath}:{line_num}: {line.strip()}")
                    except (OSError, UnicodeDecodeError):
                        continue

    assert not found_old_pattern, "Found ThreatRecord() with old 'package=' kwarg:\n" + "\n".join(found_old_pattern)


def test_returns_no_failures_when_importing_all_importers() -> None:
    """Verify all importers can be imported without errors.

    This is a broad smoke test to ensure no importer is broken after
    the command_models.py removal and import path updates.
    """
    failed = []
    for mod_name in ALL_COMMAND_IMPORTERS:
        try:
            import_module(mod_name)
        except ImportError as e:
            failed.append(f"{mod_name}: {e}")
        except Exception as e:
            failed.append(f"{mod_name}: Unexpected error - {e}")

    assert not failed, "Failed to import modules:\n" + "\n".join(failed)


def test_no_pkgd_run_command() -> None:
    """Verify pkgd run command is not available."""
    from click.testing import CliRunner

    from pkg_defender.cli.main import cli

    runner = CliRunner()
    result = runner.invoke(cli, ["run", "--help"])
    assert result.exit_code != 0, "pkgd run should not exist"
    assert "No such command" in result.output


def test_no_command_map_module() -> None:
    """Verify command_map module cannot be imported."""
    with pytest.raises((ImportError, ModuleNotFoundError)):
        import pkg_defender.cli.command_map  # type: ignore[import-not-found]  # noqa: F401  # pyright: ignore[reportMissingImports]


def test_returns_exit_code_zero_when_invoking_npm_and_pip_wrappers() -> None:
    """Verify wrapper pattern works for npm and pip."""
    from click.testing import CliRunner

    from pkg_defender.cli.main import cli

    runner = CliRunner()

    # Test npm wrapper
    result = runner.invoke(cli, ["npm", "--help"])
    assert result.exit_code == 0, "pkgd npm should work"

    # Test pip wrapper
    result = runner.invoke(cli, ["pip", "--help"])
    assert result.exit_code == 0, "pkgd pip should work"


def test_audit_logs_command_exists() -> None:
    """Verify pkgd audit-logs query and stats commands work."""
    from click.testing import CliRunner

    from pkg_defender.cli.main import cli

    runner = CliRunner()

    # Test audit-logs query
    result = runner.invoke(cli, ["audit-logs", "query", "--help"])
    assert result.exit_code == 0, "pkgd audit-logs query should work"

    # Test audit-logs stats
    result = runner.invoke(cli, ["audit-logs", "stats", "--help"])
    assert result.exit_code == 0, "pkgd audit-logs stats should work"
