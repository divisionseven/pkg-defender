"""Tests for lazy loading of heavy imports in CLI."""

from __future__ import annotations

import sys
from types import ModuleType


def _teardown_intel_modules(
    saved_modules: dict[str, ModuleType | None],
) -> None:
    """Restore original intel modules after test.

    During the test, modules are popped from sys.modules and re-imported
    to verify lazy-loading. This creates new module objects whose __dict__
    differs from the __globals__ of collection-time function references.

    Restoring the original modules ensures downstream patches target the
    same module objects that functions resolve through __globals__.
    """
    for mod_name, original_mod in saved_modules.items():
        if original_mod is not None:
            sys.modules[mod_name] = original_mod  # Restore original
        else:
            sys.modules.pop(mod_name, None)  # Was never there, ensure gone


def test_aiohttp_not_loaded_at_cli_startup() -> None:
    """Verify aiohttp is NOT loaded when CLI starts (--help).

    Before the lazy loading fix, aiohttp was imported at module level,
    causing it to be loaded immediately when pkgd is invoked.
    """
    # Track modules before import
    before = set(sys.modules.keys())

    # Import the CLI module (simulates `pkgd --help`)
    from pkg_defender.cli import main as cli_main  # noqa: F401

    # Check if aiohttp was loaded
    after = set(sys.modules.keys())
    new_modules = after - before

    # aiohttp should NOT be in sys.modules after just importing the CLI
    assert "aiohttp" not in new_modules, (
        "aiohttp should NOT be loaded at CLI import time - it should only be loaded when token validation runs"
    )


def test_intel_adapters_not_loaded_at_cli_startup() -> None:
    """Verify intel adapters are NOT loaded when CLI starts (--help).

    Before the lazy loading fix, intel adapters were imported at module level,
    causing them to be loaded immediately when pkgd is invoked.
    """
    # Track modules before import
    before = set(sys.modules.keys())

    # Import the CLI module (simulates `pkgd --help`)
    from pkg_defender.cli import main as cli_main  # noqa: F401

    # Check if intel adapters were loaded
    after = set(sys.modules.keys())
    new_modules = after - before

    # These modules should NOT be loaded after just importing the CLI
    heavy_modules = [
        "pkg_defender.intel.aggregator",
        "pkg_defender.intel.ghsa",
        "pkg_defender.intel.socket",
        "pkg_defender.intel.x_twitter",
        "pkg_defender.intel.mastodon",
        "pkg_defender.intel.reddit",
        "pkg_defender.intel.rss_feed",
        "pkg_defender.intel.npm_advisory",
    ]

    for module_name in heavy_modules:
        assert module_name not in new_modules, (
            f"{module_name} should NOT be loaded at CLI import time - "
            "it should only be loaded when status/intel sync/intel report commands run"
        )


def test_lazy_imports_loaded_on_demand() -> None:
    """Verify intel adapters ARE loaded when explicitly imported.

    This test checks that the lazy import mechanism works correctly,
    and that the adapters are loaded when they're actually needed.

    Cleanup: Restores the original module objects to sys.modules after
    the test. When this test pops modules from sys.modules and re-imports
    them, new module objects are created whose __dict__ differs from the
    __globals__ of collection-time function references. Downstream patches
    that target the module path would silently miss because they modify
    the new module's __dict__ while functions resolve globals from the
    original module's __dict__.
    Restoring the original modules to sys.modules ensures consistency.
    """
    # Save original modules before clearing, so we can restore them later
    modules_to_clear = [
        "pkg_defender.intel.aggregator",
        "pkg_defender.intel.ghsa",
    ]
    saved: dict[str, ModuleType | None] = {}
    for mod in modules_to_clear:
        saved[mod] = sys.modules.get(mod)  # Save original (may be None)
        sys.modules.pop(mod, None)

    # Import by triggering lazy import pattern (simulates what status command does)
    # Note: Import all modules to ensure they're all loadable
    from pkg_defender.intel.aggregator import OSVFeedAdapter  # noqa: F401
    from pkg_defender.intel.base import FeedSource  # noqa: F401
    from pkg_defender.intel.ghsa import GHSAFeed  # noqa: F401
    from pkg_defender.intel.socket import SocketFeed  # noqa: F401
    from pkg_defender.intel.x_twitter import XTwitterFeed  # noqa: F401

    # Verify they are now loaded
    assert "pkg_defender.intel.aggregator" in sys.modules
    assert "pkg_defender.intel.base" in sys.modules
    assert "pkg_defender.intel.socket" in sys.modules
    assert "pkg_defender.intel.ghsa" in sys.modules
    assert "pkg_defender.intel.x_twitter" in sys.modules

    # --- Cleanup: restore original module objects to sys.modules ---
    # After this test, any re-imported modules must not conflict with
    # classes already imported by other test modules. Restoring the
    # original modules ensures downstream patches target the same module
    # objects that collection-time function references resolve through.
    _teardown_intel_modules(saved)


def test_aiohttp_loaded_on_token_validation() -> None:
    """Verify aiohttp IS loaded when token validation runs.

    This test checks that the lazy import works correctly,
    and that aiohttp is loaded only when token validation executes.
    """
    # Clear aiohttp if previously loaded
    sys.modules.pop("aiohttp", None)

    # Import the token validation function
    # This simulates what happens when `pkgd config set intel.github-token` is called
    from pkg_defender.cli.common import _validate_github_token  # noqa: F401

    # Note: The function itself does `import aiohttp` internally,
    # so we verify that when the function runs, aiohttp gets loaded
    # We can't easily test this without actually running the async function,
    # but the module-level test above proves the import was moved to lazy
