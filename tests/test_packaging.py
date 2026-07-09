"""
Package-level tests verifying that luci_sky is correctly structured and importable.

Tests will fail with ImportError/ModuleNotFoundError until luci_sky is installed
via `pip install -e .`.
"""
from __future__ import annotations

import importlib
import importlib.metadata
import sys

import pytest


class TestPackageImportable:
    def test_package_is_importable(self):
        """'import luci_sky' must succeed after pip install -e ."""
        import luci_sky  # noqa: F401 — import is the assertion

    def test_version_attribute_present(self):
        """luci_sky.__version__ must equal '1.1.0'."""
        import luci_sky
        assert hasattr(luci_sky, "__version__")
        assert luci_sky.__version__ == "1.1.0"

    def test_init_imports_nothing_else(self):
        """
        luci_sky/__init__.py must not import internal submodules.

        Importing scanner, cli, config, checks, etc. from __init__.py would
        create circular-import risk and violates the architecture contract.

        We force a fresh, isolated import of the package (purging any luci_sky.*
        modules that earlier tests imported) so this checks what __init__.py
        *itself* pulls in — not what the rest of the test session has loaded.
        """
        for mod in [k for k in sys.modules if k == "luci_sky" or k.startswith("luci_sky.")]:
            del sys.modules[mod]

        import luci_sky  # re-runs __init__.py in isolation

        forbidden = ["scanner", "cli", "config", "checks", "reporters", "session"]
        for name in forbidden:
            assert f"luci_sky.{name}" not in sys.modules, (
                f"luci_sky/__init__.py must not import '{name}'"
            )
            assert not hasattr(luci_sky, name), (
                f"luci_sky/__init__.py must not expose '{name}' as an attribute"
            )

    def test_console_script_registered(self):
        """
        The 'luci-sky' console script entry point must resolve to luci_sky.cli:cli.

        This verifies that pyproject.toml [project.scripts] is correctly defined.
        """
        try:
            eps = importlib.metadata.entry_points(group="console_scripts")
            luci_sky_ep = next((ep for ep in eps if ep.name == "luci-sky"), None)
            assert luci_sky_ep is not None, (
                "'luci-sky' console script entry point not found. "
                "Check [project.scripts] in pyproject.toml."
            )
            assert "luci_sky.cli" in luci_sky_ep.value, (
                f"Entry point value '{luci_sky_ep.value}' does not reference luci_sky.cli"
            )
        except importlib.metadata.PackageNotFoundError:
            pytest.skip("Package not installed; skipping entry point check")

    def test_no_circular_imports(self):
        """
        Importing luci_sky.cli (the outermost module) must not create circular imports.

        If there are circular imports, this will raise ImportError.
        """
        # Remove any cached module to force fresh import
        modules_to_remove = [k for k in sys.modules if k.startswith("luci_sky")]
        for mod in modules_to_remove:
            del sys.modules[mod]

        try:
            import luci_sky.cli  # noqa: F401
        except ImportError as e:
            if "circular" in str(e).lower() or "cannot import" in str(e).lower():
                pytest.fail(f"Circular import detected: {e}")
            else:
                raise  # Re-raise non-circular ImportError (expected if not yet implemented)
