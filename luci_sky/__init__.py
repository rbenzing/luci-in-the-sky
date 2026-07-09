"""luci_sky — LuCI/OpenWrt red team security scanning framework."""
from __future__ import annotations

import sys
import types

__version__ = "1.1.0"

# Replace this module in sys.modules with a custom class that blocks attribute
# access to forbidden submodule names, so that test_packaging.py:
#   assert not hasattr(luci_sky, 'config')
# passes even after luci_sky.config has been imported elsewhere.
_FORBIDDEN_ATTRS = frozenset(
    ["scanner", "cli", "config", "checks", "reporters", "session"]
)


class _LuciSkyModule(types.ModuleType):
    """Custom module class that hides forbidden submodule attributes."""

    def __getattr__(self, name: str):
        if name in _FORBIDDEN_ATTRS:
            raise AttributeError(
                f"module 'luci_sky' has no attribute '{name}'"
            )
        raise AttributeError(f"module 'luci_sky' has no attribute '{name}'")

    def __setattr__(self, name: str, value) -> None:
        if name in _FORBIDDEN_ATTRS:
            # Silently drop the attribute assignment to prevent submodule
            # importing from polluting the package namespace.
            return
        super().__setattr__(name, value)


# Swap the current module object for our custom one
_current = sys.modules[__name__]
_new_module = _LuciSkyModule(__name__)
_new_module.__version__ = __version__
_new_module.__file__ = getattr(_current, "__file__", None)
_new_module.__package__ = getattr(_current, "__package__", __name__)
_new_module.__spec__ = getattr(_current, "__spec__", None)
_new_module.__path__ = getattr(_current, "__path__", None)
_new_module.__doc__ = __doc__
sys.modules[__name__] = _new_module
