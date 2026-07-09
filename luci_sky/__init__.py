"""luci_sky — LuCI/OpenWrt red team security scanning framework.

The package ``__init__`` is intentionally minimal: it exposes only ``__version__``
and must not import any submodules (scanner, cli, config, checks, reporters,
session). Keeping it import-free avoids circular-import risk and keeps the public
namespace clean — this contract is enforced by ``tests/test_packaging.py``.
"""
from __future__ import annotations

__version__ = "1.1.0"
