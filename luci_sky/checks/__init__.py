"""
luci_sky.checks — check plugin registry.

The _REGISTRY dict maps check_id -> Check class.
Use @register on any Check subclass to add it automatically.
"""
from __future__ import annotations

from typing import Dict, List, Type, TYPE_CHECKING

from luci_sky.checks.base import Check
from luci_sky.config import Config
from luci_sky.models import ScanMode, Severity

if TYPE_CHECKING:
    pass

_REGISTRY: Dict[str, Type[Check]] = {}


def register(cls: Type[Check]) -> Type[Check]:
    """
    Decorator that adds a Check subclass to the registry.

    Raises ValueError if:
    - The class has no 'id' attribute
    - A class with the same id is already registered
    """
    check_id = getattr(cls, "id", None)
    if not check_id:
        raise ValueError(f"Check class {cls.__name__} has no 'id' attribute")
    if check_id in _REGISTRY:
        raise ValueError(
            f"Duplicate check id '{check_id}' — "
            f"already registered by {_REGISTRY[check_id].__name__}"
        )
    _REGISTRY[check_id] = cls
    return cls


def all_checks() -> List[Check]:
    """Return one instance of every registered Check."""
    return [cls() for cls in _REGISTRY.values()]


def get_check(check_id: str) -> Check:
    """Return an instance of the check registered under *check_id*."""
    if check_id not in _REGISTRY:
        available = ", ".join(sorted(_REGISTRY.keys()))
        raise KeyError(
            f"Unknown check id '{check_id}'. "
            f"Available: {available}"
        )
    return _REGISTRY[check_id]()


def filtered_checks(
    mode: ScanMode,
    severity_threshold: Severity,
    include_ids: List[str],
    exclude_ids: List[str],
    requires_auth: bool,
) -> List[Check]:
    """
    Return instantiated checks eligible for the given scan parameters.

    Filter rules (all must pass):
    1. Current mode allows the check's min_mode
    2. Check severity >= severity_threshold
    3. If check requires_auth and requires_auth=False → exclude
    4. If include_ids non-empty → only those IDs
    5. Exclude IDs in exclude_ids
    """
    result: List[Check] = []
    for check_id, cls in _REGISTRY.items():
        # Rule 1: mode compatibility
        if not mode.allows(cls.min_mode):
            continue
        # Rule 2: severity threshold
        if cls.severity.numeric_rank < severity_threshold.numeric_rank:
            continue
        # Rule 3: auth requirement
        if cls.requires_auth and not requires_auth:
            continue
        # Rule 4: include list
        if include_ids and check_id not in include_ids:
            continue
        # Rule 5: exclude list
        if check_id in exclude_ids:
            continue
        result.append(cls())
    return result


# ---------------------------------------------------------------------------
# Auto-import all category modules — triggers @register decorators
# ---------------------------------------------------------------------------
from luci_sky.checks import tls  # noqa: E402, F401
from luci_sky.checks import info_disclosure  # noqa: E402, F401
from luci_sky.checks import network  # noqa: E402, F401
from luci_sky.checks import cve  # noqa: E402, F401
from luci_sky.checks import auth  # noqa: E402, F401
from luci_sky.checks import injection  # noqa: E402, F401
from luci_sky.checks import xss  # noqa: E402, F401
from luci_sky.checks import csrf  # noqa: E402, F401
from luci_sky.checks import session  # noqa: E402, F401
