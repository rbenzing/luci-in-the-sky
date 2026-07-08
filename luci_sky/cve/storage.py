"""luci_sky.cve.storage — resolve the user-writable CVE data directory."""
from __future__ import annotations

import os
import sys
from pathlib import Path

_APP = "luci-sky"
_DB_NAME = "luci_cves.yml"


def user_data_dir() -> Path:
    override = os.environ.get("LUCI_DATA_DIR")
    if override:
        return Path(override)
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / _APP
    return Path.home() / ".local" / "share" / _APP


def user_db_path() -> Path:
    return user_data_dir() / _DB_NAME
