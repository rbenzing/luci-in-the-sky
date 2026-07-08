"""luci_sky.cve.update — fetch or copy a CVE DB into the user data dir."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml

from luci_sky.cve import storage

_DEFAULT_URL = (
    "https://raw.githubusercontent.com/rbenzing/luci-in-the-sky/"
    "main/luci_sky/cve/data/luci_cves.yml"
)


def _validate(text: str) -> None:
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or not isinstance(data.get("cves"), list):
        raise ValueError("CVE database must be a mapping with a 'cves' list")


def update_cve_db(url: Optional[str] = None, from_file: Optional[Path] = None,
                  force: bool = False) -> Path:
    """Write a validated CVE DB to the user data dir. Returns the written path."""
    if from_file is not None:
        text = Path(from_file).read_text(encoding="utf-8")
    else:
        import requests
        resp = requests.get(url or _DEFAULT_URL, timeout=30)
        resp.raise_for_status()
        text = resp.text

    _validate(text)  # raises ValueError before touching the destination

    dest = storage.user_db_path()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    return dest
