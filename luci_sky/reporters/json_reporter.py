"""
luci_sky.reporters.json_reporter — JSON file reporter.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import ClassVar, Optional

from luci_sky.config import Config
from luci_sky.models import ScanResult
from luci_sky.reporters.base import Reporter


class JsonReporter(Reporter):
    """Writes scan results as a JSON file."""

    format_name: ClassVar[str] = "json"

    def render(self, result: ScanResult, output_path: Optional[Path] = None) -> None:
        dest = self._resolve_path(output_path)
        data = result.to_dict()
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        print(f"JSON report written to: {dest}")

    def _resolve_path(self, override: Optional[Path] = None) -> Path:
        if override:
            return Path(override)
        if self._config.output_path:
            return Path(self._config.output_path)
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        return Path.cwd() / f"luci-redteam-{timestamp}.json"
