"""
luci_sky.reporters.base — abstract Reporter base class.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from luci_sky.config import Config
from luci_sky.models import ScanResult


class Reporter(ABC):
    """Abstract base class for all report renderers."""

    format_name: ClassVar[str]

    def __init__(self, config: Config) -> None:
        self._config = config

    @abstractmethod
    def render(self, result: ScanResult, output_path=None) -> None:
        """Render the scan result to the configured output destination."""
