"""
luci_sky.reporters — reporter registry and factory.
"""
from __future__ import annotations

from typing import List, Type

from luci_sky.reporters.base import Reporter
from luci_sky.reporters.html_reporter import HtmlReporter
from luci_sky.reporters.json_reporter import JsonReporter
from luci_sky.reporters.terminal import TerminalReporter

_REPORTER_MAP = {
    "terminal": TerminalReporter,
    "json": JsonReporter,
    "html": HtmlReporter,
}


def get_reporters(format_spec: str) -> List[Type[Reporter]]:
    """Return a list of Reporter classes for the given format specifier.

    Special values:
      - "all"  → all three reporters
      - Any unknown format → falls back to [TerminalReporter]
    """
    if format_spec == "all":
        return [TerminalReporter, JsonReporter, HtmlReporter]
    reporter_cls = _REPORTER_MAP.get(format_spec)
    if reporter_cls is None:
        return [TerminalReporter]
    return [reporter_cls]
