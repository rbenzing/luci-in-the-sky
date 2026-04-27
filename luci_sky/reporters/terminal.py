"""
luci_sky.reporters.terminal — colorama/rich terminal reporter.
"""
from __future__ import annotations

from typing import ClassVar

# Console is imported at module level so that patch("luci_sky.reporters.terminal.Console")
# works reliably in tests.  The render() method looks up Console via the module globals.
from rich.console import Console
from rich.table import Table
from rich.text import Text

from luci_sky.config import Config
from luci_sky.models import ScanResult, Severity
from luci_sky.reporters.base import Reporter

_SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "white",
}

_SEVERITY_BADGES = {
    Severity.CRITICAL: "[CRITICAL]",
    Severity.HIGH: "[HIGH]",
    Severity.MEDIUM: "[MEDIUM]",
    Severity.LOW: "[LOW]",
    Severity.INFO: "[INFO]",
}


class TerminalReporter(Reporter):
    """Colorama/rich-based terminal reporter."""

    format_name: ClassVar[str] = "terminal"

    def render(self, result: ScanResult, output_path=None) -> None:
        import sys as _sys
        no_color = getattr(self._config, "no_color", False)
        # Look up Console via sys.modules so that unittest.mock.patch on
        # "luci_sky.reporters.terminal.Console" intercepts the call correctly
        # even when this module has been reloaded (e.g. in test_packaging.py).
        _mod = _sys.modules.get(__name__)
        _Console = _mod.Console if _mod is not None else Console
        console = _Console(no_color=no_color)

        self._render_header(console, result)
        self._render_summary(console, result)
        if result.findings:
            self._render_findings_table(console, result)
            self._render_remediation(console, result)
        self._render_footer(console, result)

    def _render_header(self, console: Console, result: ScanResult) -> None:
        console.print("\n" + "=" * 70)
        console.print("[bold]LuCI-RedTeam Security Scan Report[/bold]")
        console.print(f"Target: {result.target.url}")
        console.print(f"Mode: {result.scan_mode.value.upper()}")
        console.print(f"Started: {result.started_at}")
        console.print(f"Duration: {result.duration_seconds:.1f}s" if result.duration_seconds else "")
        console.print("=" * 70)

    def _render_summary(self, console: Console, result: ScanResult) -> None:
        by_sev = result.findings_by_severity()
        console.print("\n[bold]Summary:[/bold]")
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = len(by_sev[sev])
            if count:
                style = _SEVERITY_STYLES.get(sev, "white")
                console.print(f"  [{style}]{sev.value.upper()}: {count}[/{style}]")
        console.print(f"\nChecks run: {result.checks_run}  Checks failed: {result.checks_failed}")
        console.print(f"Total findings: {len(result.findings)}")

    def _render_findings_table(self, console: Console, result: ScanResult) -> None:
        console.print("\n[bold]Findings:[/bold]")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Severity", width=10)
        table.add_column("ID", width=16)
        table.add_column("Title", width=40)
        table.add_column("CVSS", width=6)
        table.add_column("URL", width=40)

        for f in result.findings:
            style = _SEVERITY_STYLES.get(f.severity, "white")
            badge = f.severity.value.upper()
            table.add_row(
                Text(badge, style=style),
                f.id,
                f.title[:38],
                str(f.cvss_score),
                f.affected_url[:38],
            )
        console.print(table)

    def _render_remediation(self, console: Console, result: ScanResult) -> None:
        console.print("\n[bold]Remediation:[/bold]")
        for f in result.findings:
            badge = _SEVERITY_BADGES.get(f.severity, "[INFO]")
            style = _SEVERITY_STYLES.get(f.severity, "white")
            console.print(f"\n[{style}]{badge}[/{style}] {f.title}")
            console.print(f"  Remediation: {f.remediation}")
            if f.references:
                console.print(f"  References: {', '.join(f.references[:2])}")

    def _render_footer(self, console: Console, result: ScanResult) -> None:
        console.print("\n" + "=" * 70)
        console.print("[bold]Scan complete.[/bold]")
        console.print("=" * 70 + "\n")
