"""
luci_sky.reporters.html_reporter — Jinja2 HTML reporter.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import ClassVar, Dict, Optional

from jinja2 import Environment, FileSystemLoader

from luci_sky.config import Config
from luci_sky.models import ScanResult, Severity
from luci_sky.reporters.base import Reporter

SEVERITY_COLORS: Dict[str, str] = {
    "CRITICAL": "#d32f2f",
    "HIGH": "#f57c00",
    "MEDIUM": "#f9a825",
    "LOW": "#388e3c",
    "INFO": "#1976d2",
}


class HtmlReporter(Reporter):
    """Jinja2-based HTML file reporter."""

    format_name: ClassVar[str] = "html"

    def render(self, result: ScanResult, output_path: Optional[Path] = None) -> None:
        dest = self._resolve_path(output_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        template_dir = Path(__file__).parent / "templates"
        env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=True,
        )
        template = env.get_template("report.html")

        by_sev = result.findings_by_severity()
        summary = {
            "critical": len(by_sev[Severity.CRITICAL]),
            "high": len(by_sev[Severity.HIGH]),
            "medium": len(by_sev[Severity.MEDIUM]),
            "low": len(by_sev[Severity.LOW]),
            "info": len(by_sev[Severity.INFO]),
        }

        # Build severity_colors dict keyed by enum name (CRITICAL, HIGH, etc.)
        severity_colors = {k: v for k, v in SEVERITY_COLORS.items()}

        html_content = template.render(
            result=result,
            summary=summary,
            severity_colors=severity_colors,
            findings_by_severity=by_sev,
        )

        dest.write_text(html_content, encoding="utf-8")
        print(f"HTML report written to: {dest}")

    def _resolve_path(self, override: Optional[Path] = None) -> Path:
        if override:
            return Path(override)
        if self._config.output_path:
            return Path(self._config.output_path)
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        return Path.cwd() / f"luci-redteam-{timestamp}.html"
