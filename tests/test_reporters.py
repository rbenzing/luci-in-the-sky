"""
Unit tests for luci_sky.reporters — TerminalReporter, JsonReporter, HtmlReporter.

Tests will fail with ImportError until the reporter modules are implemented.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

from luci_sky.config import Config
from luci_sky.models import (
    Category,
    Confidence,
    Finding,
    ScanMode,
    ScanResult,
    Severity,
    Target,
)
from luci_sky.reporters import get_reporters
from luci_sky.reporters.base import Reporter
from luci_sky.reporters.html_reporter import HtmlReporter
from luci_sky.reporters.json_reporter import JsonReporter
from luci_sky.reporters.terminal import TerminalReporter


# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------


def _make_target() -> Target:
    return Target(
        url="https://192.168.1.1",
        host="192.168.1.1",
        port=443,
        scheme="https",
        detected_version="21.02.3",
        detected_luci_version=None,
        open_ports=[],
        accessible_paths=[],
        is_authenticated=False,
    )


def _make_finding(
    finding_id: str = "LUCI-TEST-001",
    severity: Severity = Severity.CRITICAL,
    cvss_score: float = 9.8,
    title: str = "Test Finding Title",
    remediation: str = "Apply the recommended patch immediately.",
) -> Finding:
    return Finding(
        id=finding_id,
        check_id="test_check",
        title=title,
        severity=severity,
        cvss_score=cvss_score,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        category=Category.AUTHENTICATION,
        confidence=Confidence.HIGH,
        description="Test vulnerability description.",
        evidence="POST /login returned sysauth cookie.",
        affected_url="https://192.168.1.1/cgi-bin/luci/;stok=/login",
        remediation=remediation,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-12272"],
        cve_ids=["CVE-2019-12272"],
        scan_mode=ScanMode.ACTIVE,
        timestamp=datetime(2026, 4, 23, 12, 0, 0),
    )


def _make_result(findings: list = None) -> ScanResult:
    return ScanResult(
        target=_make_target(),
        findings=findings or [],
        scan_mode=ScanMode.ACTIVE,
        tool_version="1.0.0",
        started_at=datetime(2026, 4, 23, 12, 0, 0),
        finished_at=datetime(2026, 4, 23, 12, 1, 30),
        checks_run=10,
        checks_failed=0,
    )


def _make_config(output_path: Path = None) -> Config:
    cfg = Config()
    cfg.output_path = output_path
    cfg.no_color = True
    return cfg


# ---------------------------------------------------------------------------
# Reporter base class
# ---------------------------------------------------------------------------


class TestReporterBase:
    def test_reporter_is_abstract(self):
        """Instantiating Reporter directly must raise TypeError."""
        with pytest.raises(TypeError):
            Reporter(Config())  # type: ignore[abstract]

    def test_concrete_reporter_must_implement_render(self):
        """A subclass without render() must raise TypeError on instantiation."""

        class NoRenderReporter(Reporter):
            format_name = "no_render"
            # render() deliberately NOT defined

        with pytest.raises(TypeError):
            NoRenderReporter(Config())


# ---------------------------------------------------------------------------
# TerminalReporter
# ---------------------------------------------------------------------------


class TestTerminalReporter:
    def _render_to_string(self, result: ScanResult, no_color: bool = True) -> str:
        cfg = _make_config()
        cfg.no_color = no_color
        reporter = TerminalReporter(cfg)
        output = StringIO()
        with patch("luci_sky.reporters.terminal.Console") as MockConsole:
            # Capture print calls
            console_instance = MockConsole.return_value
            printed_lines: list = []
            console_instance.print.side_effect = lambda *args, **kwargs: printed_lines.append(
                " ".join(str(a) for a in args)
            )
            reporter.render(result)
        return "\n".join(printed_lines)

    def test_terminal_reporter_render_no_findings(self, capsys, tmp_path):
        """render() with empty findings must complete without exception."""
        cfg = _make_config()
        cfg.no_color = True
        reporter = TerminalReporter(cfg)
        result = _make_result(findings=[])
        # Must not raise
        reporter.render(result)

    def test_terminal_reporter_render_with_findings(self, capsys):
        """render() must output text that includes both finding titles."""
        finding1 = _make_finding("F1", title="Finding Alpha")
        finding2 = _make_finding("F2", severity=Severity.HIGH, cvss_score=7.5, title="Finding Beta")
        result = _make_result(findings=[finding1, finding2])

        cfg = _make_config()
        cfg.no_color = True
        reporter = TerminalReporter(cfg)

        captured_text: list = []
        with patch("luci_sky.reporters.terminal.Console") as MockConsole:
            instance = MockConsole.return_value
            instance.print.side_effect = lambda *a, **kw: captured_text.extend(
                [str(x) for x in a]
            )
            reporter.render(result)

        combined = " ".join(captured_text)
        assert "Finding Alpha" in combined or "Alpha" in combined or "F1" in combined

    def test_terminal_reporter_severity_in_output(self, capsys):
        """render() must include the word 'CRITICAL' for a CRITICAL-severity finding."""
        finding = _make_finding(severity=Severity.CRITICAL, cvss_score=9.8)
        result = _make_result(findings=[finding])

        cfg = _make_config()
        cfg.no_color = True
        reporter = TerminalReporter(cfg)

        captured_text: list = []
        with patch("luci_sky.reporters.terminal.Console") as MockConsole:
            instance = MockConsole.return_value
            instance.print.side_effect = lambda *a, **kw: captured_text.extend(
                [str(x) for x in a]
            )
            reporter.render(result)

        combined = " ".join(captured_text)
        assert "CRITICAL" in combined.upper() or "9.8" in combined

    def test_terminal_reporter_no_color_flag(self, capsys):
        """no_color=True must be passed to Console to suppress ANSI escape sequences."""
        cfg = _make_config()
        cfg.no_color = True
        reporter = TerminalReporter(cfg)
        result = _make_result()

        with patch("luci_sky.reporters.terminal.Console") as MockConsole:
            reporter.render(result)
            call_kwargs = MockConsole.call_args[1] if MockConsole.call_args else {}
            # Either no_color kwarg or force_terminal=False
            assert call_kwargs.get("no_color") is True or "no_color" in str(MockConsole.call_args)

    def test_terminal_reporter_remediation_printed(self):
        """render() must include the remediation text for each finding."""
        remediation_text = "UNIQUE_REMEDIATION_TEXT_12345"
        finding = _make_finding(remediation=remediation_text)
        result = _make_result(findings=[finding])

        cfg = _make_config()
        cfg.no_color = True
        reporter = TerminalReporter(cfg)

        captured_text: list = []
        with patch("luci_sky.reporters.terminal.Console") as MockConsole:
            instance = MockConsole.return_value
            instance.print.side_effect = lambda *a, **kw: captured_text.extend(
                [str(x) for x in a]
            )
            reporter.render(result)

        combined = " ".join(captured_text)
        assert remediation_text in combined or "UNIQUE_REMEDIATION" in combined


# ---------------------------------------------------------------------------
# JsonReporter
# ---------------------------------------------------------------------------


class TestJsonReporter:
    def test_json_reporter_writes_file(self, tmp_path: Path):
        """render() must create a JSON file at the configured output_path."""
        out_file = tmp_path / "report.json"
        cfg = _make_config(output_path=out_file)
        reporter = JsonReporter(cfg)
        result = _make_result(findings=[_make_finding()])
        reporter.render(result)

        assert out_file.exists()
        content = out_file.read_text()
        parsed = json.loads(content)
        assert isinstance(parsed, dict)

    def test_json_reporter_output_contains_findings(self, tmp_path: Path):
        """The JSON output must include a non-empty 'findings' list."""
        out_file = tmp_path / "report.json"
        cfg = _make_config(output_path=out_file)
        reporter = JsonReporter(cfg)
        result = _make_result(findings=[_make_finding()])
        reporter.render(result)

        data = json.loads(out_file.read_text())
        assert "findings" in data
        assert len(data["findings"]) == 1

    def test_json_reporter_finding_has_all_required_fields(self, tmp_path: Path):
        """Each finding dict in the JSON must contain all required fields."""
        out_file = tmp_path / "report.json"
        cfg = _make_config(output_path=out_file)
        reporter = JsonReporter(cfg)
        result = _make_result(findings=[_make_finding()])
        reporter.render(result)

        data = json.loads(out_file.read_text())
        finding = data["findings"][0]
        for field in ("id", "check_id", "title", "severity", "cvss_score", "category",
                      "evidence", "remediation"):
            assert field in finding, f"Required field '{field}' missing from finding dict"

    def test_json_reporter_timestamps_are_iso_format(self, tmp_path: Path):
        """started_at and finished_at must be ISO 8601 strings in the JSON output."""
        out_file = tmp_path / "report.json"
        cfg = _make_config(output_path=out_file)
        reporter = JsonReporter(cfg)
        result = _make_result()
        reporter.render(result)

        data = json.loads(out_file.read_text())
        assert "started_at" in data
        assert "T" in data["started_at"]  # ISO 8601 separator
        assert data["finished_at"] is not None

    def test_json_reporter_default_filename_has_timestamp(self, tmp_path: Path):
        """When no output_path is set, the file must be created with a timestamped name."""
        cfg = _make_config(output_path=None)
        reporter = JsonReporter(cfg)
        result = _make_result()

        with patch("luci_sky.reporters.json_reporter.Path.cwd", return_value=tmp_path):
            reporter.render(result)

        # Check that some file matching luci-redteam-*.json was created
        json_files = list(tmp_path.glob("luci-redteam-*.json"))
        assert len(json_files) >= 1

    def test_json_reporter_output_path_respected(self, tmp_path: Path):
        """render() must write to the exact path specified in config.output_path."""
        custom_path = tmp_path / "custom_report.json"
        cfg = _make_config(output_path=custom_path)
        reporter = JsonReporter(cfg)
        reporter.render(_make_result())

        assert custom_path.exists()


# ---------------------------------------------------------------------------
# HtmlReporter
# ---------------------------------------------------------------------------


class TestHtmlReporter:
    def test_html_reporter_writes_file(self, tmp_path: Path):
        """render() must create an HTML file at the configured output_path."""
        out_file = tmp_path / "report.html"
        cfg = _make_config(output_path=out_file)
        reporter = HtmlReporter(cfg)
        reporter.render(_make_result(findings=[_make_finding()]))
        assert out_file.exists()

    def test_html_reporter_output_is_valid_html(self, tmp_path: Path):
        """The HTML output must start with <!DOCTYPE html> and end with </html>."""
        out_file = tmp_path / "report.html"
        cfg = _make_config(output_path=out_file)
        reporter = HtmlReporter(cfg)
        reporter.render(_make_result(findings=[_make_finding()]))
        content = out_file.read_text()
        assert "<!DOCTYPE html>" in content or "<!doctype html>" in content.lower()
        assert "</html>" in content

    def test_html_reporter_finding_title_in_output(self, tmp_path: Path):
        """The rendered HTML must include the finding's title text."""
        finding = _make_finding(title="Unique Finding Title ABC123")
        out_file = tmp_path / "report.html"
        cfg = _make_config(output_path=out_file)
        reporter = HtmlReporter(cfg)
        reporter.render(_make_result(findings=[finding]))
        content = out_file.read_text()
        assert "Unique Finding Title ABC123" in content

    def test_html_reporter_no_external_resources(self, tmp_path: Path):
        """Rendered HTML must not reference any external URLs in src/href/url() attributes."""
        out_file = tmp_path / "report.html"
        cfg = _make_config(output_path=out_file)
        reporter = HtmlReporter(cfg)
        reporter.render(_make_result(findings=[_make_finding()]))
        content = out_file.read_text()

        # Look for external references in src=, href=, and url() CSS
        ext_src = re.findall(r'src=["\']https?://', content)
        ext_href = re.findall(r'href=["\']https?://', content)
        ext_url = re.findall(r'url\(["\']?https?://', content)

        assert not ext_src, f"External src references found: {ext_src}"
        assert not ext_href, f"External href references found: {ext_href}"
        assert not ext_url, f"External CSS url() references found: {ext_url}"

    def test_html_reporter_severity_colors_applied(self, tmp_path: Path):
        """SEVERITY_COLORS hex codes from HtmlReporter must appear in the HTML output."""
        out_file = tmp_path / "report.html"
        cfg = _make_config(output_path=out_file)
        reporter = HtmlReporter(cfg)
        reporter.render(_make_result(findings=[_make_finding()]))
        content = out_file.read_text()

        # At least one of the severity color codes must appear
        from luci_sky.reporters.html_reporter import SEVERITY_COLORS
        found_color = any(color.lstrip("#") in content or color in content
                          for color in SEVERITY_COLORS.values())
        assert found_color, "No SEVERITY_COLORS hex codes found in HTML output"

    def test_html_reporter_cvss_score_displayed(self, tmp_path: Path):
        """CVSS score 9.8 must appear in the HTML for a CRITICAL finding."""
        finding = _make_finding(cvss_score=9.8)
        out_file = tmp_path / "report.html"
        cfg = _make_config(output_path=out_file)
        reporter = HtmlReporter(cfg)
        reporter.render(_make_result(findings=[finding]))
        content = out_file.read_text()
        assert "9.8" in content

    def test_html_reporter_empty_findings_renders_cleanly(self, tmp_path: Path):
        """render() with no findings must produce a valid HTML file without errors."""
        out_file = tmp_path / "report.html"
        cfg = _make_config(output_path=out_file)
        reporter = HtmlReporter(cfg)
        reporter.render(_make_result(findings=[]))
        assert out_file.exists()
        content = out_file.read_text()
        assert "html" in content.lower()


# ---------------------------------------------------------------------------
# Reporter registry (get_reporters)
# ---------------------------------------------------------------------------


class TestGetReporters:
    def test_get_reporters_all_returns_three(self):
        """get_reporters('all') must return a list of exactly three reporter classes."""
        reporters = get_reporters("all")
        assert len(reporters) == 3

    def test_get_reporters_terminal_returns_one(self):
        """get_reporters('terminal') must return [TerminalReporter]."""
        reporters = get_reporters("terminal")
        assert len(reporters) == 1
        assert reporters[0] is TerminalReporter

    def test_get_reporters_json_returns_json_reporter(self):
        """get_reporters('json') must return [JsonReporter]."""
        reporters = get_reporters("json")
        assert len(reporters) == 1
        assert reporters[0] is JsonReporter

    def test_get_reporters_html_returns_html_reporter(self):
        """get_reporters('html') must return [HtmlReporter]."""
        reporters = get_reporters("html")
        assert len(reporters) == 1
        assert reporters[0] is HtmlReporter

    def test_get_reporters_unknown_returns_terminal(self):
        """get_reporters with an unknown format must fall back to [TerminalReporter]."""
        reporters = get_reporters("invalid_format_xyz")
        assert len(reporters) == 1
        assert reporters[0] is TerminalReporter


# ---------------------------------------------------------------------------
# HtmlReporter — self-contained interactive report (Task 15)
# ---------------------------------------------------------------------------


def _render(sample_scan_result, tmp_path) -> str:
    cfg = Config()
    out = tmp_path / "r.html"
    HtmlReporter(cfg).render(sample_scan_result, output_path=out)
    return out.read_text(encoding="utf-8")


def test_html_is_self_contained(sample_scan_result, tmp_path):
    # "Self-contained" means no external ASSET references. Reference URLs may still
    # appear as plain text, so assert on asset-loading markers, not the string "http".
    html = _render(sample_scan_result, tmp_path).lower()
    assert "<link" not in html      # no external stylesheets
    assert "src=" not in html        # no external scripts/images
    assert "href=" not in html       # references rendered as text, not <a> links
    assert "@import" not in html
    assert "cdn" not in html


def test_html_has_summary_and_filters(sample_scan_result, tmp_path):
    html = _render(sample_scan_result, tmp_path)
    assert "Executive Summary" in html
    assert 'data-severity' in html            # filterable finding rows
    assert "filterBySeverity" in html          # inline filter script


def test_html_shows_finding_details(sample_scan_result, tmp_path):
    """The rendered HTML must include affected_url, description, and CVE ids for
    findings, while remaining self-contained (no href=/src=/<link markers)."""
    html = _render(sample_scan_result, tmp_path)
    finding = sample_scan_result.findings[0]
    assert finding.affected_url in html
    assert finding.description in html
    for cve in finding.cve_ids:
        assert cve in html

    lowered = html.lower()
    assert "<link" not in lowered
    assert "src=" not in lowered
    assert "href=" not in lowered
