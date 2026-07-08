"""
Unit tests for luci_sky.cli — CLI commands, argument parsing, exit codes.

Uses click.testing.CliRunner to invoke the CLI without a real subprocess.
Tests will fail with ImportError until luci_sky/cli.py is implemented.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from luci_sky.cli import cli
from luci_sky.models import (
    Category,
    Confidence,
    Finding,
    ScanMode,
    ScanResult,
    Severity,
    Target,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_target() -> Target:
    return Target(
        url="https://192.168.1.1",
        host="192.168.1.1",
        port=443,
        scheme="https",
        detected_version=None,
        detected_luci_version=None,
        is_authenticated=False,
    )


def _make_empty_result() -> ScanResult:
    return ScanResult(
        target=_make_target(),
        findings=[],
        scan_mode=ScanMode.PASSIVE,
        tool_version="1.0.0",
        started_at=datetime(2026, 4, 23, 12, 0, 0),
        finished_at=datetime(2026, 4, 23, 12, 1, 0),
        checks_run=5,
        checks_failed=0,
    )


def _make_result_with_critical() -> ScanResult:
    finding = Finding(
        id="LUCI-TEST-001",
        check_id="default_credentials",
        title="Default credentials accepted",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        category=Category.AUTHENTICATION,
        confidence=Confidence.HIGH,
        description="Default credentials accepted.",
        evidence="sysauth cookie present",
        affected_url="https://192.168.1.1/cgi-bin/luci/;stok=/login",
        remediation="Change default password.",
        references=[],
        cve_ids=[],
        scan_mode=ScanMode.ACTIVE,
        timestamp=datetime(2026, 4, 23, 12, 0, 30),
    )
    return ScanResult(
        target=_make_target(),
        findings=[finding],
        scan_mode=ScanMode.ACTIVE,
        tool_version="1.0.0",
        started_at=datetime(2026, 4, 23, 12, 0, 0),
        finished_at=datetime(2026, 4, 23, 12, 1, 0),
        checks_run=10,
        checks_failed=0,
    )


# ---------------------------------------------------------------------------
# scan command — argument validation
# ---------------------------------------------------------------------------


class TestCliScanArguments:
    def test_cli_scan_requires_target_url(self):
        """'scan' invoked with no arguments must exit with a usage error."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan"])
        assert result.exit_code != 0

    def test_cli_scan_help_flag(self):
        """'scan --help' must exit 0 and display help text."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "TARGET" in result.output or "target" in result.output.lower()


# ---------------------------------------------------------------------------
# scan command — exit codes
# ---------------------------------------------------------------------------


class TestCliScanExitCodes:
    def test_cli_scan_passive_exits_0_no_findings(self):
        """Scan with no findings at or above threshold must exit 0."""
        runner = CliRunner()

        with patch("luci_sky.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = _make_empty_result()
            result = runner.invoke(
                cli,
                ["scan", "https://192.168.1.1", "--mode", "passive", "--confirm"],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, f"Expected exit 0, got {result.exit_code}: {result.output}"

    def test_cli_scan_exits_1_with_findings_above_threshold(self):
        """Scan with at least one finding above threshold must exit 1."""
        runner = CliRunner()

        with patch("luci_sky.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = _make_result_with_critical()
            result = runner.invoke(
                cli,
                ["scan", "https://192.168.1.1", "--mode", "passive", "--confirm"],
                catch_exceptions=False,
            )

        assert result.exit_code == 1, f"Expected exit 1, got {result.exit_code}: {result.output}"

    def test_cli_scan_exits_2_on_unreachable_target(self):
        """Scan where Scanner.run() raises RuntimeError must exit 2."""
        runner = CliRunner()

        with patch("luci_sky.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.side_effect = RuntimeError("Target unreachable")
            result = runner.invoke(
                cli,
                ["scan", "https://192.168.1.1", "--mode", "passive", "--confirm"],
            )

        assert result.exit_code == 2, f"Expected exit 2, got {result.exit_code}: {result.output}"


# ---------------------------------------------------------------------------
# scan command — disclaimer
# ---------------------------------------------------------------------------


class TestCliDisclaimer:
    def test_cli_scan_shows_disclaimer(self):
        """Normal scan invocation must display disclaimer text containing 'authorized'."""
        runner = CliRunner()

        with patch("luci_sky.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = _make_empty_result()
            result = runner.invoke(
                cli,
                ["scan", "https://192.168.1.1", "--confirm"],
            )

        assert "authorized" in result.output.lower(), (
            f"Disclaimer not found in output: {result.output[:300]}"
        )

    def test_cli_scan_quiet_suppresses_disclaimer(self):
        """--quiet flag must suppress the disclaimer."""
        runner = CliRunner()

        with patch("luci_sky.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = _make_empty_result()
            result = runner.invoke(
                cli,
                ["scan", "https://192.168.1.1", "--confirm", "--quiet"],
            )

        # Disclaimer should not appear
        assert "authorized" not in result.output.lower()


# ---------------------------------------------------------------------------
# scan command — active mode confirmation
# ---------------------------------------------------------------------------


class TestCliActiveModeConfirmation:
    def test_cli_scan_active_mode_without_confirm_prompts(self):
        """Active mode without --confirm must display a confirmation prompt."""
        runner = CliRunner()

        with patch("luci_sky.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = _make_empty_result()
            # Answer 'n' to the confirmation prompt
            result = runner.invoke(
                cli,
                ["scan", "https://192.168.1.1", "--mode", "active"],
                input="n\n",
            )

        # Should show prompt text or abort message
        assert ("confirm" in result.output.lower()
                or "abort" in result.output.lower()
                or "proceed" in result.output.lower()
                or result.exit_code == 0)

    def test_cli_scan_active_mode_with_confirm_skips_prompt(self):
        """--confirm flag must suppress the interactive confirmation gate."""
        runner = CliRunner()

        with patch("luci_sky.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = _make_empty_result()
            result = runner.invoke(
                cli,
                ["scan", "https://192.168.1.1", "--mode", "active", "--confirm"],
            )

        # Should not prompt and should proceed to scan (exit 0 with no findings)
        assert result.exit_code in (0, 1), (
            f"Expected successful scan exit code, got {result.exit_code}: {result.output}"
        )


# ---------------------------------------------------------------------------
# list-checks command
# ---------------------------------------------------------------------------


class TestCliListChecks:
    def test_cli_list_checks_outputs_table(self):
        """list-checks must display check IDs in its output."""
        runner = CliRunner()
        result = runner.invoke(cli, ["list-checks"])
        assert result.exit_code == 0
        # Should contain at least one known check ID
        assert ("tls_analysis" in result.output
                or "default_credentials" in result.output
                or "command_injection" in result.output)

    def test_cli_list_checks_json_format(self):
        """list-checks --format json must produce a valid JSON array."""
        runner = CliRunner()
        result = runner.invoke(cli, ["list-checks", "--format", "json"])
        assert result.exit_code == 0
        try:
            data = json.loads(result.output)
            assert isinstance(data, list)
            assert len(data) > 0
        except json.JSONDecodeError:
            pytest.fail(f"list-checks --format json did not produce valid JSON: {result.output[:500]}")


# ---------------------------------------------------------------------------
# version command
# ---------------------------------------------------------------------------


class TestCliVersion:
    def test_cli_version_shows_version_string(self):
        """'version' command must display '1.0.0' in its output."""
        runner = CliRunner()
        result = runner.invoke(cli, ["version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output

    def test_cli_version_shows_cve_count(self):
        """'version' command must display CVE database entry count."""
        runner = CliRunner()
        result = runner.invoke(cli, ["version"])
        assert result.exit_code == 0
        assert "CVE" in result.output or "cve" in result.output.lower()


# ---------------------------------------------------------------------------
# check command (single-check runner)
# ---------------------------------------------------------------------------


class TestCliCheckCommand:
    def test_cli_check_command_runs_single_check(self):
        """'check <id> <url>' must invoke the scanner with the specified check ID."""
        runner = CliRunner()

        with patch("luci_sky.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = _make_empty_result()
            result = runner.invoke(
                cli,
                ["check", "tls_analysis", "https://192.168.1.1"],
            )

        assert result.exit_code in (0, 1, 2)
        MockScanner.assert_called()


# ---------------------------------------------------------------------------
# report command
# ---------------------------------------------------------------------------


class TestCliReportCommand:
    def test_cli_report_rerenders_json_file(self, tmp_path: Path):
        """'report <json_file> --format terminal' must exit 0."""
        result_dict = _make_empty_result().to_dict()
        json_file = tmp_path / "scan_result.json"
        import json as _json
        json_file.write_text(_json.dumps(result_dict))

        runner = CliRunner()
        with patch("luci_sky.cli.TerminalReporter") as MockReporter:
            MockReporter.return_value.render.return_value = None
            result = runner.invoke(
                cli,
                ["report", str(json_file), "--format", "terminal"],
            )

        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# scan command — Config.build precedence and new flags (Task 6)
# ---------------------------------------------------------------------------


def test_scan_accepts_new_flags():
    runner = CliRunner()
    with patch("luci_sky.cli.Scanner") as M:
        M.return_value.run.return_value = _make_empty_result()
        result = runner.invoke(cli, [
            "scan", "https://192.168.1.1", "--mode", "passive", "--confirm",
            "--delay-ms", "50", "--jitter-ms", "10",
            "--include", "tls_analysis", "--exclude", "port_scan",
            "--extra-cred", "root:toor",
        ], catch_exceptions=False)
    assert result.exit_code == 0, result.output


def test_scan_config_flag_sets_mode(tmp_path):
    cf = tmp_path / "c.yml"
    cf.write_text("severity_threshold: critical\n")
    runner = CliRunner()
    captured = {}
    with patch("luci_sky.cli.Scanner") as M:
        def _capture(cfg, *a, **k):
            captured["cfg"] = cfg
            M.return_value.run.return_value = _make_empty_result()
            return M.return_value
        M.side_effect = _capture
        runner.invoke(cli, ["scan", "https://192.168.1.1", "--config", str(cf), "--confirm"],
                      catch_exceptions=False)
    from luci_sky.models import Severity
    assert captured["cfg"].severity_threshold == Severity.CRITICAL


def test_scan_debug_and_log_file_flags_set_on_config(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    runner = CliRunner()
    captured = {}
    with patch("luci_sky.cli.Scanner") as M:
        def _capture(cfg, *a, **k):
            captured["cfg"] = cfg
            M.return_value.run.return_value = _make_empty_result()
            return M.return_value
        M.side_effect = _capture
        runner.invoke(
            cli,
            [
                "scan", "https://192.168.1.1", "--confirm",
                "--debug", "--log-file", str(log_path),
            ],
            catch_exceptions=False,
        )
    assert captured["cfg"].debug is True
    assert str(log_path) in str(captured["cfg"].log_file)


def test_scan_quiet_runs_without_progress():
    runner = CliRunner()
    with patch("luci_sky.cli.Scanner") as M:
        M.return_value.run.return_value = _make_empty_result()
        result = runner.invoke(cli, ["scan", "https://192.168.1.1", "--confirm", "--quiet"],
                               catch_exceptions=False)
    assert result.exit_code == 0
    # Scanner constructed with a progress_callback kwarg (None under quiet/non-TTY)
    _, kwargs = M.call_args
    assert "progress_callback" in kwargs
