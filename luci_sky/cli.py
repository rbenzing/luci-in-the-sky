"""
luci_sky.cli — Click-based command-line interface.

Entry point: luci-sky = luci_sky.cli:cli
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click

import luci_sky
from luci_sky.config import Config
from luci_sky.models import ScanMode
from luci_sky.reporters.terminal import TerminalReporter
from luci_sky.scanner import Scanner

_DISCLAIMER = (
    "WARNING: This tool is for authorized security testing only. "
    "Ensure you have explicit written permission to test the target. "
    "Unauthorized use is illegal and unethical."
)

_ACTIVE_CONFIRM_MSG = (
    "Active/Full scan mode will send potentially harmful payloads to the target. "
    "Proceed only if you have explicit written authorization."
)


@click.group()
def cli() -> None:
    """LuCI-RedTeam — OpenWrt / LuCI security assessment tool."""


def _make_progress_callback(quiet: bool):
    """Return (callback, finalizer). Callback is None when progress is suppressed."""
    import sys as _sys
    if quiet or not _sys.stdout.isatty():
        return None, (lambda: None)
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
    )
    progress.start()
    task_id = progress.add_task("Scanning", total=None)

    def _cb(event: dict) -> None:
        total = event.get("total")
        if total is not None:
            progress.update(task_id, total=total, completed=event.get("completed", 0))
        if event.get("status") == "started":
            progress.update(task_id, description=f"[{event.get('phase','')}] {event.get('check_id','')}")

    return _cb, progress.stop


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------


@cli.command("scan")
@click.argument("target_url")
@click.option("--mode", default=None,
              type=click.Choice(["passive", "active", "full"], case_sensitive=False),
              help="Scan mode (default: passive).")
@click.option("--format", "output_format", default=None,
              help="Output format: terminal, json, html, all.")
@click.option("--output", "-o", default=None, help="Output file path.")
@click.option("--username", default=None, envvar="LUCI_USERNAME", help="LuCI username.")
@click.option("--password", default=None, envvar="LUCI_PASSWORD", help="LuCI password.")
@click.option("--token", default=None, envvar="LUCI_SESSION_TOKEN", help="Session token.")
@click.option("--threads", default=None, type=int, help="Number of worker threads.")
@click.option("--timeout", default=None, type=float, help="Request timeout in seconds.")
@click.option("--severity", "severity_threshold", default=None,
              type=click.Choice(["critical", "high", "medium", "low", "info"],
                                case_sensitive=False),
              help="Minimum severity threshold to report.")
@click.option("--confirm", is_flag=True, default=False,
              help="Skip interactive confirmation for active/full scans.")
@click.option("--quiet", "-q", is_flag=True, default=False,
              help="Suppress disclaimer and progress output.")
@click.option("--no-color", is_flag=True, default=False, help="Disable ANSI color output.")
@click.option("--proxy", default=None, envvar="LUCI_PROXY", help="HTTP proxy URL.")
@click.option("--canary-domain", default=None, envvar="LUCI_CANARY_DOMAIN",
              help="Canary domain for out-of-band detection.")
@click.option("--no-verify-tls", "no_verify_tls", is_flag=True, default=False,
              help="Disable TLS certificate verification (use with self-signed certs).")
@click.option("--config", "config_path", default=None, type=click.Path(),
              help="Path to a YAML config file.")
@click.option("--delay-ms", "delay_ms", default=None, type=int, help="Per-request delay (ms).")
@click.option("--jitter-ms", "jitter_ms", default=None, type=int,
              help="Random jitter added to delay (ms).")
@click.option("--include", "include", multiple=True, help="Only run these check IDs (repeatable).")
@click.option("--exclude", "exclude", multiple=True, help="Skip these check IDs (repeatable).")
@click.option("--ca-bundle", "ca_bundle", default=None, type=click.Path(),
              help="CA bundle path for TLS verify.")
@click.option("--extra-cred", "extra_cred", multiple=True,
              help="Extra USER:PASS to try (repeatable).")
@click.option("-v", "--verbose", is_flag=True, default=False, help="Verbose (INFO) logging.")
@click.option("--debug", is_flag=True, default=False, help="Debug logging + full audit bodies.")
@click.option("--log-file", "log_file", default=None, type=click.Path(),
              help="Write a JSONL audit log of every request.")
def scan(
    target_url: str,
    mode: Optional[str],
    output_format: Optional[str],
    output: Optional[str],
    username: Optional[str],
    password: Optional[str],
    token: Optional[str],
    threads: Optional[int],
    timeout: Optional[float],
    severity_threshold: Optional[str],
    confirm: bool,
    quiet: bool,
    no_color: bool,
    proxy: Optional[str],
    canary_domain: Optional[str],
    no_verify_tls: bool,
    config_path: Optional[str],
    delay_ms: Optional[int],
    jitter_ms: Optional[int],
    include: tuple,
    exclude: tuple,
    ca_bundle: Optional[str],
    extra_cred: tuple,
    verbose: bool,
    debug: bool,
    log_file: Optional[str],
) -> None:
    """Run a security scan against TARGET_URL."""
    extra_credentials = []
    for pair in extra_cred:
        user, _, pw = pair.partition(":")
        extra_credentials.append((user, pw))

    overrides = {
        "target_url": target_url,
        "mode": mode,
        "threads": threads,
        "timeout": timeout,
        "format": output_format,
        "output_path": output,
        "username": username,
        "password": password,
        "session_token": token,
        "severity_threshold": severity_threshold,
        "proxy": proxy,
        "canary_domain": canary_domain,
        "delay_ms": delay_ms,
        "jitter_ms": jitter_ms,
        "include_checks": list(include) or None,
        "exclude_checks": list(exclude) or None,
        "ca_bundle": ca_bundle,
        "extra_credentials": extra_credentials or None,
    }
    cfg = Config.build(Path(config_path) if config_path else None, overrides)
    if no_color:
        cfg.no_color = True
    if quiet:
        cfg.quiet = True
    if no_verify_tls:
        cfg.verify_tls = False
    cfg.confirm = confirm

    import logging as _logging
    if debug:
        cfg.debug = True
        _logging.basicConfig(level=_logging.DEBUG)
    elif verbose:
        cfg.verbose = True
        _logging.basicConfig(level=_logging.INFO)
    if log_file:
        cfg.log_file = Path(log_file)

    scan_mode = cfg.mode

    # Show disclaimer
    if not cfg.quiet:
        click.echo(_DISCLAIMER)
        click.echo()

    # Confirmation gate for active/full modes
    if scan_mode in (ScanMode.ACTIVE, ScanMode.FULL) and not cfg.confirm:
        click.echo(_ACTIVE_CONFIRM_MSG)
        if not click.confirm("Do you wish to proceed?"):
            click.echo("Scan aborted.")
            sys.exit(0)

    # Run scan
    progress_cb, stop_progress = _make_progress_callback(cfg.quiet)
    scanner = Scanner(cfg, progress_callback=progress_cb)
    try:
        result = scanner.run()
    except RuntimeError as exc:
        stop_progress()
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)
    finally:
        stop_progress()

    # Render reports
    from luci_sky.reporters import get_reporters
    reporter_classes = get_reporters(cfg.format)
    for reporter_cls in reporter_classes:
        reporter = reporter_cls(cfg)
        reporter.render(result, output_path=cfg.output_path)

    # Exit 1 if findings at or above threshold
    threshold = cfg.severity_threshold
    qualifying = result.findings_above(threshold)
    if qualifying:
        sys.exit(1)


# ---------------------------------------------------------------------------
# list-checks command
# ---------------------------------------------------------------------------


@cli.command("list-checks")
@click.option("--format", "output_format", default="table", show_default=True,
              type=click.Choice(["table", "json"], case_sensitive=False),
              help="Output format.")
@click.option("--mode", default=None,
              type=click.Choice(["passive", "active", "full"], case_sensitive=False),
              help="Filter by minimum scan mode.")
def list_checks(output_format: str, mode: Optional[str]) -> None:
    """List all available security checks."""
    from luci_sky.checks import all_checks

    checks = all_checks()

    if mode:
        filter_mode = ScanMode(mode.lower())
        checks = [c for c in checks if filter_mode.allows(c.__class__.min_mode)]

    if output_format == "json":
        data = [
            {
                "id": c.__class__.id,
                "name": c.__class__.name,
                "category": c.__class__.category.value,
                "severity": c.__class__.severity.value,
                "min_mode": c.__class__.min_mode.value,
                "requires_auth": c.__class__.requires_auth,
                "description": c.__class__.description,
            }
            for c in checks
        ]
        click.echo(json.dumps(data, indent=2))
    else:
        # Table format
        click.echo(f"{'ID':<30} {'NAME':<40} {'SEVERITY':<12} {'MODE':<10} {'AUTH'}")
        click.echo("-" * 100)
        for c in checks:
            click.echo(
                f"{c.__class__.id:<30} "
                f"{c.__class__.name[:38]:<40} "
                f"{c.__class__.severity.value:<12} "
                f"{c.__class__.min_mode.value:<10} "
                f"{'yes' if c.__class__.requires_auth else 'no'}"
            )


# ---------------------------------------------------------------------------
# check command (run a single check)
# ---------------------------------------------------------------------------


@cli.command("check")
@click.argument("check_id")
@click.argument("target_url")
@click.option("--mode", default="active", show_default=True,
              type=click.Choice(["passive", "active", "full"], case_sensitive=False))
@click.option("--output", "-o", default=None, help="Output file path.")
@click.option("--format", "output_format", default="terminal", show_default=True)
@click.option("--confirm", is_flag=True, default=False)
@click.option("--no-color", is_flag=True, default=False)
@click.option("--config", "config_path", default=None, type=click.Path(),
              help="Path to a YAML config file.")
def check_command(
    check_id: str,
    target_url: str,
    mode: str,
    output: Optional[str],
    output_format: str,
    confirm: bool,
    no_color: bool,
    config_path: Optional[str],
) -> None:
    """Run a single check by CHECK_ID against TARGET_URL."""
    overrides = {
        "target_url": target_url,
        "mode": mode,
        "format": output_format,
        "output_path": output,
        "include_checks": [check_id],
    }
    cfg = Config.build(Path(config_path) if config_path else None, overrides)
    if no_color:
        cfg.no_color = True

    scanner = Scanner(cfg)
    try:
        result = scanner.run()
    except RuntimeError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)

    from luci_sky.reporters import get_reporters
    reporter_classes = get_reporters(output_format)
    for reporter_cls in reporter_classes:
        reporter = reporter_cls(cfg)
        reporter.render(result, output_path=cfg.output_path)

    if result.findings:
        sys.exit(1)


# ---------------------------------------------------------------------------
# report command (re-render an existing JSON result)
# ---------------------------------------------------------------------------


@cli.command("report")
@click.argument("json_file", type=click.Path(exists=True, readable=True))
@click.option("--format", "output_format", default="terminal", show_default=True,
              help="Output format: terminal, json, html, all.")
@click.option("--output", "-o", default=None, help="Output file path.")
@click.option("--no-color", is_flag=True, default=False)
def report(
    json_file: str,
    output_format: str,
    output: Optional[str],
    no_color: bool,
) -> None:
    """Re-render a previously saved JSON scan result."""
    import json as _json
    from luci_sky.models import ScanResult

    raw = Path(json_file).read_text(encoding="utf-8")
    data = _json.loads(raw)

    result = _build_result_from_dict(data)

    cfg = Config()
    cfg.output_path = Path(output) if output else None
    cfg.no_color = no_color
    cfg.format = output_format

    from luci_sky.reporters import get_reporters
    reporter_classes = get_reporters(output_format)

    # The test patches TerminalReporter directly at luci_sky.cli.TerminalReporter
    if output_format == "terminal":
        reporter = TerminalReporter(cfg)
        reporter.render(result, output_path=cfg.output_path)
    else:
        for reporter_cls in reporter_classes:
            reporter = reporter_cls(cfg)
            reporter.render(result, output_path=cfg.output_path)


def _build_result_from_dict(data: dict):
    """Best-effort reconstruction of ScanResult from a dict."""
    from datetime import datetime
    from luci_sky.models import (
        Category, Confidence, Finding, ScanMode, ScanResult, Severity, Target
    )

    raw_target = data.get("target", {})
    target = Target(
        url=raw_target.get("url", ""),
        host=raw_target.get("host", ""),
        port=raw_target.get("port", 80),
        scheme=raw_target.get("scheme", "http"),
        detected_version=raw_target.get("detected_version"),
        detected_luci_version=raw_target.get("detected_luci_version"),
        open_ports=raw_target.get("open_ports", []),
        accessible_paths=raw_target.get("accessible_paths", []),
        is_authenticated=raw_target.get("is_authenticated", False),
    )

    findings = []
    for f in data.get("findings", []):
        try:
            findings.append(Finding(
                id=f.get("id", ""),
                check_id=f.get("check_id", ""),
                title=f.get("title", ""),
                severity=Severity(f.get("severity", "info")),
                cvss_score=float(f.get("cvss_score", 0.0)),
                cvss_vector=f.get("cvss_vector", ""),
                category=Category(f.get("category", "configuration")),
                confidence=Confidence(f.get("confidence", "medium")),
                description=f.get("description", ""),
                evidence=f.get("evidence", ""),
                affected_url=f.get("affected_url", ""),
                remediation=f.get("remediation", ""),
                references=f.get("references", []),
                cve_ids=f.get("cve_ids", []),
                contributing_checks=f.get("contributing_checks", []),
                scan_mode=ScanMode(f.get("scan_mode", "passive")),
                timestamp=datetime.fromisoformat(f["timestamp"]) if f.get("timestamp") else datetime.utcnow(),
            ))
        except Exception:
            pass

    def _parse_dt(val):
        if not val:
            return datetime.utcnow()
        if isinstance(val, datetime):
            return val
        try:
            return datetime.fromisoformat(str(val))
        except Exception:
            return datetime.utcnow()

    return ScanResult(
        target=target,
        findings=findings,
        scan_mode=ScanMode(data.get("scan_mode", "passive")),
        tool_version=data.get("tool_version", "1.0.0"),
        started_at=_parse_dt(data.get("started_at")),
        finished_at=_parse_dt(data.get("finished_at")),
        checks_run=data.get("checks_run", 0),
        checks_failed=data.get("checks_failed", 0),
    )


# ---------------------------------------------------------------------------
# version command
# ---------------------------------------------------------------------------


@cli.command("version")
def version() -> None:
    """Display version and CVE database information."""
    from luci_sky.cve.database import CVEDatabase
    db = CVEDatabase()
    cve_count = len(db._entries)
    click.echo(f"LuCI-RedTeam version {luci_sky.__version__}")
    click.echo(f"CVE database: {cve_count} entries loaded")


# ---------------------------------------------------------------------------
# update-cve command
# ---------------------------------------------------------------------------


@cli.command("update-cve")
@click.option("--url", default=None, help="URL to fetch the CVE database from.")
@click.option("--from-file", "from_file", default=None, type=click.Path(exists=True),
              help="Local YAML file to install instead of fetching.")
@click.option("--force", is_flag=True, default=False, help="Overwrite without prompting.")
def update_cve(url, from_file, force):
    """Update the local CVE database."""
    from luci_sky.cve.update import update_cve_db
    from luci_sky.cve.database import CVEDatabase
    try:
        dest = update_cve_db(url=url, from_file=Path(from_file) if from_file else None, force=force)
    except Exception as exc:
        click.echo(f"Update failed: {exc}", err=True)
        sys.exit(2)
    CVEDatabase.reset()
    db = CVEDatabase()
    click.echo(f"CVE database updated: {dest}")
    click.echo(f"Version: {db.db_version}  Updated: {db.updated}  Entries: {len(db._entries)}")
