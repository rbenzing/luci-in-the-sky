# Scanner Enhancements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add six enhancements to the `luci-in-the-sky` scanner — phased orchestration, config wiring, engagement audit log, live progress UI, CVE freshness/update, and finding dedup + interactive HTML report — with no breaking changes to existing CLI usage.

**Architecture:** Foundations first (shared sanitizer, `Finding.contributing_checks`, `Phase` enum, config precedence), then features that build on them. Scan checks are grouped into ordered phases (RECON → ANALYSIS → EXPLOIT) so recon output is available to later checks; the CLI routes all config through `Config.load()` with a CLI-override overlay; an `AuditLogger` records every HTTP call as JSONL; the existing unused `progress_callback` drives a `rich` progress display; the CVE DB gains freshness metadata + an `update-cve` command; findings are merged before reporting and rendered into a self-contained interactive HTML report.

**Tech Stack:** Python 3.10+, `click`, `requests`, `rich`, `jinja2`, `pyyaml`, `pytest` + `requests-mock`.

## Global Constraints

- Python floor: **3.10** (`requires-python = ">=3.10"`). Use `from __future__ import annotations`.
- No new third-party dependencies — only what is already in `pyproject.toml` (`requests`, `click`, `colorama`, `jinja2`, `pyyaml`, `packaging`, `rich`, `urllib3`).
- No breaking changes to existing CLI invocations or the JSON schema (additive only).
- Existing test suite must stay green; new code passes `ruff check` (config in `pyproject.toml`, line-length 100).
- New code uses timezone-aware `datetime.now(timezone.utc)`; do not introduce new `datetime.utcnow()` calls.
- HTML report must be self-contained: no `http://` / `https://` asset references, no CDN scripts, no external fonts.
- Tests mock the network (`requests-mock` / `MagicMock`); never contact a live host.
- Preserve the scanner test seams: `_get_filtered_checks`, `_make_session_manager`, and module-level `Scanner`/`TerminalReporter`/`Console` patch points.

---

## File Structure

**New files**
- `luci_sky/sanitize.py` — shared secret-masking `sanitize()` used by checks + audit + dedup.
- `luci_sky/audit.py` — `AuditLogger` thread-safe JSONL request/response recorder.
- `luci_sky/dedup.py` — `merge_findings()` duplicate collapse.
- `luci_sky/cve/storage.py` — user-data-dir resolution for the CVE DB.
- `luci_sky/cve/update.py` — `update_cve_db()` fetch/copy/validate/write.
- Test modules mirroring the above under `tests/`.

**Modified files**
- `luci_sky/models.py` — add `Phase` enum + `Finding.contributing_checks`.
- `luci_sky/checks/base.py` — `Check.phase` default via metaclass; `_sanitize` delegates to `sanitize`.
- `luci_sky/checks/*.py` — assign `phase` per check.
- `luci_sky/config.py` — new fields, `_apply_dict` coercions, `Config.build()`.
- `luci_sky/cli.py` — `--config` + exposed flags + audit/progress flags; route through `Config.build`; enrich `version`; add `update-cve`.
- `luci_sky/scanner.py` — phased execution, audit + progress wiring, dedup call.
- `luci_sky/session/http.py` — `AuditLogger` hook, `ca_bundle` verify.
- `luci_sky/cve/database.py` — metadata, user-dir precedence, staleness, `reset()`.
- `luci_sky/cve/data/luci_cves.yml` — top-level metadata block.
- `luci_sky/reporters/templates/report.html` + `luci_sky/reporters/html_reporter.py` — interactive self-contained report.

---

## Task 1: Shared sanitizer module

**Files:**
- Create: `luci_sky/sanitize.py`
- Modify: `luci_sky/checks/base.py` (the `_sanitize` staticmethod, ~lines 95–127)
- Test: `tests/test_sanitize.py`

**Interfaces:**
- Produces: `luci_sky.sanitize.sanitize(text: str, max_len: int = 2000) -> str`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_sanitize.py
from luci_sky.sanitize import sanitize


def test_sanitize_masks_sysauth_cookie():
    out = sanitize("Cookie: sysauth=ABCDEFGH1234567890secret")
    assert "ABCDEFGH***" in out
    assert "1234567890secret" not in out


def test_sanitize_masks_password_field():
    out = sanitize("luci_username=root&luci_password=hunter2")
    assert "luci_password=***" in out
    assert "hunter2" not in out


def test_sanitize_masks_authorization_header():
    out = sanitize("Authorization: Bearer sometoken")
    assert "Authorization: Bearer ***" in out
    assert "sometoken" not in out


def test_sanitize_truncates_to_max_len():
    assert len(sanitize("x" * 5000, max_len=100)) == 100
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_sanitize.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'luci_sky.sanitize'`

- [ ] **Step 3: Create the module**

```python
# luci_sky/sanitize.py
"""luci_sky.sanitize — shared secret-masking for evidence and audit logs."""
from __future__ import annotations

import re

_SYSAUTH_RE = re.compile(r"(sysauth(?:_\w+)?=)([A-Za-z0-9]{8})([A-Za-z0-9]+)")
_PASSWORD_RE = re.compile(r"(?i)((?:luci_)?password=)[^\s&\"']+")
_AUTH_RE = re.compile(r"(Authorization:\s*\w+\s+)\S+", re.IGNORECASE)


def sanitize(text: str, max_len: int = 2000) -> str:
    """Mask sysauth cookies, password fields, and Authorization tokens, then truncate."""
    text = _SYSAUTH_RE.sub(r"\1\2***", text)
    text = _PASSWORD_RE.sub(r"\1***", text)
    text = _AUTH_RE.sub(r"\1***", text)
    return text[:max_len]
```

- [ ] **Step 4: Delegate `Check._sanitize` to the shared function**

In `luci_sky/checks/base.py`, add near the top imports:

```python
from luci_sky.sanitize import sanitize as _shared_sanitize
```

Replace the body of the `_sanitize` staticmethod (keep the signature so all callers work) with:

```python
    @staticmethod
    def _sanitize(text: str, max_len: int = 2000) -> str:
        """Delegate to the shared sanitizer (kept as a method for existing callers)."""
        return _shared_sanitize(text, max_len=max_len)
```

Delete the now-unused `import re` in `base.py` only if no other code there uses it (search the file first; leave it if used elsewhere).

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_sanitize.py tests/test_check_base.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add luci_sky/sanitize.py luci_sky/checks/base.py tests/test_sanitize.py
git commit -m "refactor: extract shared sanitize() from Check._sanitize"
```

---

## Task 2: `Finding.contributing_checks` field

**Files:**
- Modify: `luci_sky/models.py` (`Finding` dataclass + `to_dict`)
- Modify: `luci_sky/cli.py` (`_build_result_from_dict`, ~lines 305–327)
- Test: `tests/test_models.py`

**Interfaces:**
- Produces: `Finding.contributing_checks: List[str]` (default `[]`), serialized in `to_dict()` and reconstructed in `_build_result_from_dict`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_models.py  (append)
from luci_sky.models import Finding, Severity, Category, Confidence, ScanMode


def _minimal_finding(**kw):
    base = dict(
        id="LUCI-X-001", check_id="c", title="t", severity=Severity.LOW,
        cvss_score=1.0, cvss_vector="v", category=Category.CONFIGURATION,
        confidence=Confidence.LOW, description="d", evidence="e",
        affected_url="u", remediation="r",
    )
    base.update(kw)
    return Finding(**base)


def test_finding_contributing_checks_defaults_empty():
    assert _minimal_finding().contributing_checks == []


def test_finding_to_dict_includes_contributing_checks():
    f = _minimal_finding(contributing_checks=["a", "b"])
    assert f.to_dict()["contributing_checks"] == ["a", "b"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_models.py -k contributing -v`
Expected: FAIL (`TypeError: __init__() got an unexpected keyword argument 'contributing_checks'`)

- [ ] **Step 3: Add the field and serialization**

In `luci_sky/models.py` inside `@dataclass class Finding`, add after `cve_ids`:

```python
    contributing_checks: List[str] = field(default_factory=list)
```

In `Finding.to_dict()`, add before the `"scan_mode"` entry:

```python
            "contributing_checks": list(self.contributing_checks),
```

- [ ] **Step 4: Reconstruct it in the CLI report loader**

In `luci_sky/cli.py`, inside `_build_result_from_dict` where each `Finding(...)` is built, add:

```python
                contributing_checks=f.get("contributing_checks", []),
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_models.py tests/test_cli.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add luci_sky/models.py luci_sky/cli.py tests/test_models.py
git commit -m "feat: add Finding.contributing_checks (additive, backward-compatible)"
```

---

## Task 3: `Phase` enum + `Check.phase` default

**Files:**
- Modify: `luci_sky/models.py` (new `Phase`)
- Modify: `luci_sky/checks/base.py` (`_CheckMeta.__prepare__`, `Check` ClassVar)
- Test: `tests/test_check_base.py`

**Interfaces:**
- Produces: `luci_sky.models.Phase` (`IntEnum`: `RECON=0`, `ANALYSIS=1`, `EXPLOIT=2`) and `Check.phase: ClassVar[Phase]` defaulting to `Phase.ANALYSIS`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_check_base.py  (append)
from luci_sky.models import Category, Phase
from luci_sky.checks.base import Check


def test_phase_ordering():
    assert Phase.RECON < Phase.ANALYSIS < Phase.EXPLOIT


def test_check_phase_defaults_to_analysis():
    class Dummy(Check):
        id = "dummy_phase_check"
        name = "Dummy"
        category = Category.CONFIGURATION
        description = "d"
        cve_ids = []

        def run(self, target, session, config):
            return []

    assert Dummy.phase == Phase.ANALYSIS
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_check_base.py -k phase -v`
Expected: FAIL (`ImportError: cannot import name 'Phase'`)

- [ ] **Step 3: Add the `Phase` enum**

In `luci_sky/models.py`, add after the `ScanMode` class:

```python
class Phase(IntEnum):
    """Scan phase ordering: recon runs before analysis before exploitation."""

    RECON = 0
    ANALYSIS = 1
    EXPLOIT = 2
```

Add `IntEnum` to the existing enum import line:

```python
from enum import Enum, IntEnum
```

- [ ] **Step 4: Give `Check` a default `phase`**

In `luci_sky/checks/base.py`, import `Phase`:

```python
from luci_sky.models import Category, Confidence, Finding, Phase, ScanMode, Severity, Target
```

In `_CheckMeta.__prepare__`, add to the injected namespace defaults:

```python
        ns["phase"] = Phase.ANALYSIS
```

In the `Check` class body, add to the ClassVar declarations:

```python
    phase: ClassVar[Phase]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_check_base.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add luci_sky/models.py luci_sky/checks/base.py tests/test_check_base.py
git commit -m "feat: add Phase enum and Check.phase default"
```

---

## Task 4: Assign phases to all checks

**Files:**
- Modify: `luci_sky/checks/info_disclosure.py`, `network.py`, `tls.py`, `cve.py`, `auth.py`, `injection.py`, `xss.py`, `csrf.py`, `session.py`
- Test: `tests/checks/test_phase_assignment.py`

**Interfaces:**
- Consumes: `Phase` from Task 3.
- Produces: every registered check has an explicit `phase`. RECON = `version_detection`, `port_scan`, `path_enumeration`, `package_enumeration`. EXPLOIT = `command_injection`, `time_based_injection`, `path_traversal`, `default_credentials`, `auth_bypass`, `rate_limiting`, `rate_limit_stress`, `rpc_exploitation`, `dns_rebinding`, `upnp_audit`, `upnp_port_mapping`, plus any XSS/CSRF/session checks that send payloads. All others default to ANALYSIS.

- [ ] **Step 1: Write the failing test**

```python
# tests/checks/test_phase_assignment.py
import luci_sky.checks  # triggers registration
from luci_sky.checks import get_check
from luci_sky.models import Phase

RECON = ["version_detection", "port_scan", "path_enumeration", "package_enumeration"]
EXPLOIT = [
    "command_injection", "time_based_injection", "path_traversal",
    "default_credentials", "auth_bypass", "rate_limiting", "rate_limit_stress",
    "rpc_exploitation", "dns_rebinding", "upnp_audit", "upnp_port_mapping",
]
ANALYSIS = ["cve_correlation", "service_security", "tls_analysis", "security_headers"]


def test_recon_checks_are_recon():
    for cid in RECON:
        assert get_check(cid).phase == Phase.RECON, cid


def test_exploit_checks_are_exploit():
    for cid in EXPLOIT:
        assert get_check(cid).phase == Phase.EXPLOIT, cid


def test_analysis_checks_are_analysis():
    for cid in ANALYSIS:
        assert get_check(cid).phase == Phase.ANALYSIS, cid
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/checks/test_phase_assignment.py -v`
Expected: FAIL (recon/exploit checks currently report `Phase.ANALYSIS`)

- [ ] **Step 3: Assign phases**

In each check module, add `from luci_sky.models import Phase` to the existing models import line (append `Phase`), then add a `phase = Phase.<X>` attribute to each class body next to its other metadata.

- `info_disclosure.py`: `VersionDetection`, `PathEnumeration`, `PackageEnumeration` → `phase = Phase.RECON`. `BackupExposure`, `SecurityHeaders` → leave default (ANALYSIS) — add `phase = Phase.ANALYSIS` explicitly for clarity.
- `network.py`: `PortScan` → `Phase.RECON`. `RPCExploitation`, `DNSRebinding`, `UPnPAudit`, `UPnPPortMapping` → `Phase.EXPLOIT`. `ServiceSecurity`, `CORSMisconfiguration`, `WANExposure`, `FirewallAudit`, `WirelessAudit` → `Phase.ANALYSIS`.
- `injection.py`: `CommandInjection`, `PathTraversal`, `TimeBasedInjection` → `Phase.EXPLOIT`.
- `auth.py`: `DefaultCredentials`, `AuthBypass`, `RateLimiting`, `RateLimitStress` → `Phase.EXPLOIT`.
- `tls.py`: `TLSAnalysis` → `Phase.ANALYSIS`.
- `cve.py`: `CVECorrelation` → `Phase.ANALYSIS`.
- `xss.py`, `csrf.py`, `session.py`: any check that submits a crafted payload/form → `Phase.EXPLOIT`; purely passive header/cookie inspection → `Phase.ANALYSIS`. (Open each file and classify by whether `run()` sends attack input.)

Example edit (in `injection.py`, `CommandInjection`):

```python
    category = Category.INJECTION
    severity = Severity.CRITICAL
    min_mode = ScanMode.ACTIVE
    phase = Phase.EXPLOIT
    requires_auth = False
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/checks/test_phase_assignment.py -v`
Expected: PASS

- [ ] **Step 5: Run the full check suite for regressions**

Run: `pytest tests/checks -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add luci_sky/checks tests/checks/test_phase_assignment.py
git commit -m "feat: assign scan phases to all checks"
```

---

## Task 5: Config fields + coercions + `Config.build` precedence

**Files:**
- Modify: `luci_sky/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Produces: new `Config` fields `include_checks: List[str]`, `exclude_checks: List[str]`, `log_file: Optional[Path]`, `verbose: bool`, `debug: bool` (all with safe defaults); `Config.build(config_path: Optional[Path], overrides: dict) -> Config` applying **only non-None** overrides on top of `Config.load()`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config.py  (append)
from luci_sky.config import Config
from luci_sky.models import ScanMode, Severity


def test_config_has_new_fields():
    cfg = Config()
    assert cfg.include_checks == []
    assert cfg.exclude_checks == []
    assert cfg.log_file is None
    assert cfg.verbose is False
    assert cfg.debug is False


def test_build_cli_overrides_win_over_yaml(tmp_path):
    cf = tmp_path / "c.yml"
    cf.write_text("mode: active\nthreads: 3\n")
    cfg = Config.build(cf, {"threads": 9, "mode": None})
    assert cfg.threads == 9          # CLI wins
    assert cfg.mode == ScanMode.ACTIVE  # None override ignored -> YAML value kept


def test_build_none_overrides_are_ignored(tmp_path):
    cfg = Config.build(None, {"severity_threshold": None})
    assert cfg.severity_threshold == Severity.INFO  # default preserved


def test_build_coerces_string_overrides():
    cfg = Config.build(None, {"mode": "full", "severity_threshold": "high"})
    assert cfg.mode == ScanMode.FULL
    assert cfg.severity_threshold == Severity.HIGH
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_config.py -k "new_fields or build" -v`
Expected: FAIL (`AttributeError: 'Config' object has no attribute 'include_checks'` / `Config has no attribute 'build'`)

- [ ] **Step 3: Add fields**

In `luci_sky/config.py` `@dataclass class Config`, add:

```python
    # Check selection
    include_checks: List[str] = field(default_factory=list)
    exclude_checks: List[str] = field(default_factory=list)

    # Logging / diagnostics
    log_file: Optional[Path] = None
    verbose: bool = False
    debug: bool = False
```

- [ ] **Step 4: Extend `_apply_dict` path coercion and add `Config.build`**

In `_apply_dict`, change the path-coercion branch to include `log_file`:

```python
            elif key in ("output_path", "ca_bundle", "log_file") and value is not None:
                value = _PosixStrPath(value)
```

Add a classmethod on `Config`:

```python
    @classmethod
    def build(cls, config_path: Optional[Path], overrides: dict) -> "Config":
        """Load config (YAML + env), then overlay non-None CLI overrides (CLI wins)."""
        cfg = cls.load(config_path)
        filtered = {k: v for k, v in overrides.items() if v is not None}
        cls._apply_dict(cfg, filtered)
        return cfg
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_config.py -v`
Expected: PASS (existing + new)

- [ ] **Step 6: Commit**

```bash
git add luci_sky/config.py tests/test_config.py
git commit -m "feat: config fields + Config.build precedence overlay"
```

---

## Task 6: CLI `scan` routes through `Config.build` + exposed flags

**Files:**
- Modify: `luci_sky/cli.py` (`scan` command)
- Modify: `luci_sky/session/http.py` (`ca_bundle` verify)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `Config.build` (Task 5).
- Produces: `scan` gains `--config`, `--delay-ms`, `--jitter-ms`, `--include` (multiple), `--exclude` (multiple), `--ca-bundle`, `--extra-cred` (multiple, `USER:PASS`); config precedence honored; `ca_bundle` reaches the session `verify`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli.py  (append — reuses the module-level _make_empty_result helper)
from unittest.mock import patch
from click.testing import CliRunner
from luci_sky.cli import cli


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py -k "new_flags or config_flag" -v`
Expected: FAIL (`No such option: --delay-ms` / `--config`)

- [ ] **Step 3: Add options and route through `Config.build`**

In `luci_sky/cli.py`, add these options to the `scan` command (after `--no-verify-tls`):

```python
@click.option("--config", "config_path", default=None, type=click.Path(),
              help="Path to a YAML config file.")
@click.option("--delay-ms", "delay_ms", default=None, type=int, help="Per-request delay (ms).")
@click.option("--jitter-ms", "jitter_ms", default=None, type=int, help="Random jitter added to delay (ms).")
@click.option("--include", "include", multiple=True, help="Only run these check IDs (repeatable).")
@click.option("--exclude", "exclude", multiple=True, help="Skip these check IDs (repeatable).")
@click.option("--ca-bundle", "ca_bundle", default=None, type=click.Path(), help="CA bundle path for TLS verify.")
@click.option("--extra-cred", "extra_cred", multiple=True, help="Extra USER:PASS to try (repeatable).")
```

Add the matching parameters to the `scan(...)` signature: `config_path, delay_ms, jitter_ms, include, exclude, ca_bundle, extra_cred`.

Replace the config-building block (the `cfg = Config()` section) with:

```python
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
    scan_mode = cfg.mode
```

Move the disclaimer + confirmation gate to **after** this block and use `cfg`:

```python
    if not cfg.quiet:
        click.echo(_DISCLAIMER)
        click.echo()
    if scan_mode in (ScanMode.ACTIVE, ScanMode.FULL) and not cfg.confirm:
        click.echo(_ACTIVE_CONFIRM_MSG)
        if not click.confirm("Do you wish to proceed?"):
            click.echo("Scan aborted.")
            sys.exit(0)
```

Keep `mode` as a `click.Choice` option but change its default so config can win when omitted:

```python
@click.option("--mode", default=None,
              type=click.Choice(["passive", "active", "full"], case_sensitive=False),
              help="Scan mode (default: passive).")
```

Do the same (`default=None`) for `--format` (`output_format`), `--threads`, `--timeout`, and `--severity`. Because `Config.build` ignores `None`, the dataclass defaults (`PASSIVE`, `terminal`, `5`, `10.0`, `INFO`) apply when the flag is omitted — preserving today's behavior.

- [ ] **Step 4: Wire `ca_bundle` into the session verify**

In `luci_sky/session/http.py` `_request`, replace the `verify` default line with logic that prefers the CA bundle:

```python
        if self._config.verify_tls and self._config.ca_bundle:
            kwargs.setdefault("verify", str(self._config.ca_bundle))
        else:
            kwargs.setdefault("verify", self._config.verify_tls)
```

- [ ] **Step 4b: Add `--config` to the `check` command**

The spec requires `--config` on both `scan` and `check`. In `luci_sky/cli.py`, add to the `check` command options:

```python
@click.option("--config", "config_path", default=None, type=click.Path(),
              help="Path to a YAML config file.")
```

Add `config_path` to the `check_command(...)` signature, then replace its `cfg = Config()` block with:

```python
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
```

`--mode` for `check` keeps its current `default="active"` (a single explicit check is intentionally active), so `mode` is always a real string here and overrides any config value.

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_cli.py tests/test_http_session.py -v`
Expected: PASS (existing scan/exit-code/disclaimer/confirm tests + new)

- [ ] **Step 6: Commit**

```bash
git add luci_sky/cli.py luci_sky/session/http.py tests/test_cli.py
git commit -m "feat: scan --config and exposed config flags with precedence"
```

---

## Task 7: Phased scan execution

**Files:**
- Modify: `luci_sky/scanner.py` (`run`)
- Test: `tests/test_scanner.py`

**Interfaces:**
- Consumes: `Check.phase` (Task 4).
- Produces: `Scanner.run` executes checks grouped by ascending `Phase`, parallel within a phase; RECON completes before ANALYSIS/EXPLOIT read `target`. Return type `ScanResult` unchanged.

**Notes:** Phase serialization is the correctness fix. Within RECON the concurrent checks write **disjoint** `Target` attributes (`detected_version`, `open_ports`, `accessible_paths`), so no extra `Target` lock is added — this is a deliberate simplification of the spec's belt-and-suspenders lock, avoiding intrusive edits to every check and keeping `Target` serializable.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_scanner.py  (append)
from unittest.mock import patch
from luci_sky.config import Config
from luci_sky.models import Phase
from luci_sky.scanner import Scanner


class _ReconSetsVersion:
    id = "recon_probe"
    phase = Phase.RECON

    def run(self, target, session, config):
        target.detected_version = "21.02.3"
        return []


class _AnalysisReadsVersion:
    id = "analysis_reader"
    phase = Phase.ANALYSIS
    seen = {}

    def run(self, target, session, config):
        type(self).seen["version"] = target.detected_version
        return []


def test_recon_runs_before_analysis():
    recon = _ReconSetsVersion()
    analysis = _AnalysisReadsVersion()
    type(analysis).seen = {}
    cfg = Config()
    cfg.target_url = "https://192.168.1.1"

    with patch("luci_sky.scanner._get_filtered_checks", return_value=[analysis, recon]), \
         patch("luci_sky.scanner._make_session_manager") as MS:
        MS.return_value.clone.return_value = MS.return_value
        MS.return_value.authenticate.return_value = False
        Scanner(cfg).run()

    assert _AnalysisReadsVersion.seen["version"] == "21.02.3"
```

(`recon` is returned second in the list to prove ordering comes from phases, not list order.)

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_scanner.py -k recon_runs_before_analysis -v`
Expected: FAIL (analysis sees `None` because checks currently run in one unordered pool)

- [ ] **Step 3: Group execution by phase**

In `luci_sky/scanner.py`, add imports:

```python
from collections import defaultdict
from luci_sky.models import Phase
```

Change `run_check` to accept progress context and replace the single executor block. The `run_check` inner function signature becomes:

```python
        def run_check(check) -> List[Finding]:
            check_id = check.__class__.id
            phase = getattr(check.__class__, "phase", Phase.ANALYSIS)
            try:
                self._emit_progress({"status": "started", "check_id": check_id,
                                     "phase": int(phase)})
                thread_session = session.clone()
                result = check.run(target, thread_session, config)
                with lock:
                    completed[0] += 1
                self._emit_progress({"status": "done", "check_id": check_id,
                                     "phase": int(phase), "findings": len(result or []),
                                     "completed": completed[0], "total": checks_run})
                return result or []
            except Exception as exc:
                logger.warning("Check %s failed: %s", check_id, exc)
                with lock:
                    checks_failed_counter[0] += 1
                    completed[0] += 1
                self._emit_progress({"status": "error", "check_id": check_id,
                                     "phase": int(phase), "error": str(exc),
                                     "completed": completed[0], "total": checks_run})
                return []
```

Add `completed = [0]` next to `checks_failed_counter = [0]`. Replace the executor loop with a per-phase loop:

```python
        by_phase = defaultdict(list)
        for c in checks:
            by_phase[getattr(c.__class__, "phase", Phase.ANALYSIS)].append(c)

        max_workers = max(1, config.threads)
        for phase in sorted(by_phase.keys()):
            phase_checks = by_phase[phase]
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {ex.submit(run_check, c): c for c in phase_checks}
                for fut in as_completed(futures):
                    findings.extend(fut.result())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_scanner.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add luci_sky/scanner.py tests/test_scanner.py
git commit -m "feat: phased scan execution (recon before analysis/exploit)"
```

---

## Task 8: `AuditLogger` module

**Files:**
- Create: `luci_sky/audit.py`
- Test: `tests/test_audit.py`

**Interfaces:**
- Produces:
  - `AuditLogger(log_file: Optional[Path] = None, debug: bool = False)`
  - `.record(method: str, url: str, status: int, elapsed_ms: float, req_bytes: int, resp_bytes: int, snippet: str = "", req_body: str = "", resp_body: str = "") -> None` — writes one sanitized JSONL line (bodies only when `debug=True`); thread-safe; no-op when `log_file` is None.
  - `.close() -> None`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_audit.py
import json
from luci_sky.audit import AuditLogger


def test_record_writes_jsonl_line(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = AuditLogger(log_file=p)
    log.record("GET", "https://h/x", 200, 12.5, 0, 34, snippet="hello")
    log.close()
    lines = p.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["method"] == "GET" and rec["status"] == 200 and rec["snippet"] == "hello"


def test_record_sanitizes_snippet(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLogger(log_file=p)
    log.record("POST", "https://h/login", 200, 1.0, 0, 0,
               snippet="luci_password=hunter2")
    log.close()
    assert "hunter2" not in p.read_text(encoding="utf-8")


def test_bodies_only_in_debug(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLogger(log_file=p, debug=False)
    log.record("GET", "https://h", 200, 1.0, 0, 3, resp_body="abc")
    log.close()
    rec = json.loads(p.read_text(encoding="utf-8").splitlines()[0])
    assert "resp_body" not in rec


def test_none_log_file_is_noop():
    log = AuditLogger(log_file=None)
    log.record("GET", "https://h", 200, 1.0, 0, 0)  # must not raise
    log.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_audit.py -v`
Expected: FAIL (`ModuleNotFoundError: luci_sky.audit`)

- [ ] **Step 3: Implement the module**

```python
# luci_sky/audit.py
"""luci_sky.audit — thread-safe JSONL audit logger for HTTP calls."""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from luci_sky.sanitize import sanitize


class AuditLogger:
    """Append one sanitized JSONL record per HTTP call. No-op when log_file is None."""

    def __init__(self, log_file: Optional[Path] = None, debug: bool = False) -> None:
        self._debug = debug
        self._lock = threading.Lock()
        self._fh = None
        if log_file is not None:
            path = Path(log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(path, "a", encoding="utf-8")

    def record(self, method: str, url: str, status: int, elapsed_ms: float,
               req_bytes: int, resp_bytes: int, snippet: str = "",
               req_body: str = "", resp_body: str = "") -> None:
        if self._fh is None:
            return
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "url": url,
            "status": status,
            "elapsed_ms": round(elapsed_ms, 2),
            "req_bytes": req_bytes,
            "resp_bytes": resp_bytes,
            "snippet": sanitize(snippet, max_len=300),
        }
        if self._debug:
            rec["req_body"] = sanitize(req_body, max_len=4000)
            rec["resp_body"] = sanitize(resp_body, max_len=4000)
        line = json.dumps(rec, default=str)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                try:
                    self._fh.close()
                finally:
                    self._fh = None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_audit.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add luci_sky/audit.py tests/test_audit.py
git commit -m "feat: AuditLogger JSONL request recorder"
```

---

## Task 9: Wire `AuditLogger` into the session + CLI audit flags

**Files:**
- Modify: `luci_sky/session/http.py` (`SessionManager`)
- Modify: `luci_sky/scanner.py` (`_make_session_manager`, `run`)
- Modify: `luci_sky/cli.py` (`scan`: `-v/--verbose`, `--debug`, `--log-file`)
- Test: `tests/test_http_session.py`, `tests/test_cli.py`

**Interfaces:**
- Consumes: `AuditLogger` (Task 8).
- Produces: `SessionManager(config, audit: Optional[AuditLogger] = None)`; `.clone()` shares the same `audit`; `_request` records each call. `scan` builds an `AuditLogger` from `cfg.log_file`/`cfg.debug` and passes it in.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_http_session.py  (append)
import json
import requests_mock
from pathlib import Path
from luci_sky.audit import AuditLogger
from luci_sky.config import Config
from luci_sky.session.http import SessionManager


def test_session_records_audit(tmp_path):
    cfg = Config()
    cfg.verify_tls = False
    log = AuditLogger(log_file=tmp_path / "a.jsonl")
    sm = SessionManager(cfg, audit=log)
    with requests_mock.Mocker() as m:
        m.get("https://h/x", text="body-here", status_code=200)
        sm.get("https://h/x")
    log.close()
    rec = json.loads((tmp_path / "a.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert rec["method"] == "GET" and rec["status"] == 200


def test_clone_shares_audit(tmp_path):
    cfg = Config()
    log = AuditLogger(log_file=tmp_path / "a.jsonl")
    sm = SessionManager(cfg, audit=log)
    assert sm.clone()._audit is log
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_http_session.py -k "audit" -v`
Expected: FAIL (`SessionManager.__init__() got an unexpected keyword argument 'audit'`)

- [ ] **Step 3: Add audit support to `SessionManager`**

In `luci_sky/session/http.py`:

- `__init__` signature → `def __init__(self, config: Config, audit: "Optional[AuditLogger]" = None) -> None:` and store `self._audit = audit`. Add `from typing import Optional` if not present and a `TYPE_CHECKING` import:

```python
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from luci_sky.audit import AuditLogger
```

- In `_request`, wrap the call to time it and record:

```python
    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        self._throttle()
        kwargs.setdefault("timeout", self._config.timeout)
        if self._config.verify_tls and self._config.ca_bundle:
            kwargs.setdefault("verify", str(self._config.ca_bundle))
        else:
            kwargs.setdefault("verify", self._config.verify_tls)
        logger.debug("%s %s", method, url)
        start = time.monotonic()
        resp = self._session.request(method, url, **kwargs)
        if self._audit is not None:
            elapsed_ms = (time.monotonic() - start) * 1000.0
            body = resp.text or ""
            self._audit.record(
                method=method, url=url, status=resp.status_code,
                elapsed_ms=elapsed_ms, req_bytes=len(kwargs.get("data", "") or ""),
                resp_bytes=len(resp.content or b""), snippet=body[:300],
                req_body=str(kwargs.get("data", "") or kwargs.get("json", "") or ""),
                resp_body=body,
            )
        return resp
```

(Remove the duplicated `verify` `setdefault` line that Task 6 added if it now conflicts — the block above is the single source of truth.)

- In `clone`, pass audit through:

```python
        cloned = SessionManager(self._config, audit=self._audit)
```

- [ ] **Step 4: Thread the audit logger through the scanner**

In `luci_sky/scanner.py`:

- `_make_session_manager(config, audit=None)` → construct `cls(config, audit=audit)`.
- In `run()`, before `session = _make_session_manager(...)`:

```python
        from luci_sky.audit import AuditLogger
        audit = AuditLogger(log_file=getattr(config, "log_file", None),
                            debug=getattr(config, "debug", False))
        session = _make_session_manager(config, audit=audit)
```

- After the scan completes (near `session.close()`), add `audit.close()`.

- [ ] **Step 5: Add CLI flags**

In `luci_sky/cli.py` `scan`, add:

```python
@click.option("-v", "--verbose", is_flag=True, default=False, help="Verbose (INFO) logging.")
@click.option("--debug", is_flag=True, default=False, help="Debug logging + full audit bodies.")
@click.option("--log-file", "log_file", default=None, type=click.Path(),
              help="Write a JSONL audit log of every request.")
```

Add `verbose, debug, log_file` to the signature and to the post-build overlay:

```python
    import logging as _logging
    if debug:
        cfg.debug = True
        _logging.basicConfig(level=_logging.DEBUG)
    elif verbose:
        cfg.verbose = True
        _logging.basicConfig(level=_logging.INFO)
    if log_file:
        cfg.log_file = Path(log_file)
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_http_session.py tests/test_cli.py tests/test_scanner.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add luci_sky/session/http.py luci_sky/scanner.py luci_sky/cli.py tests/test_http_session.py
git commit -m "feat: engagement audit log wired through session + CLI flags"
```

---

## Task 10: Live progress UI

**Files:**
- Modify: `luci_sky/cli.py` (`scan`: build a `rich` progress callback)
- Test: `tests/test_scanner.py` (event shape), `tests/test_cli.py` (quiet path)

**Interfaces:**
- Consumes: progress events emitted in Task 7 (`status`, `check_id`, `phase`, `completed`, `total`).
- Produces: `scan` passes a `progress_callback` to `Scanner` unless `cfg.quiet` or stdout is not a TTY.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_scanner.py  (append)
from unittest.mock import patch
from luci_sky.config import Config
from luci_sky.models import Phase
from luci_sky.scanner import Scanner


def test_progress_events_include_totals():
    events = []

    class _C:
        id = "p_check"
        phase = Phase.RECON
        def run(self, target, session, config):
            return []

    cfg = Config()
    cfg.target_url = "https://192.168.1.1"
    with patch("luci_sky.scanner._get_filtered_checks", return_value=[_C()]), \
         patch("luci_sky.scanner._make_session_manager") as MS:
        MS.return_value.clone.return_value = MS.return_value
        MS.return_value.authenticate.return_value = False
        Scanner(cfg, progress_callback=events.append).run()

    done = [e for e in events if e["status"] == "done"]
    assert done and done[0]["total"] == 1 and done[0]["completed"] == 1
    assert "phase" in done[0]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_scanner.py -k progress_events_include_totals -v`
Expected: PASS if Task 7 shipped the fields; if FAIL, fix the emit in Task 7. (This test locks the event contract that the CLI depends on.)

- [ ] **Step 3: Build the CLI progress callback**

In `luci_sky/cli.py`, add a helper above `scan`:

```python
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
```

In `scan`, after `cfg` is finalized and before running:

```python
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
```

(Replace the existing `scanner = Scanner(cfg)` / try-run block with the above; keep the subsequent report rendering and exit-code logic unchanged.)

- [ ] **Step 4: Add the quiet-path CLI test**

```python
# tests/test_cli.py  (append — reuses module-level _make_empty_result)
from unittest.mock import patch
from click.testing import CliRunner
from luci_sky.cli import cli


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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_scanner.py tests/test_cli.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add luci_sky/cli.py tests/test_scanner.py tests/test_cli.py
git commit -m "feat: live rich progress UI wired to scanner events"
```

---

## Task 11: CVE storage, metadata loading, and staleness

**Files:**
- Create: `luci_sky/cve/storage.py`
- Modify: `luci_sky/cve/database.py`
- Modify: `luci_sky/cve/data/luci_cves.yml` (add metadata block)
- Test: `tests/test_cve_freshness.py`

**Interfaces:**
- Produces:
  - `luci_sky.cve.storage.user_db_path() -> Path` (respects `LUCI_DATA_DIR`; else `%LOCALAPPDATA%\luci-sky\luci_cves.yml` on Windows, `~/.local/share/luci-sky/luci_cves.yml` on POSIX).
  - `CVEDatabase` gains `db_version: Optional[int]`, `updated: Optional[str]`, `source: Optional[str]`, `age_days() -> Optional[int]`, `is_stale(max_age_days: int = 90) -> bool`, and classmethod `reset() -> None`.
  - Loader precedence: user-dir file → bundled file.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cve_freshness.py
import pytest
import yaml
from pathlib import Path
from luci_sky.cve import storage
from luci_sky.cve.database import CVEDatabase


@pytest.fixture(autouse=True)
def _reset_cve_singleton():
    """Keep the CVEDatabase singleton from leaking a tmp-dir load into other modules."""
    CVEDatabase.reset()
    yield
    CVEDatabase.reset()


_DB = """
version: 2
updated: "2000-01-01"
source: "https://example/luci_cves.yml"
cves:
  - id: CVE-0000-0001
    title: t
    description: d
    cvss_score: 9.0
    cvss_vector: v
    severity: critical
    detection_method: version
    component: c
    remediation: r
    affected_versions: []
"""


def _fresh_db(tmp_path, monkeypatch, text):
    monkeypatch.setenv("LUCI_DATA_DIR", str(tmp_path))
    (tmp_path / "luci_cves.yml").write_text(text, encoding="utf-8")
    CVEDatabase.reset()
    return CVEDatabase()


def test_user_dir_takes_precedence(tmp_path, monkeypatch):
    db = _fresh_db(tmp_path, monkeypatch, _DB)
    assert db.db_version == 2
    assert any(e.cve_id == "CVE-0000-0001" for e in db._entries)


def test_is_stale_past_threshold(tmp_path, monkeypatch):
    db = _fresh_db(tmp_path, monkeypatch, _DB)
    assert db.is_stale(max_age_days=90) is True


def test_user_db_path_respects_env(tmp_path, monkeypatch):
    monkeypatch.setenv("LUCI_DATA_DIR", str(tmp_path))
    assert storage.user_db_path() == tmp_path / "luci_cves.yml"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cve_freshness.py -v`
Expected: FAIL (`ModuleNotFoundError: luci_sky.cve.storage`)

- [ ] **Step 3: Create the storage helper**

```python
# luci_sky/cve/storage.py
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
```

- [ ] **Step 4: Add metadata + precedence + staleness to `CVEDatabase`**

In `luci_sky/cve/data/luci_cves.yml`, add at the very top (above `cves:`):

```yaml
version: 1
updated: "2026-07-06"
source: "https://raw.githubusercontent.com/rbenzing/luci-in-the-sky/main/luci_sky/cve/data/luci_cves.yml"
```

In `luci_sky/cve/database.py`:

- Add imports: `from datetime import date` and `from luci_sky.cve import storage`.
- In `__init__`, initialize metadata fields before `_load`:

```python
    def __init__(self) -> None:
        if not CVEDatabase._loaded:
            self._entries: List[CVEEntry] = []
            self.db_version: Optional[int] = None
            self.updated: Optional[str] = None
            self.source: Optional[str] = None
            self._load()
            CVEDatabase._loaded = True
```

- Add a path resolver and use it in `_load`:

```python
    @staticmethod
    def _resolve_db_path() -> Path:
        user = storage.user_db_path()
        return user if user.exists() else _DB_PATH
```

In `_load`, change `with open(_DB_PATH, ...)` to `with open(self._resolve_db_path(), ...)`, and after `data = yaml.safe_load(fh) or {}` capture metadata:

```python
            self.db_version = data.get("version")
            self.updated = data.get("updated")
            self.source = data.get("source")
```

- Add staleness helpers and reset:

```python
    def age_days(self) -> Optional[int]:
        if not self.updated:
            return None
        try:
            y, m, d = (int(x) for x in str(self.updated).split("-"))
            return (date.today() - date(y, m, d)).days
        except Exception:
            return None

    def is_stale(self, max_age_days: int = 90) -> bool:
        age = self.age_days()
        return age is not None and age > max_age_days

    @classmethod
    def reset(cls) -> None:
        cls._instance = None
        cls._loaded = False
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_cve_freshness.py tests/checks/test_cve_checks.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add luci_sky/cve/storage.py luci_sky/cve/database.py luci_sky/cve/data/luci_cves.yml tests/test_cve_freshness.py
git commit -m "feat: CVE DB metadata, user-dir precedence, staleness"
```

---

## Task 12: `update-cve` command

**Files:**
- Create: `luci_sky/cve/update.py`
- Modify: `luci_sky/cli.py` (register `update-cve`)
- Test: `tests/test_cve_update.py`

**Interfaces:**
- Produces: `luci_sky.cve.update.update_cve_db(url: Optional[str] = None, from_file: Optional[Path] = None, force: bool = False) -> Path` — validates the YAML parses and has a `cves` list, writes it to `storage.user_db_path()`, returns that path. Raises `ValueError` on malformed content.
- CLI: `luci-sky update-cve [--url URL] [--from-file PATH] [--force]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cve_update.py
import pytest
from pathlib import Path
from luci_sky.cve import storage
from luci_sky.cve.database import CVEDatabase
from luci_sky.cve.update import update_cve_db


@pytest.fixture(autouse=True)
def _reset_cve_singleton():
    CVEDatabase.reset()
    yield
    CVEDatabase.reset()


_GOOD = 'version: 3\nupdated: "2030-01-01"\ncves: []\n'
_BAD = "just a string, not a mapping"


def test_update_from_file_writes_user_db(tmp_path, monkeypatch):
    monkeypatch.setenv("LUCI_DATA_DIR", str(tmp_path))
    src = tmp_path / "src.yml"
    src.write_text(_GOOD, encoding="utf-8")
    out = update_cve_db(from_file=src)
    assert out == storage.user_db_path()
    assert out.read_text(encoding="utf-8").strip() == _GOOD.strip()


def test_update_rejects_malformed(tmp_path, monkeypatch):
    monkeypatch.setenv("LUCI_DATA_DIR", str(tmp_path))
    src = tmp_path / "bad.yml"
    src.write_text(_BAD, encoding="utf-8")
    with pytest.raises(ValueError):
        update_cve_db(from_file=src)
    assert not storage.user_db_path().exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cve_update.py -v`
Expected: FAIL (`ModuleNotFoundError: luci_sky.cve.update`)

- [ ] **Step 3: Implement `update_cve_db`**

```python
# luci_sky/cve/update.py
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
```

- [ ] **Step 4: Register the CLI command**

In `luci_sky/cli.py`, add:

```python
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_cve_update.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add luci_sky/cve/update.py luci_sky/cli.py tests/test_cve_update.py
git commit -m "feat: update-cve command (fetch/copy/validate)"
```

---

## Task 13: Staleness warning in `scan` + enriched `version`

**Files:**
- Modify: `luci_sky/cli.py` (`scan` startup warning, `version` output)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `CVEDatabase.is_stale`, `.db_version`, `.updated` (Task 11).
- Produces: `version` prints DB version + updated date + count; `scan` prints a one-line staleness warning when the DB is stale and not `--quiet`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli.py  (append)
from unittest.mock import patch
from click.testing import CliRunner
from luci_sky.cli import cli


def test_version_shows_db_metadata():
    runner = CliRunner()
    with patch("luci_sky.cve.database.CVEDatabase") as DB:
        DB.return_value._entries = [object(), object()]
        DB.return_value.db_version = 7
        DB.return_value.updated = "2026-07-06"
        result = runner.invoke(cli, ["version"])
    assert result.exit_code == 0
    assert "7" in result.output and "2026-07-06" in result.output
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py -k version_shows_db_metadata -v`
Expected: FAIL (updated date not printed)

- [ ] **Step 3: Enrich `version`**

Replace the body of the `version` command with:

```python
    from luci_sky.cve.database import CVEDatabase
    db = CVEDatabase()
    click.echo(f"LuCI-RedTeam version {luci_sky.__version__}")
    click.echo(
        f"CVE database: {len(db._entries)} entries "
        f"(version {db.db_version}, updated {db.updated})"
    )
    if db.is_stale():
        click.echo("WARNING: CVE database is over 90 days old. Run 'luci-sky update-cve'.")
```

- [ ] **Step 4: Add the scan-time warning**

In `scan`, right after the disclaimer block (and only when not quiet), add:

```python
    if not cfg.quiet:
        from luci_sky.cve.database import CVEDatabase
        _db = CVEDatabase()
        if _db.is_stale():
            click.echo("WARNING: CVE database is over 90 days old. Run 'luci-sky update-cve'.")
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_cli.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add luci_sky/cli.py tests/test_cli.py
git commit -m "feat: CVE staleness warning + enriched version output"
```

---

## Task 14: Finding dedup/merge

**Files:**
- Create: `luci_sky/dedup.py`
- Modify: `luci_sky/scanner.py` (`run`, before the severity sort)
- Test: `tests/test_dedup.py`

**Interfaces:**
- Produces: `luci_sky.dedup.merge_findings(findings: List[Finding]) -> List[Finding]` — collapses findings that share a CVE ID (else a normalized title) **and** `affected_url`; keeps the highest `(severity.numeric_rank, cvss_score, confidence)`, unions `references`/`cve_ids`, and sets `contributing_checks` to the sorted set of all source `check_id`s.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_dedup.py
from luci_sky.dedup import merge_findings
from luci_sky.models import Finding, Severity, Category, Confidence


def _f(check_id, sev, cve=None, url="https://h/x", title="t"):
    return Finding(
        id="LUCI-X-001", check_id=check_id, title=title, severity=sev,
        cvss_score=float(sev.numeric_rank), cvss_vector="v",
        category=Category.CVE, confidence=Confidence.HIGH, description="d",
        evidence="e", affected_url=url, remediation="r",
        references=[f"ref-{check_id}"], cve_ids=[cve] if cve else [],
    )


def test_merge_collapses_shared_cve_same_url():
    findings = [
        _f("default_credentials", Severity.CRITICAL, cve="CVE-2019-12272"),
        _f("service_security", Severity.HIGH, cve="CVE-2019-12272"),
        _f("cve_correlation", Severity.MEDIUM, cve="CVE-2019-12272"),
    ]
    merged = merge_findings(findings)
    assert len(merged) == 1
    m = merged[0]
    assert m.severity == Severity.CRITICAL          # highest wins
    assert set(m.contributing_checks) == {
        "default_credentials", "service_security", "cve_correlation"}
    assert set(m.references) == {"ref-default_credentials", "ref-service_security",
                                 "ref-cve_correlation"}


def test_merge_keeps_distinct_urls_separate():
    findings = [
        _f("a", Severity.HIGH, cve="CVE-1", url="https://h/1"),
        _f("b", Severity.HIGH, cve="CVE-1", url="https://h/2"),
    ]
    assert len(merge_findings(findings)) == 2


def test_merge_empty_returns_empty():
    assert merge_findings([]) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_dedup.py -v`
Expected: FAIL (`ModuleNotFoundError: luci_sky.dedup`)

- [ ] **Step 3: Implement `merge_findings`**

```python
# luci_sky/dedup.py
"""luci_sky.dedup — collapse duplicate findings before reporting."""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

from luci_sky.models import Finding

_WS = re.compile(r"\s+")


def _norm_title(title: str) -> str:
    return _WS.sub(" ", title.strip().lower())


def _keys(f: Finding) -> List[Tuple[str, str]]:
    """Grouping keys for a finding: one per CVE id (else the normalized title)."""
    url = f.affected_url
    if f.cve_ids:
        return [(cve, url) for cve in f.cve_ids]
    return [(_norm_title(f.title), url)]


def _rank(f: Finding) -> tuple:
    conf_rank = {"high": 3, "medium": 2, "low": 1}.get(f.confidence.value, 0)
    return (f.severity.numeric_rank, f.cvss_score, conf_rank)


def merge_findings(findings: List[Finding]) -> List[Finding]:
    """Merge findings sharing a CVE id (else normalized title) + affected URL."""
    groups: Dict[Tuple[str, str], List[Finding]] = {}
    order: List[Tuple[str, str]] = []
    for f in findings:
        # A finding joins the first existing group any of its keys already map to.
        chosen = None
        for k in _keys(f):
            if k in groups:
                chosen = k
                break
        if chosen is None:
            chosen = _keys(f)[0]
            groups[chosen] = []
            order.append(chosen)
        groups[chosen].append(f)

    merged: List[Finding] = []
    for k in order:
        members = groups[k]
        if len(members) == 1:
            merged.append(members[0])
            continue
        best = max(members, key=_rank)
        refs, cves, checks, evidence = [], [], [], []
        for m in members:
            refs.extend(m.references)
            cves.extend(m.cve_ids)
            checks.append(m.check_id)
            evidence.append(f"[{m.check_id}] {m.evidence}")
        best.references = sorted(dict.fromkeys(refs))
        best.cve_ids = sorted(dict.fromkeys(cves))
        best.contributing_checks = sorted(dict.fromkeys(checks))
        best.evidence = "\n---\n".join(evidence)
        merged.append(best)
    return merged
```

- [ ] **Step 4: Wire dedup into the scanner**

In `luci_sky/scanner.py` `run()`, after all phases have populated `findings` and **before** the `findings.sort(...)` call, add:

```python
        from luci_sky.dedup import merge_findings
        findings = merge_findings(findings)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_dedup.py tests/test_scanner.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add luci_sky/dedup.py luci_sky/scanner.py tests/test_dedup.py
git commit -m "feat: merge duplicate findings before reporting"
```

---

## Task 15: Interactive self-contained HTML report

**Files:**
- Modify: `luci_sky/reporters/templates/report.html`
- Modify: `luci_sky/reporters/html_reporter.py` (only if extra template context is needed)
- Test: `tests/test_reporters.py`

**Interfaces:**
- Consumes: `ScanResult`, `summary`, `severity_colors`, `findings_by_severity` already passed by `HtmlReporter.render`; `Finding.contributing_checks` (Task 2).
- Produces: a single self-contained HTML file — inline CSS/JS only, executive summary, inline-SVG severity donut + category bars, severity/category filter chips, collapsible evidence/remediation, light/dark via `prefers-color-scheme`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_reporters.py  (append)
from pathlib import Path
from luci_sky.config import Config
from luci_sky.reporters.html_reporter import HtmlReporter


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
```

Note: findings legitimately contain reference URLs. The self-contained assertion targets **asset** references, so the template must render finding `references` as plain text (not `<a href>` / `<link>` / `<script src>`), and must not pull any external CSS/JS/fonts. The test above tolerates the echoed target URL; keep reference URLs as text so they don't trip asset-loading.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_reporters.py -k "self_contained or summary_and_filters" -v`
Expected: FAIL (current template lacks the summary/filters/inline script markers)

- [ ] **Step 3: Rewrite the template**

Replace `luci_sky/reporters/templates/report.html` with a self-contained document. Key required elements (all inline; no external `href`/`src`):

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LuCI-RedTeam Report — {{ result.target.url }}</title>
<style>
  :root { color-scheme: light dark; --bg:#fff; --fg:#111; --card:#f5f5f5; }
  @media (prefers-color-scheme: dark) { :root { --bg:#111; --fg:#eee; --card:#1c1c1c; } }
  body { background:var(--bg); color:var(--fg); font-family:system-ui,sans-serif; margin:0; padding:1.5rem; }
  .card { background:var(--card); border-radius:8px; padding:1rem; margin-bottom:1rem; }
  .chip { display:inline-block; padding:.25rem .6rem; border-radius:999px; cursor:pointer;
          border:1px solid currentColor; margin:.15rem; font-size:.85rem; }
  .finding { border-left:4px solid #888; padding:.5rem .75rem; margin:.5rem 0; }
  .evidence { display:none; white-space:pre-wrap; font-family:monospace; font-size:.8rem; }
  .finding.open .evidence { display:block; }
  table { border-collapse:collapse; width:100%; }
  th,td { text-align:left; padding:.3rem .5rem; border-bottom:1px solid #8884; }
</style>
</head>
<body>
  <h1>LuCI-RedTeam Security Report</h1>
  <div class="card">
    <h2>Executive Summary</h2>
    <p>Target: {{ result.target.url }} — Mode: {{ result.scan_mode.value }} —
       Duration: {{ '%.1f' % (result.duration_seconds or 0) }}s</p>
    <table>
      <tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr>
      <tr><td>{{ summary.critical }}</td><td>{{ summary.high }}</td><td>{{ summary.medium }}</td>
          <td>{{ summary.low }}</td><td>{{ summary.info }}</td></tr>
    </table>
  </div>

  <div class="card">
    <h3>Severity distribution</h3>
    {% for sev in ['critical','high','medium','low','info'] %}
    <div style="margin:.2rem 0;">
      <span style="display:inline-block;width:5rem;">{{ sev }}</span>
      <span style="display:inline-block;height:.9rem;vertical-align:middle;
                   background:{{ severity_colors[sev|upper] }};
                   width:{{ summary[sev] * 18 }}px;"></span>
      {{ summary[sev] }}
    </div>
    {% endfor %}
  </div>

  <div class="card">
    <strong>Filter:</strong>
    <span class="chip" onclick="filterBySeverity('all')">all</span>
    {% for sev in ['critical','high','medium','low','info'] %}
    <span class="chip" onclick="filterBySeverity('{{ sev }}')">{{ sev }}</span>
    {% endfor %}
  </div>

  {% for f in result.findings %}
  <div class="finding" data-severity="{{ f.severity.value }}" data-category="{{ f.category.value }}"
       onclick="this.classList.toggle('open')">
    <strong>[{{ f.severity.value|upper }}]</strong> {{ f.title }}
    ({{ f.id }}{% if f.contributing_checks %} — checks: {{ f.contributing_checks|join(', ') }}{% endif %})
    <div class="evidence">Evidence:
{{ f.evidence }}

Remediation: {{ f.remediation }}
{% if f.references %}References:
{% for r in f.references %}- {{ r }}
{% endfor %}{% endif %}</div>
  </div>
  {% endfor %}

<script>
function filterBySeverity(sev) {
  document.querySelectorAll('.finding').forEach(function (el) {
    el.style.display = (sev === 'all' || el.dataset.severity === sev) ? '' : 'none';
  });
}
</script>
</body>
</html>
```

References are rendered as plain text list items (no `<a href>`), so no external asset is loaded. The "Severity distribution" block is a pure-CSS inline bar chart (widths scale from `summary` counts, colors from the `severity_colors` context already passed by `HtmlReporter.render`) — no chart library and no external assets. Keep autoescape on (already set in `HtmlReporter`). If an SVG donut is wanted later, build the `<svg>` string in `html_reporter.py` and pass it as an extra context variable; it is not required for the tests.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_reporters.py -v`
Expected: PASS

- [ ] **Step 5: Run the full suite + lint**

Run: `pytest` then `ruff check luci_sky`
Expected: all tests PASS; ruff reports no errors on new/modified files.

- [ ] **Step 6: Commit**

```bash
git add luci_sky/reporters/templates/report.html luci_sky/reporters/html_reporter.py tests/test_reporters.py
git commit -m "feat: interactive self-contained HTML report"
```

---

## Final verification

- [ ] Run the complete suite: `pytest`
- [ ] Lint: `ruff check luci_sky`
- [ ] Manual smoke (offline, expects exit 2 on unreachable — proves the pipeline wires up):
  `luci-sky scan https://127.0.0.1:9 --mode passive --confirm --log-file /tmp/audit.jsonl`
- [ ] `luci-sky version` shows DB version + updated date.
- [ ] `luci-sky update-cve --from-file luci_sky/cve/data/luci_cves.yml` writes to the user data dir.
- [ ] `luci-sky list-checks` still lists all checks.

---

## Self-Review Notes (coverage vs. spec)

- **#2 config wiring** → Tasks 5, 6 (fields, `Config.build`, `--config`, exposed flags, `ca_bundle`).
- **#1 phased orchestration** → Tasks 3, 4, 7 (`Phase`, assignments, phased executor). Deliberate refinement: no per-`Target` lock; phase serialization + disjoint recon attributes provide correctness without touching every check or breaking `Target` serialization.
- **#5 audit log** → Tasks 1, 8, 9 (shared sanitizer, `AuditLogger`, session/CLI wiring, `-v/--debug/--log-file`).
- **#6 progress** → Tasks 7 (event fields), 10 (rich callback, quiet/non-TTY suppression).
- **#8 CVE freshness** → Tasks 11, 12, 13 (storage, metadata, staleness, `update-cve`, warnings, enriched `version`).
- **#10 dedup + HTML** → Tasks 2, 14, 15 (`contributing_checks`, `merge_findings`, self-contained interactive report).
