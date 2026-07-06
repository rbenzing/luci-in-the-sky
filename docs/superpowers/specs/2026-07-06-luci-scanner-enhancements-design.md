# LuCI-Sky Scanner Enhancements — Design

**Date:** 2026-07-06
**Status:** Approved (pending spec review)
**Scope:** Six enhancements (#1, #2, #5, #6, #8, #10) to the `luci-in-the-sky` red-team scanner.

---

## 1. Goals

Ship six enhancements behind the existing CLI with **no breaking changes** to current
invocations:

| # | Enhancement | Primary value |
|---|-------------|---------------|
| 1 | Phased scan orchestration with check phases | Correctness — fixes CVE correlation no-op |
| 2 | Wire the orphaned `Config.load()` YAML+env chain | Robustness — unlocks unreachable config |
| 5 | Engagement audit log + `-v/--verbose` + `--debug` | Proof-of-work + debuggability |
| 6 | Live progress UI (wire existing `progress_callback`) | UX |
| 8 | CVE database freshness metadata + `update-cve` | Robustness of a security tool |
| 10 | Finding dedup/merge + richer interactive HTML report | Result quality + UX |

### Non-goals

- No new scan checks or CVE content authored here (only the freshness/update *mechanism*).
- No async rewrite; the existing `ThreadPoolExecutor` model is retained.
- No changes to the JSON schema beyond the additive `contributing_checks` field.

---

## 2. Design decisions (locked)

- **#8 update source:** GitHub raw file + local-file fallback. Add `version`/`updated`/`source`
  metadata to the YAML now; staleness warning from that date; `update-cve` fetches from a
  configurable URL (default: this project's GitHub raw path), `--from-file` for air-gapped use.
- **#1 ordering model:** a `phase` enum on each `Check` (`RECON` → `ANALYSIS` → `EXPLOIT`).
  Scanner runs phase-by-phase, parallel within a phase.
- **#5 audit depth:** metadata + sanitized response snippet always; full sanitized bodies only
  under `--debug`.
- **#10 dedup:** merge duplicates — collapse findings sharing a CVE ID (or normalized title) +
  affected URL, keep the highest severity/confidence, merge references/evidence, record all
  contributing checks.

---

## 3. Cross-cutting changes

These are shared by multiple features and are implemented first.

### 3.1 Shared sanitizer (`luci_sky/sanitize.py`)

Extract the secret-masking logic currently in `Check._sanitize`
([`luci_sky/checks/base.py`](../../../luci_sky/checks/base.py) lines ~95–127) into a module-level
function:

```python
def sanitize(text: str, max_len: int = 2000) -> str: ...
```

`Check._sanitize` becomes a thin wrapper delegating to `sanitize(...)` so all existing check
code is unchanged. The audit logger (#5) and evidence merge (#10) call `sanitize` directly.

### 3.2 `Finding.contributing_checks`

Add `contributing_checks: List[str] = field(default_factory=list)` to `Finding`
([`luci_sky/models.py`](../../../luci_sky/models.py)). Include it in `Finding.to_dict()` and in
`_build_result_from_dict` reconstruction ([`luci_sky/cli.py`](../../../luci_sky/cli.py)). Default
empty; populated by the merge pass. Backward-compatible (older JSON without the field
reconstructs to `[]`).

### 3.3 Config → CLI precedence

Final precedence chain: **CLI-explicit > environment > YAML file > dataclass defaults.**

Mechanism: CLI options that can also come from config default to a `None` sentinel. The command:

1. Calls `Config.load(config_path)` (YAML + env overlay, already implemented).
2. Overlays each CLI value **only when it is not `None`** (i.e. the user actually passed it).

Options that are purely presentational or safety-related and have no config-file meaning (e.g.
`--confirm`, `--quiet`) keep their current boolean defaults.

---

## 4. Feature designs

### #2 — Config wiring

**Files:** [`luci_sky/config.py`](../../../luci_sky/config.py), [`luci_sky/cli.py`](../../../luci_sky/cli.py),
[`luci_sky/session/http.py`](../../../luci_sky/session/http.py)

- Add `--config PATH` to `scan` and `check`. When omitted, auto-discover in order:
  `./luci-sky.yml`, then `~/.config/luci-sky/config.yml`. Missing files are skipped silently
  (unless `--debug`).
- Route config construction through `Config.load()` + CLI overlay (§3.3), replacing the current
  bare `cfg = Config()`.
- Expose currently-dead fields as CLI flags:
  - `--delay-ms INT`, `--jitter-ms INT` → rate-limit throttle inputs.
  - `--include ID` / `--exclude ID` (repeatable) → `include_checks` / `exclude_checks`.
  - `--ca-bundle PATH` → wired into the session `verify` argument (a CA path overrides the
    boolean `verify_tls` when TLS verification is on).
  - `--extra-cred USER:PASS` (repeatable) → `extra_credentials` (consumed by `DefaultCredentials`).
- `--debug` makes the YAML load error in `Config.load()` visible instead of silent `pass`.

**Tests:** precedence (defaults < YAML < env < CLI), auto-discovery, repeatable flags parse to
lists, `--ca-bundle` reaches the session verify param.

### #1 — Phased orchestration

**Files:** [`luci_sky/models.py`](../../../luci_sky/models.py) (new `Phase`),
[`luci_sky/checks/base.py`](../../../luci_sky/checks/base.py), every check module,
[`luci_sky/scanner.py`](../../../luci_sky/scanner.py)

- New `class Phase(IntEnum): RECON = 0; ANALYSIS = 1; EXPLOIT = 2`.
- `Check` gains `phase: ClassVar[Phase]` with default `Phase.ANALYSIS`, injected via the existing
  `_CheckMeta.__prepare__` default-value pattern (mirrors `severity`/`min_mode`/`requires_auth`).
- **Phase assignments:**
  - **RECON:** `version_detection`, `port_scan`, `path_enumeration`, `package_enumeration`
  - **ANALYSIS:** `cve_correlation`, `service_security`, `tls_analysis`, `security_headers`,
    `cors_misconfiguration`, `wan_exposure`, `firewall_audit`, `wireless_audit`, `backup_exposure`
  - **EXPLOIT:** `command_injection`, `time_based_injection`, `path_traversal`,
    `default_credentials`, `auth_bypass`, `rate_limiting`, `rate_limit_stress`,
    `rpc_exploitation`, `dns_rebinding`, `upnp_audit`, `upnp_port_mapping`
- `Scanner.run` groups the filtered checks by phase and executes phases in ascending order; within
  a phase it keeps the current `ThreadPoolExecutor` fan-out. Findings accumulate across phases.
- A `threading.Lock` guards mutations of the shared `Target` (`detected_version`, `open_ports`,
  `accessible_paths`) for the in-phase parallel case.
- **Result:** RECON populates `target.detected_version`/`open_ports` before ANALYSIS reads them,
  so `CVECorrelation` and `ServiceSecurity` see real recon output.

**Tests:** a RECON check that sets `detected_version` is observed by an ANALYSIS check; phase
execution order asserted; `check` command (single check) still runs regardless of phase.

### #5 — Engagement audit log

**Files:** [`luci_sky/session/http.py`](../../../luci_sky/session/http.py), new
`luci_sky/audit.py`, [`luci_sky/cli.py`](../../../luci_sky/cli.py)

- New `AuditLogger` (in `luci_sky/audit.py`): thread-safe JSONL writer, shared across cloned
  sessions (constructed once, passed into `SessionManager` and its clones).
- `SessionManager._request` (plus `authenticate`/`logout`) emit one record per call:
  `{ts, method, url, status, elapsed_ms, req_bytes, resp_bytes, snippet}` where `snippet` is a
  `sanitize()`d ~300-char response excerpt. Under `--debug`, records also include full sanitized
  request/response headers and bodies.
- CLI flags:
  - `--log-file PATH` → JSONL sink (no-op if unset; console-only when combined with `-v`).
  - `-v/--verbose` → console logging at `INFO`.
  - `--debug` → `DEBUG` level + full bodies in audit records + un-swallowed exceptions.

**Tests:** record shape, snippet sanitization masks secrets, `--debug` includes bodies, writer is
thread-safe (concurrent writes produce valid JSONL lines).

### #6 — Live progress UI

**Files:** [`luci_sky/scanner.py`](../../../luci_sky/scanner.py),
[`luci_sky/cli.py`](../../../luci_sky/cli.py)

- Extend progress events to carry `phase`, `total`, and `completed` in addition to the existing
  `status`/`check_id` fields emitted at
  [`luci_sky/scanner.py`](../../../luci_sky/scanner.py) (~line 137).
- CLI builds a `progress_callback` backed by `rich.progress.Progress` (rich is already a
  dependency): a bar per phase plus a current-check spinner/description.
- Progress is suppressed when `--quiet` is set or when stdout is not a TTY (falls back to no
  output). The `progress_callback` parameter already exists on `Scanner.__init__` and is currently
  unused.

**Tests:** a fake callback captures the event stream and asserts phase/total/completed are present
and monotonic; `--quiet` produces no progress callback.

### #8 — CVE freshness & update

**Files:** [`luci_sky/cve/database.py`](../../../luci_sky/cve/database.py),
[`luci_sky/cve/data/luci_cves.yml`](../../../luci_sky/cve/data/luci_cves.yml), new
`luci_sky/cve/update.py`, [`luci_sky/cli.py`](../../../luci_sky/cli.py)

- Add a metadata block to the YAML top level:
  ```yaml
  version: 1
  updated: "2026-07-06"
  source: "https://raw.githubusercontent.com/rbenzing/luci-in-the-sky/main/luci_sky/cve/data/luci_cves.yml"
  cves: [ ... ]
  ```
- **Loader precedence:** `CVEDatabase._load` checks a **user data dir first**, then the bundled
  file. User data dir resolution: `LUCI_DATA_DIR` env override → `%LOCALAPPDATA%\luci-sky\` on
  Windows → `~/.local/share/luci-sky/` on POSIX. Filename `luci_cves.yml`.
- **`update-cve` command:** `luci-sky update-cve [--url URL] [--from-file PATH] [--force]`.
  Fetches YAML from `--url` (default = the `source` in the current DB / project raw path) or copies
  from `--from-file`, validates it parses and has a `cves` list, then writes it to the user data
  dir. `--force` overwrites without the "already newer" guard.
- **Staleness:** if `updated` is older than **90 days**, print a one-line warning at the start of
  `scan` and in `version`. `version` reports DB `version`, `updated`, and entry count.

**Tests:** loader prefers user-dir over bundled; staleness warning fires past 90 days and not
before; `update-cve --from-file` writes and re-loads; malformed downloaded YAML is rejected without
corrupting the existing DB.

### #10 — Dedup + richer HTML report

**Files:** new `luci_sky/dedup.py`, [`luci_sky/scanner.py`](../../../luci_sky/scanner.py),
[`luci_sky/reporters/templates/report.html`](../../../luci_sky/reporters/templates/report.html),
[`luci_sky/reporters/html_reporter.py`](../../../luci_sky/reporters/html_reporter.py)

- **`merge_findings(findings) -> findings`** in `luci_sky/dedup.py`:
  - Group key: shared CVE ID if any, else normalized (lowercased, whitespace-collapsed) title;
    combined with `affected_url`.
  - Merge: keep the finding with the highest `(severity.numeric_rank, cvss_score, confidence)`;
    union `references` and `cve_ids`; concatenate distinct evidence blocks; set
    `contributing_checks` to the sorted set of all source `check_id`s.
  - Called in `Scanner.run` after collection, before the existing severity sort.
- **HTML report** upgraded to a **self-contained single file** (all CSS/JS inline, no external or
  CDN assets — matches the offline/air-gapped security context):
  - Executive-summary header (target, mode, duration, severity counts).
  - Severity donut + per-category bar chart rendered as inline SVG (no chart library).
  - Filter chips (by severity and category) implemented in a small inline `<script>`.
  - Collapsible per-finding evidence/remediation; `contributing_checks` shown when > 1.
  - Light/dark support via `prefers-color-scheme`.

**Tests:** merge collapses the three CVE-2019-12272 reporters into one finding carrying all three
check IDs; highest severity wins; references union is deduped. HTML smoke test asserts the rendered
output contains no `http(s)://` asset references (self-contained), and includes the summary block
and filter controls.

---

## 5. Implementation sequence

1. **Foundations:** §3.1 sanitizer, §3.2 `Finding` field, §3.3 precedence helper, `Phase` enum.
2. **#2 Config wiring** (depends on §3.3).
3. **#1 Phased orchestration** (depends on `Phase`).
4. **#5 Audit log** (depends on §3.1 sanitizer; new flags share the §3.3 pattern).
5. **#6 Progress** (depends on #1 phase events).
6. **#8 CVE freshness/update.**
7. **#10 Dedup + HTML** (depends on §3.2 field).

Each step keeps the suite green before the next begins.

---

## 6. Testing & quality strategy

- Unit tests per feature in the existing `tests/` layout (mirroring `tests/checks/`,
  `tests/test_config.py`, `tests/test_scanner.py`, `tests/test_reporters.py`).
- Network is mocked (`requests-mock`) as in the current suite; no live targets.
- Full `pytest` suite plus `ruff check` must pass (ruff is configured in `pyproject.toml` but not
  yet enforced — this work runs it locally as the quality gate).
- `datetime.utcnow()` usage introduced by new code uses timezone-aware `datetime.now(timezone.utc)`
  to avoid deprecation; existing usages are left unless touched.

---

## 7. Risks & mitigations

| Risk | Mitigation |
|------|-----------|
| Config precedence regressions break existing CLI behavior | `None`-sentinel overlay only changes values the user explicitly passes; covered by precedence tests. |
| Phase serialization slows scans | Parallelism is preserved *within* each phase; only three phase barriers are added. |
| `update-cve` writes to a non-writable install dir | Writes to a per-user data dir, never the package dir. |
| Audit log captures sensitive target data | Snippets are `sanitize()`d; full bodies are opt-in via `--debug`. |
| Self-contained HTML grows large | Inline SVG + minimal JS; no chart library; evidence is already length-capped. |
