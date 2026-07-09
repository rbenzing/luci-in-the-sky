# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-07-09

Feature release. All changes are backward compatible: existing commands, flags,
and the JSON result schema continue to work unchanged.

### Added

- **Phased scan orchestration.** Checks now run in ordered phases —
  reconnaissance → analysis → exploitation — so version and port discovery are
  available to later checks. This fixes CVE correlation and service-security
  checks that previously raced reconnaissance and saw no detected version.
- **YAML configuration files** via `--config`, wired into a documented
  precedence chain: CLI flags > environment variables > config file > defaults.
- **Newly exposed scan flags:** `--include` / `--exclude` (per-check selection),
  `--delay-ms` / `--jitter-ms` (client-side rate limiting), `--ca-bundle`
  (custom CA for TLS verification), and `--extra-cred` (additional credential
  pairs).
- **Engagement audit log** (`--log-file`) writing one redacted JSONL record per
  HTTP request/response, plus `-v` / `--verbose` and `--debug` logging modes.
- **Live progress display** during scans (suppressed with `--quiet` or on
  non-interactive output).
- **CVE database freshness:** the bundled database now carries version/updated
  metadata, `luci-sky version` reports it, scans warn when it is stale, and a
  new `update-cve` command refreshes it (`--url`, `--from-file`, `--force`).
- **Finding de-duplication:** overlapping findings (same CVE ID / affected URL)
  are merged, keeping the highest severity and recording every contributing
  check.
- **Interactive HTML report:** self-contained single file with severity/category
  filtering and collapsible evidence; no external assets (renders offline).

### Changed

- The HTML report template was rewritten to be interactive and self-contained.
- The project version is now maintained in a single source of truth
  (`luci_sky/__init__.py::__version__`), read dynamically by `pyproject.toml`
  and stamped into scan results.

### Security

- Evidence and audit-log redaction was hardened to mask password fields in
  URL-encoded, dict-repr, and JSON forms (including values containing quote
  characters), in addition to `sysauth` cookies and `Authorization` tokens.
- `authenticate` and `logout` requests now flow through the audited request
  path, so login/logout are captured in the engagement trail (with credentials
  redacted).

## [1.0.0]

- Initial release: passive/active/full scan modes, 28 built-in checks across
  auth, TLS, network, injection, XSS, CSRF, session, information-disclosure, and
  CVE categories, terminal/JSON/HTML reporting, optional authenticated scanning,
  severity threshold filtering, and re-rendering of saved JSON results.

[1.1.0]: https://github.com/rbenzing/LuCI-RedTeam/releases/tag/v1.1.0
