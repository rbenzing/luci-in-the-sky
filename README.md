# LuCI-Sky RedTeam Framework

![License: AGPL v3+](https://img.shields.io/badge/license-AGPLv3%2B-blue.svg)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB.svg?logo=python&logoColor=white)
![Tests: pytest](https://img.shields.io/badge/tests-pytest-0A9EDC.svg?logo=pytest&logoColor=white)
![Status: Beta](https://img.shields.io/badge/status-beta-orange.svg)

Red team security scanning framework for LuCI / OpenWrt web interfaces.

This project provides a CLI for enumerating exposed LuCI services, running passive and active security checks, correlating known LuCI CVEs, and rendering results in terminal, JSON, or HTML form.

## Responsible Use

This tool is for authorized security testing only.

Do not run it against systems you do not own or do not have explicit written permission to assess. Active and full scans may send intrusive payloads and can affect target availability or integrity.

## Features

- Passive, active, and full scan modes with **phased orchestration** (reconnaissance → analysis → exploitation) so version and port discovery inform later checks such as CVE correlation
- 28 built-in checks across auth, TLS, network, injection, XSS, CSRF, session, information-disclosure, and CVE categories
- Terminal, JSON, and **interactive, self-contained HTML** reporting (severity/category filtering, collapsible evidence, no external assets — works offline)
- **Automatic de-duplication** of overlapping findings (correlated by CVE ID / affected URL, with contributing checks recorded)
- **Layered configuration** with a clear precedence chain: CLI flags > environment variables > YAML config file > defaults
- **Engagement audit log**: optional JSONL trail of every request/response, with automatic redaction of credentials, session cookies, and tokens
- **CVE database freshness tracking** plus an `update-cve` command to refresh the bundled database
- Optional authenticated scanning
- **Client-side rate limiting** (request delay + jitter) for careful, authorized testing
- Severity threshold filtering and per-check include/exclude selection
- Re-render saved JSON results into other output formats

## Installation

### From source

```bash
git clone <repository-url>
cd luci-in-the-sky
python -m pip install -e .[dev]
```

### Runtime requirements

- Python 3.10 or newer
- Network access to the LuCI/OpenWrt target you are authorized to test

## Quick Start

List available checks:

```bash
luci-sky list-checks
```

Run a passive scan:

```bash
luci-sky scan https://192.168.1.1 --mode passive
```

Run an authenticated active scan and write JSON output:

```bash
luci-sky scan https://192.168.1.1 \
  --mode active \
  --username root \
  --password '<password>' \
  --format json \
  --output scan-results.json \
  --confirm
```

Generate an HTML report from a saved JSON result:

```bash
luci-sky report scan-results.json --format html --output report.html
```

Run a single check:

```bash
luci-sky check tls_analysis https://192.168.1.1
```

Run a scan from a configuration file and write an engagement audit log:

```bash
luci-sky scan https://192.168.1.1 \
  --config ./luci-sky.yml \
  --log-file ./engagement-audit.jsonl \
  --verbose
```

Throttle requests and scope the run to specific checks:

```bash
luci-sky scan https://192.168.1.1 \
  --mode active \
  --delay-ms 250 --jitter-ms 100 \
  --exclude rate_limit_stress \
  --confirm
```

Update the bundled CVE database:

```bash
luci-sky update-cve                     # fetch the latest published database
luci-sky update-cve --from-file cves.yml  # install from a local file (air-gapped)
```

Show tool version and CVE database freshness:

```bash
luci-sky version
```

## CLI Overview

Primary commands:

- `scan`: run a scan against a target URL
- `check`: run a single registered check by ID
- `list-checks`: enumerate available checks
- `report`: re-render a saved JSON result
- `update-cve`: refresh the local CVE database (`--url`, `--from-file`, `--force`)
- `version`: print tool version and CVE database version/freshness

Important scan options:

- `--config /path/to/luci-sky.yml` — load a YAML configuration file
- `--mode passive|active|full`
- `--format terminal|json|html|all`
- `--output /path/to/file`
- `--username`, `--password`, `--token`
- `--include CHECK_ID` / `--exclude CHECK_ID` (repeatable) — select specific checks
- `--extra-cred user:pass` (repeatable) — additional credential pairs to try
- `--threads`
- `--timeout`
- `--delay-ms` / `--jitter-ms` — client-side rate limiting
- `--severity critical|high|medium|low|info`
- `--proxy`
- `--ca-bundle /path/to/ca.pem` — verify TLS against a custom CA bundle
- `--canary-domain`
- `--no-verify-tls`
- `--log-file /path/to/audit.jsonl` — write a JSONL request/response audit log
- `-v`, `--verbose` — verbose (INFO) logging
- `--debug` — debug logging and full (redacted) request/response bodies in the audit log
- `--quiet`, `--no-color`
- `--confirm`

## Output Formats

- `terminal`: rich console output
- `json`: machine-readable scan result
- `html`: self-contained, interactive HTML report — severity/category filtering and collapsible evidence, with all styles and scripts inlined so it renders offline with no external assets
- `all`: emit all supported formats through the reporter registry

## Configuration

Settings are resolved with the following precedence (highest wins):

**CLI flags > environment variables > YAML config file > built-in defaults**

Pass a YAML file with `--config`. Any omitted value falls back to the next source down. Example `luci-sky.yml`:

```yaml
mode: active
threads: 8
timeout: 15
severity_threshold: medium
delay_ms: 200
jitter_ms: 100
verify_tls: true
exclude_checks:
  - rate_limit_stress
```

Selected environment variables (useful for keeping secrets out of shell history):

- `LUCI_USERNAME`, `LUCI_PASSWORD`, `LUCI_SESSION_TOKEN`
- `LUCI_PROXY`, `LUCI_CANARY_DOMAIN`
- `LUCI_DATA_DIR` — directory used to store an updated CVE database (see `update-cve`)

### Engagement audit log

Passing `--log-file` records one JSON object per HTTP request as newline-delimited JSON (JSONL): method, URL, status, timing, and a redacted response snippet. With `--debug`, full request/response bodies are included. Credentials, `sysauth` cookies, and `Authorization` tokens are redacted automatically before anything is written.

## Development

Install the development extras and run the test suite:

```bash
python -m pip install -e .[dev]
pytest
```

The project uses `setuptools` packaging and `pytest` for tests.

## Project Layout

```text
luci_sky/
  checks/       Built-in security checks and registry
  cve/          LuCI CVE correlation data and loader
  reporters/    Terminal, JSON, and HTML reporters
  session/      HTTP session and authentication helpers
tests/          Unit and integration tests
```

## Security and Disclosure

If you find a vulnerability in the tool itself, please follow the guidance in [SECURITY.md](SECURITY.md) and avoid opening a public issue with exploit details.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

By participating in this project, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Versioning

This project follows [Semantic Versioning](https://semver.org/). Notable changes are recorded in [CHANGELOG.md](CHANGELOG.md).

The version is maintained in a single place — `luci_sky/__init__.py` (`__version__`) — and `pyproject.toml` reads it from there, so a release only needs that one value updated. It is also reported by `luci-sky version` and stamped into every scan result's `tool_version` field. Release commits are tagged `vMAJOR.MINOR.PATCH` (e.g. `v1.1.0`).

## License

This project is licensed under the GNU Affero General Public License, version 3 or any later version. See [LICENSE](LICENSE).
