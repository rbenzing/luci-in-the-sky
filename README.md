# LuCI-RedTeam

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

- Passive, active, and full scan modes
- 28 built-in checks across auth, TLS, network, injection, XSS, CSRF, session, and CVE categories
- Terminal, JSON, and HTML reporting
- Optional authenticated scanning
- Severity threshold filtering
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

Show version and CVE database information:

```bash
luci-sky version
```

## CLI Overview

Primary commands:

- `scan`: run a full scan against a target URL
- `check`: run a single registered check by ID
- `list-checks`: enumerate available checks
- `report`: re-render a saved JSON result
- `version`: print tool and CVE database version info

Important scan options:

- `--mode passive|active|full`
- `--format terminal|json|html|all`
- `--output /path/to/file`
- `--username`, `--password`, `--token`
- `--threads`
- `--timeout`
- `--severity critical|high|medium|low|info`
- `--proxy`
- `--canary-domain`
- `--no-verify-tls`
- `--confirm`

## Output Formats

- `terminal`: rich console output
- `json`: machine-readable scan result
- `html`: standalone HTML report
- `all`: emit all supported formats through the reporter registry

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

## License

This project is licensed under the GNU Affero General Public License, version 3 or any later version. See [LICENSE](LICENSE).
