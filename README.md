# Web Application Security Scanner

A lightweight Python security scanner for educational and authorized testing. It checks common web application issues, crawls same-domain pages, and writes timestamped text and JSON reports.

> Use this tool only on systems you own or have explicit permission to test.

## Features

- SQL injection checks with error-based, boolean-based, and time-based techniques.
- Cross-site scripting checks with context-aware HTML analysis.
- CSRF form checks with token detection and enforcement testing.
- Optional same-domain crawler for discovering pages before scanning.
- Authenticated scanning with cookie headers.
- Configurable request delay, timeout, module selection, crawl depth, and output directory.
- Text and JSON report generation.
- Pytest test suite covering scanner logic and false-positive controls.

## Quick Start

```bash
git clone https://github.com/alizadahasan/Web-Application-Security-Scanner.git
cd Web-Application-Security-Scanner

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Run a basic scan:

```bash
python3 scanner.py --url "http://example.com"
```

Run tests:

```bash
python -m pytest tests/ -v
```

## Usage

```bash
python3 scanner.py --url URL [options]
```

Common options:

| Option | Description |
| --- | --- |
| `--url` | Target HTTP or HTTPS URL. Required. |
| `--modules` | Comma-separated modules: `sqli`, `xss`, `csrf`, or `all`. Default: `sqli,xss,csrf`. |
| `--cookies` | Cookie string for authenticated requests, for example `PHPSESSID=abc123; security=low`. |
| `--crawl` | Discover same-domain URLs before scanning. |
| `--max-pages` | Maximum pages to crawl. Default: `50`. |
| `--delay` | Delay between requests in seconds. Default: `0.5`. |
| `--timeout` | HTTP request timeout in seconds. Default: `5`. |
| `--outdir` | Report output directory. Default: `reports`. |
| `-v`, `-vv` | Increase output verbosity. |

## Examples

Run all default checks:

```bash
python3 scanner.py --url "http://example.com"
```

Run only SQL injection checks:

```bash
python3 scanner.py --url "http://example.com/item.php?id=1" --modules sqli
```

Run an authenticated scan:

```bash
python3 scanner.py \
  --url "http://127.0.0.1/dvwa/vulnerabilities/sqli/" \
  --cookies "PHPSESSID=abc123; security=low" \
  --modules sqli \
  -v
```

Crawl first, then scan discovered pages:

```bash
python3 scanner.py --url "http://example.com" --crawl --modules all --max-pages 100 -v
```

Use slower, safer request pacing:

```bash
python3 scanner.py --url "http://example.com" --delay 1.5 --timeout 15
```

## Reports

Reports are written to the output directory with a timestamped filename:

```text
reports/report_YYYYMMDD_HHMMSS.txt
reports/report_YYYYMMDD_HHMMSS.json
```

Each finding includes:

- vulnerability type
- location
- URL
- HTTP method
- affected parameter
- payload
- evidence snippet

## Project Structure

```text
.
├── scanner.py                 # CLI entry point and scan orchestration
├── requirements.txt           # Runtime and test dependencies
├── modules/
│   ├── crawler.py             # Same-domain BFS crawler
│   ├── extractor.py           # HTTP client and cookie handling
│   ├── sql_injection.py       # SQL injection scanner
│   ├── checks_xss.py          # XSS scanner
│   ├── checks_csrf.py         # CSRF scanner
│   ├── reporter.py            # Text and JSON report generation
│   └── init.py                # Console logger
└── tests/
    └── test_scanner.py        # Unit tests
```

## Detection Modules

### SQL Injection

- Looks for common database error messages.
- Confirms boolean-based behavior with true and false payload comparisons.
- Supports time-based payload checks for blind SQL injection indicators.

### XSS

- Uses unique markers to avoid cached-response false positives.
- Detects marker reflection in executable contexts such as script tags and event handler attributes.
- Avoids treating plain JSON marker reflection as executable XSS.

### CSRF

- Finds forms and checks for common CSRF token field names.
- Treats missing tokens on POST forms as suspicious.
- Tests whether token-protected POST forms appear to enforce token validation.
- Avoids flagging simple GET forms as CSRF vulnerabilities.

### Crawler

- Uses a same-domain breadth-first crawl.
- Respects configurable page limits and request delays.
- Preserves discovered pages for scanning.

## Development

Install dependencies and run the test suite before submitting changes:

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
python -m compileall -q scanner.py modules tests
```

When adding a detection module:

1. Create a new scanner class under `modules/`.
2. Return findings using the shared report format.
3. Register the module in `scanner.py`.
4. Add tests under `tests/`.

Finding format:

```python
{
    "type": "Vulnerability Type",
    "location": "query",
    "url": "http://example.com/vulnerable",
    "method": "GET",
    "param": "id",
    "payload": "test payload",
    "evidence": "proof or response snippet",
}
```

## Security And Ethics

This project is for learning, auditing, and authorized testing. Do not scan systems without permission. Use conservative delays, avoid production systems unless explicitly approved, and treat reports as sensitive security data.

## Test Targets

Recommended intentionally vulnerable targets:

- DVWA for local authenticated testing.
- Public security training targets where scanning is explicitly allowed.

Avoid using this scanner against real third-party services without written authorization.
