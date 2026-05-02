# Web Application Security Scanner - Developer Documentation



## Project Overview:
This is the developer documentation for the Python-based Web Application Security Scanner. For user documentation and project proposal, refer to the main pdf document.


### Installation:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Install the requirements before running the scanner or test suite. The tests use `pytest`, which is included in `requirements.txt`.

### Running the Scanner

#### Basic Public Site Scanning
```bash
# Scan TestPHP (public test site)
python3 scanner.py --url "http://testphp.vulnweb.com" --modules sqli,xss,csrf

# Targeted scan on specific endpoint
python3 scanner.py --url "http://testphp.vulnweb.com/listproducts.php?cat=1" --modules sqli
```

#### DVWA Scanning (Local Installation)
```bash
# Basic DVWA scan (requires authentication)
python3 scanner.py --url "http://127.0.0.1/dvwa/vulnerabilities/sqli/" --cookies "PHPSESSID=abc123; security=low" --modules sqli -v

# XSS scanning on DVWA
python3 scanner.py --url "http://127.0.0.1/dvwa/vulnerabilities/xss_r/" --cookies "PHPSESSID=abc123; security=low" --modules xss -v

# CSRF scanning on DVWA  
python3 scanner.py --url "http://127.0.0.1/dvwa/vulnerabilities/csrf/" --cookies "PHPSESSID=abc123; security=low" --modules csrf -v

```
### Comprehensive scan with crawling
```bash
python3 scanner.py --url "http://testphp.vulnweb.com" --crawl --modules all -v                    

```


## Architecture & Module Structure

### Core Components
```
scanner.py                 # Main CLI controller
modules/
├── crawler.py            # URL discovery (BFS algorithm)
├── extractor.py          # HTTP client with session management
├── sql_injection.py      # SQLi detection engine
├── checks_xss.py         # XSS detection engine  
├── checks_csrf.py        # CSRF detection engine
└── reporter.py           # Report generation
```

### Module Interface Contract
All detection modules must implement:

```python
class VulnerabilityScanner:
    def __init__(self, logger, http, delay_between_requests=0.5):
        self.logger = logger
        self.http = http
        self.delay = delay_between_requests

    def scan(self, url: str) -> List[Dict]:
        """Returns list of finding dictionaries"""
        pass
```

## Adding New Detection Modules

### 1. Create Module File
Create `modules/your_detector.py`:

```python
from modules.init import Logger

class YourVulnerabilityScanner:
    def __init__(self, logger=None, http=None, delay_between_requests=0.5):
        self.logger = logger if logger is not None else Logger(verbosity=0)
        self.http = http
        self.delay = delay_between_requests

    def scan(self, url: str):
        findings = []
        # Your detection logic here
        
        finding = {
            "type": "Your Vulnerability Type",
            "location": "query|form",
            "url": url,
            "method": "GET|POST", 
            "param": "parameter_name",
            "payload": "test_payload",
            "evidence": "proof_of_vulnerability"
        }
        findings.append(finding)
        return findings
```

### 2. Register Module
In `scanner.py`, add to scanners dictionary:

```python
scanners = {
    "sqli": lambda: SQLInjectionScanner(logger, http, args.delay),
    "xss": lambda: XSSScanner(logger, http, args.delay),
    "csrf": lambda: CSRFScanner(logger, http, args.delay),
    "your_module": lambda: YourVulnerabilityScanner(logger, http, args.delay)
}
```

### 3. Add Tests
Create tests in `tests/test_your_detector.py`:

```python
def test_your_detector_basic():
    html = "vulnerable response content"
    client = MockHttpClient({"http://test.local": html})
    scanner = YourVulnerabilityScanner(None, client)
    results = scanner.scan("http://test.local")
    assert len(results) > 0
```

## Core Algorithm Details

### SQL Injection Detection
**Multi-phase approach:**
1. **Error-based**: Pattern matching on database errors
2. **Boolean-based**: Differential analysis (`1' AND '1'='1` vs `1' AND '1'='2`)
3. **Time-based**: Response timing analysis (disabled by default)

**Key data structures:**
```python
BASIC_PAYLOADS = ["' OR '1'='1", "' OR 1=1 --", ...]
SQL_ERRORS = ["SQL syntax", "mysql_fetch", "ORA-", ...]
TIME_PAYLOADS = ["' OR SLEEP(3)--", ...]
```

### XSS Detection  
**Context-aware analysis:**
- Script tag content detection
- Event handler attribute analysis  
- HTML element creation detection
- JSON reflection identification

**Unique marker system prevents false positives:**
```python
marker = f"XSSMARKER_{uuid.uuid4().hex[:8]}"
```

### CSRF Detection
**Protection identification:**
- Token field detection (`csrf_token`, `authenticity_token`, etc.)
- Enforcement testing (with/without token comparison)
- Header validation checks

## Crawler Implementation

### Usage
```bash
# Integrated scanning  
python3 scanner.py --url "http://example.com" --crawl --modules sqli,xss
```

### Algorithm
- **BFS-based** URL discovery
- **Same-domain** confinement
- **Form extraction** with method/action resolution
- **Configurable limits** (max pages, delay between requests)

## Reporting System Integration

### Adding Findings
All detectors use consistent finding format:

```python
finding = {
    "type": "Vulnerability Type",
    "location": "query",  # or "form"
    "url": "http://example.com/vulnerable",
    "method": "GET",
    "param": "id",
    "payload": "test'payload",
    "evidence": "Error: SQL syntax..."
}
```

### Report Generation
- Automatic evidence sanitization
- Timestamped report files
- Structured text format
- JSON output available

## Testing Framework

### Running Tests
```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

### Test Structure
- `MockHttpClient` for simulated responses
- Unit tests for each detection algorithm
- Integration tests for full workflows
- False positive/negative validation

### Example Test
```python
class MockHttpClient:
    def __init__(self, html_map):
        self.html_map = html_map
    
    def get(self, url, params=None):
        return SimpleNamespace(text=self.html_map.get(url, ""), status_code=200)
```

## Extension Examples

### Adding New Payloads
**SQLi:** Add to `BASIC_PAYLOADS` in `sql_injection.py`  
**XSS:** Add to `self.payloads` in `checks_xss.py.__init__()`  
**CSRF:** Add patterns to `TOKEN_KEYWORDS` in `checks_csrf.py`

### Adding Configuration
Modify `parse_args()` in `scanner.py` for new CLI options:

```python
parser.add_argument("--new-option", help="Description")
```

## Performance Considerations

- Configurable delays between requests (default: 0.5s)
- Early termination when vulnerability confirmed
- Cached baseline responses for comparison
- Limited crawler discovery to prevent infinite loops

## Security & Ethics

- Never scan production systems without permission
- Non-destructive payloads by default
- Rate limiting to avoid service disruption
- Clear educational purpose statements

## Test Applications

### DVWA (Damn Vulnerable Web Application)
- **Purpose**: Local PHP/MySQL application for security training
- **Usage**: Requires authentication with session cookies
- **Security Levels**: Test with "low" security setting initially
- **Setup**: Requires local web server (Apache/Nginx) and MySQL

### TestPHP (testphp.vulnweb.com)
- **Purpose**: Publicly accessible vulnerable test site
- **Usage**: No authentication required
- **Advantage**: Quick testing without local setup
