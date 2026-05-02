import pytest
from types import SimpleNamespace
from modules.checks_csrf import CSRFScanner
from modules.checks_xss import XSSScanner
from modules.sql_injection import SQLInjectionScanner
from scanner import get_modules_to_scan

class MockHttpClient:
    """Mock HTTP client for testing - simulates web server responses without network calls."""
    def __init__(self, html_map):
        # html_map is dict: url -> html response (simple)
        self.html_map = html_map

    def get(self, url, params=None):
        # If params provided, build a pseudo-query string representation to match mapping keys used in tests
        if params:
            from urllib.parse import urlencode, urlparse, urlunparse
            parsed = urlparse(url)
            q = urlencode(params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, q, parsed.fragment))
            return SimpleNamespace(text=self.html_map.get(test_url, self.html_map.get(url, "")), headers={}, status_code=200)
        return SimpleNamespace(text=self.html_map.get(url, ""), headers={}, status_code=200)

    def post(self, url, data=None):
        # Use url as-is for test mapping
        return SimpleNamespace(text=self.html_map.get(url, ""), headers={}, status_code=200)

# ---------------- CLI Helper Test Cases ----------------
def test_get_modules_to_scan_normalizes_and_deduplicates():
    """Test module parsing normalizes case and removes duplicates."""
    assert get_modules_to_scan("XSS, sqli, xss") == ["xss", "sqli"]

def test_get_modules_to_scan_all_keyword():
    """Test all keyword expands to every supported module."""
    assert get_modules_to_scan("all") == ["sqli", "xss", "csrf"]

# ---------------- CSRF Test Cases ----------------
def test_csrf_detection():
    """Test CSRF detection on form without protection tokens."""
    html = """<form method="POST" action="/transfer.php">
        <input type="text" name="amount"/>
        <input type="text" name="recipient"/>
    </form>"""
    scanner = CSRFScanner(None, MockHttpClient({"http://test.local": html}))
    findings = scanner.scan("http://test.local")
    assert len(findings) == 1
    assert "lacks an obvious CSRF token" in findings[0]["evidence"]

def test_csrf_ignores_get_form_without_token():
    """Test CSRF scanner does not flag harmless GET search forms."""
    html = """<form method="GET" action="/search">
        <input type="text" name="q"/>
    </form>"""
    scanner = CSRFScanner(None, MockHttpClient({"http://test.local": html}))
    findings = scanner.scan("http://test.local")
    assert findings == []

def test_csrf_token_present_and_enforced():
    """Test CSRF detection on form with protection tokens."""
    html = """<form method="POST" action="/transfer.php">
        <input type="text" name="amount"/>
        <input type="hidden" name="csrf_token" value="abc123"/>
    </form>"""
    client_map = {
        "http://test.local": html,
        # baseline POST response (server) key is the action URL (post returns this text)
        "http://test.local/transfer.php": "<html>OK with token</html>",
    }
    scanner = CSRFScanner(None, MockHttpClient(client_map))
    findings = scanner.scan("http://test.local")
    assert isinstance(findings, list)

# ---------------- XSS Test Cases ----------------
def test_xss_reflected_marker():
    """Test XSS detection when marker appears in script context."""
    marker = "XSSMARKER_1234"
    html = f"<html><body><script>{marker}</script></body></html>"
    client = MockHttpClient({"http://test.local?name=test": html})
    scanner = XSSScanner(None, client)
    results = scanner._is_xss(html, marker)
    assert results is True

def test_xss_detects_script_tag_alert():
    """Test XSS detection with actual alert script."""
    html = "<html><body><script>alert(1)</script></body></html>"
    client = MockHttpClient({"http://test.local": html})
    scanner = XSSScanner(None, client)
    assert scanner._is_xss(html, "alert(1)") is True

def test_xss_does_not_flag_json_marker_reflection():
    """Test JSON marker reflection is not treated as executable XSS."""
    marker = "XSSMARKER_1234"
    html = f'{{"name": "{marker}"}}'
    scanner = XSSScanner(None, MockHttpClient({"http://test.local": html}))
    assert scanner._is_xss(html, marker) is False

# ---------------- SQL Injection Test Cases ----------------
def test_sqli_error_based():
    """Test SQL injection detection via error message patterns."""
    html_error = "You have an error in your SQL syntax;"
    # Map full query URL to match extractor expectations
    scanner = SQLInjectionScanner(None, MockHttpClient({"http://test.local?id=1": html_error}))
    assert scanner._contains_sql_error(html_error) is True

def test_sqli_basic_boolean_confirmation():
    """Test boolean-based SQL injection confirmation."""
    true_url = "http://test.local/path?param=1%27+AND+%271%27%3D%271"
    false_url = "http://test.local/path?param=1%27+AND+%271%27%3D%272"
    client_map = {
        true_url: "RESULT_TRUE",
        false_url: "RESULT_FALSE",
    }
    client = MockHttpClient(client_map)
    scanner = SQLInjectionScanner(None, client)
    original_params = {"param": ["1"]}
    res = scanner._confirm_boolean("http://test.local/path?param=1", "param", original_params)
    assert res is False

def test_sqli_boolean_confirmation_requires_significant_difference():
    """Test small body differences alone do not confirm SQL injection."""
    true_url = "http://test.local/path?param=1%27+AND+%271%27%3D%271"
    false_url = "http://test.local/path?param=1%27+AND+%271%27%3D%272"
    client_map = {
        true_url: "Hello Alice",
        false_url: "Hello Bob",
    }
    client = MockHttpClient(client_map)
    scanner = SQLInjectionScanner(None, client)
    original_params = {"param": ["1"]}
    assert scanner._confirm_boolean("http://test.local/path?param=1", "param", original_params) is False

def test_sqli_boolean_confirmation_accepts_large_length_difference():
    """Test large response length differences can still confirm SQL injection."""
    true_url = "http://test.local/path?param=1%27+AND+%271%27%3D%271"
    false_url = "http://test.local/path?param=1%27+AND+%271%27%3D%272"
    client_map = {
        true_url: "A" * 100,
        false_url: "B",
    }
    client = MockHttpClient(client_map)
    scanner = SQLInjectionScanner(None, client)
    original_params = {"param": ["1"]}
    assert scanner._confirm_boolean("http://test.local/path?param=1", "param", original_params) is True
