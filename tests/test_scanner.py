import pytest
from types import SimpleNamespace
from modules.checks_csrf import CSRFScanner
from modules.checks_xss import XSSScanner
from modules.sql_injection import SQLInjectionScanner

class MockHttpClient:
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

# ---------------- CSRF ----------------
def test_csrf_detection():
    html = """<form method="POST" action="/transfer.php">
        <input type="text" name="amount"/>
        <input type="text" name="recipient"/>
    </form>"""
    scanner = CSRFScanner(None, MockHttpClient({"http://test.local": html}))
    findings = scanner.scan("http://test.local")
    assert len(findings) == 1
    assert "lacks an obvious CSRF token" in findings[0]["evidence"]

def test_csrf_token_present_and_enforced():
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

# ---------------- XSS ----------------
def test_xss_reflected_marker():
    marker = "XSSMARKER_1234"
    html = f"<html><body><script>{marker}</script></body></html>"
    client = MockHttpClient({"http://test.local?name=test": html})
    scanner = XSSScanner(None, client)
    results = scanner._is_xss(html, marker)
    assert results is True

def test_xss_detects_script_tag_alert():
    html = "<html><body><script>alert(1)</script></body></html>"
    client = MockHttpClient({"http://test.local": html})
    scanner = XSSScanner(None, client)
    assert scanner._is_xss(html, "alert(1)") is True

# ---------------- SQL Injection ----------------
def test_sqli_error_based():
    html_error = "You have an error in your SQL syntax;"
    # Map full query URL to match extractor expectations
    scanner = SQLInjectionScanner(None, MockHttpClient({"http://test.local?id=1": html_error}))
    assert scanner._contains_sql_error(html_error) is True

def test_sqli_basic_boolean_confirmation():
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
    assert res is True
