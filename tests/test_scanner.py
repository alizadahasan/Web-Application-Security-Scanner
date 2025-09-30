import pytest
from types import SimpleNamespace
from modules.checks_csrf import CSRFScanner
from modules.checks_xss import XSSScanner
from modules.sql_injection import SQLInjectionScanner

class MockHttpClient:
    def __init__(self, html_map):
        # html_map is dict: url -> html response
        self.html_map = html_map

    def get(self, url, params=None):
        return SimpleNamespace(text=self.html_map.get(url, ""), headers={})

    def post(self, url, data=None):
        return SimpleNamespace(text=self.html_map.get(url, ""), headers={})

# ---------------- CSRF ----------------
def test_csrf_detection():
    html = """<form method="POST" action="/transfer.php">
        <input type="text" name="amount"/>
        <input type="text" name="recipient"/>
    </form>"""
    scanner = CSRFScanner(None, MockHttpClient({"http://test.local": html}))
    findings = scanner.scan("http://test.local")
    assert len(findings) == 1
    # Update this to match the new format returned by the scanner
    assert "Form likely vulnerable" in findings[0]["evidence"]

def test_csrf_token_present():
    html = """<form method="POST" action="/transfer.php">
        <input type="text" name="amount"/>
        <input type="hidden" name="csrf_token" value="abc123"/>
    </form>"""
    scanner = CSRFScanner(None, MockHttpClient({"http://test.local": html}))
    findings = scanner.scan("http://test.local")
    assert len(findings) == 0

# ---------------- XSS ----------------
def test_xss_reflected_marker():
    marker = "XSSMARKER_1234"
    html = f"<html><body>Hello <script>{marker}</script></body></html>"
    client = MockHttpClient({"http://test.local?name=test": html})
    scanner = XSSScanner(None, client)
    results = scanner._is_xss(html, marker)
    assert results is True

def test_xss_detects_script_tag_without_marker():
    html = "<html><body><pre>Hello <script>alert(1)</script></pre></body></html>"
    client = MockHttpClient({"http://test.local": html})
    scanner = XSSScanner(None, client)
    assert scanner._is_xss(html, "NONEXISTENT") is True

# ---------------- SQL Injection ----------------
def test_sqli_error_based():
    html_error = "You have an error in your SQL syntax;"
    scanner = SQLInjectionScanner(None, MockHttpClient({"http://test.local?id=1": html_error}))
    assert scanner._is_sqli(html_error) is True

def test_sqli_baseline_difference():
    base = "Normal page content."
    injected = base + "Error: SQL syntax near..."  # Generic error simulation
    scanner = SQLInjectionScanner(None, MockHttpClient({"http://test.local": injected}))
    assert scanner._is_sqli(injected, base) is True
