import uuid
import json
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin, unquote
from bs4 import BeautifulSoup
from modules.init import Logger

class XSSScanner:
    """Scanner for detecting Cross-Site Scripting vulnerabilities using context-aware analysis."""
    
    def __init__(self, logger=None, http=None, delay_between_requests=0.5):
        self.logger = logger if logger is not None else Logger(verbosity=0)
        self.http = http
        self.delay = delay_between_requests
        # XSS payloads targeting different injection contexts with placeholder for unique markers
        self.payloads = [
            "XSSMARKER",  # Basic reflection test
            "<script>XSSMARKER</script>",  # Script tag injection
            "<img src=x onerror=XSSMARKER>",  # Image with error handler
            "\"> <svg/onload=XSSMARKER>",  # SVG injection
            "<svg><script>XSSMARKER</script>",  # SVG with script
            "';alert(1);XSSMARKER",  # JavaScript string break
            "<iframe src=javascript:alert('XSSMARKER')>",  # Iframe with JS URL
            "<input onfocus=alert('XSSMARKER')>",  # Input with event handler
        ]

    def scan(self, url: str):
        """Scan URL for XSS vulnerabilities in both query parameters and forms."""
        # Generate unique marker to avoid false positives from cached responses
        marker = f"XSSMARKER_{uuid.uuid4().hex[:8]}"
        self.logger.info(f"Starting XSS scan with marker: {marker}")
        findings = []
        
        # Parse URL to extract query parameters for testing
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Test each query parameter with all payload variations
        for param in params.keys():
            found_vuln = False
            for payload in self.payloads:
                if found_vuln:  # Stop testing this parameter once vulnerability found
                    break
                    
                payload_with_marker = payload.replace("XSSMARKER", marker)
                # Build new URL with injected payload in the target parameter
                new_params = {k: list(v) for k, v in params.items()}
                new_params[param] = [payload_with_marker]
                new_query = urlencode(new_params, doseq=True)
                new_url = urlunparse(
                    (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
                )
                
                time.sleep(self.delay)
                try:
                    r = self.http.get(new_url, params=None)
                    if r and self._is_xss(r.text, marker):
                        findings.append({
                            "type": "Cross-Site Scripting (XSS)",
                            "location": "query",
                            "url": new_url,
                            "method": "GET",
                            "param": param,
                            "payload": payload_with_marker,
                            "evidence": self._extract_evidence(r.text, marker),
                        })
                        found_vuln = True
                except Exception as e:
                    self.logger.error(f"GET {new_url} failed: {str(e)}")

        # Test forms for XSS vulnerabilities
        try:
            r = self.http.get(url, params=None)
            if r and r.text:
                findings.extend(self._test_forms(url, r.text, marker))
        except Exception as e:
            self.logger.error(f"GET {url} failed: {str(e)}")

        # Remove duplicate findings before returning
        findings = self._deduplicate_findings(findings)
        return findings

    def _deduplicate_findings(self, findings):
        """Remove duplicate findings based on URL, parameter, type, and location."""
        seen = set()
        unique_findings = []
        for finding in findings:
            key = (finding["url"], finding.get("param", ""), finding["type"], finding["location"])
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        return unique_findings

    def _test_forms(self, base_url: str, html: str, marker: str):
        """Test all forms in the HTML for XSS vulnerabilities."""
        findings = []
        soup = BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")
        
        if not forms:
            return findings

        for form in forms:
            action = form.get("action") or base_url
            method = (form.get("method") or "get").upper()
            inputs = form.find_all(["input", "textarea"])
            
            for inp in inputs:
                name = inp.get("name")
                if not name:
                    continue
                    
                found_vuln = False
                for payload in self.payloads:
                    if found_vuln:
                        break
                        
                    payload_with_marker = payload.replace("XSSMARKER", marker)
                    # Build form data with payload in target field
                    data = {i.get("name"): "test" for i in inputs if i.get("name")}
                    data[name] = payload_with_marker
                    target_url = urljoin(base_url, action)
                    
                    time.sleep(self.delay)
                    try:
                        # Submit form based on method (POST or GET)
                        r = self.http.post(target_url, data=data) if method == "POST" else self.http.get(target_url, params=data)
                        if r and self._is_xss(r.text, marker):
                            findings.append({
                                "type": "Cross-Site Scripting (XSS)",
                                "location": "form",
                                "url": target_url,
                                "method": method,
                                "param": name,
                                "payload": payload_with_marker,
                                "evidence": self._extract_evidence(r.text, marker),
                            })
                            found_vuln = True
                    except Exception as e:
                        self.logger.error(f"{method} {target_url} failed: {str(e)}")
        return findings

    def _is_xss(self, text: str, marker: str) -> bool:
        """
        Determine if marker appears in an executable XSS context.
        Returns True only for dangerous contexts, False for safe reflection.
        """
        if not text:
            return False
            
        soup = BeautifulSoup(text, "html.parser")

        # 1) Check if marker appears inside script tag content (immediately executable)
        for script in soup.find_all("script"):
            try:
                if script.string and marker in script.string:
                    self.logger.debug("XSS detected in <script> content")
                    return True
            except Exception:
                continue

        # 2) Check if marker appears in dangerous attributes (event handlers, javascript: URLs)
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                val_str = " ".join(value) if isinstance(value, list) else str(value)
                if val_str and (marker in val_str or marker in unquote(val_str)):
                    # Check for event handlers (onclick, onerror, etc.) or javascript: URLs
                    if attr.lower().startswith("on") or "javascript:" in val_str.lower():
                        self.logger.debug(f"XSS detected in attribute {attr}")
                        return True

        # 3) Check if payload created new dangerous HTML elements
        for tag in soup.find_all(True):
            try:
                if tag.string and marker in tag.string:
                    # Only consider dangerous if in executable-capable tags
                    if tag.name.lower() in ("script", "iframe", "img", "svg", "object", "embed", "body"):
                        self.logger.debug(f"XSS detected in tag content <{tag.name}>")
                        return True
            except Exception:
                continue

        # 4) Check JSON responses for reflected markers (potential API XSS)
        try:
            data = json.loads(text)
            def search_marker(obj):
                """Recursively search for marker in JSON structure."""
                if isinstance(obj, str):
                    return marker in obj or marker in unquote(obj)
                elif isinstance(obj, dict):
                    return any(search_marker(v) for v in obj.values())
                elif isinstance(obj, list):
                    return any(search_marker(item) for item in obj)
                return False
                
            if search_marker(data):
                self.logger.debug("XSS marker found in JSON response (potential)")
                return True
        except json.JSONDecodeError:
            pass

        # If marker appears but wasn't in executable contexts above, treat as safe reflection
        if marker in text or unquote(marker) in text:
            self.logger.debug("Marker found but not in executable context (treated as safe reflection)")
            return False

        return False

    def _extract_evidence(self, text: str, marker: str, context: int = 200) -> str:
        """Extract a safe evidence snippet around the marker for reporting."""
        if not text:
            return "No response content"
            
        idx = text.find(marker)
        if idx != -1:
            # Extract context around the marker
            start = max(0, idx - context)
            end = min(len(text), idx + len(marker) + context)
            snippet = text[start:end].replace("\n", " ").replace("\r", " ")
            return f"Evidence: {snippet}"
            
        # Fallback if marker not found
        return "Evidence: " + text[:context].replace("\n", " ").replace("\r", " ")
