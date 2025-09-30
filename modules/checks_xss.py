import uuid
import json
import time
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin, unquote
from bs4 import BeautifulSoup

class XSSScanner:
    def __init__(self, logger, http):
        self.logger = logger
        self.http = http
        self.payloads = [
            "XSSMARKER",
            "<script>XSSMARKER</script>",
            "<img src=x onerror=XSSMARKER>",
            "\"><svg/onload=XSSMARKER>",
            "<svg><script>XSSMARKER",
            "';alert(1);XSSMARKER",
            "<iframe src=javascript:alert('XSSMARKER')>",
            "<input onfocus=alert('XSSMARKER')>",
        ]

    def scan(self, url: str):
        marker = f"XSSMARKER_{uuid.uuid4().hex[:8]}"
        self.logger.info(f"Starting XSS scan with marker: {marker}")
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Test query parameters
        for param in params.keys():
            found_vuln = False
            for payload in self.payloads:
                if found_vuln:
                    break
                payload_with_marker = payload.replace("XSSMARKER", marker)
                new_params = dict(params)
                new_params[param] = payload_with_marker
                new_query = urlencode(new_params, doseq=True)
                new_url = urlunparse(
                    (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
                )
                time.sleep(0.5)
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
                    if self.logger:
                        self.logger.error(f"GET {new_url} failed: {str(e)}")

        # Test forms
        try:
            r = self.http.get(url, params=None)
            if r and r.text:
                findings.extend(self._test_forms(url, r.text, marker))
        except Exception as e:
            if self.logger:
                self.logger.error(f"GET {url} failed: {str(e)}")

        # Deduplicate findings
        findings = self._deduplicate_findings(findings)
        return findings

    def _deduplicate_findings(self, findings):
        seen = set()
        unique_findings = []
        for finding in findings:
            key = (finding["url"], finding.get("param", ""), finding["type"], finding["location"])
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        return unique_findings

    def _test_forms(self, base_url: str, html: str, marker: str):
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
                    data = {i.get("name"): "test" for i in inputs if i.get("name")}
                    data[name] = payload_with_marker
                    target_url = urljoin(base_url, action)
                    time.sleep(0.5)
                    try:
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
                        if self.logger:
                            self.logger.error(f"{method} {target_url} failed: {str(e)}")
        return findings

    def _is_xss(self, text: str, marker: str) -> bool:
        soup = BeautifulSoup(text, "html.parser")
        # Search in HTML text
        if soup.find(text=re.compile(marker, re.IGNORECASE)) or soup.find(text=re.compile(unquote(marker), re.IGNORECASE)):
            return True
        # Search in attributes
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if attr.startswith("on") and (marker in value or unquote(marker) in value):
                    return True
        # Search in JSON
        try:
            data = json.loads(text)
            def search_marker(obj):
                if isinstance(obj, str):
                    if marker in obj or unquote(marker) in obj or marker in unquote(obj):
                        return True
                elif isinstance(obj, dict):
                    return any(search_marker(v) for v in obj.values())
                elif isinstance(obj, list):
                    return any(search_marker(item) for item in obj)
                return False
            if search_marker(data):
                return True
        except json.JSONDecodeError:
            pass
        return False

    def _extract_evidence(self, text: str, marker: str, context: int = 100) -> str:
        # Check HTML
        for m in [marker, unquote(marker)]:
            idx = text.find(m)
            if idx != -1:
                start = max(0, idx - context)
                end = min(len(text), idx + len(m) + context)
                return "Evidence: " + text[start:end].replace("\n", " ")
        # Check JSON
        try:
            data = json.loads(text)
            def find_marker(obj):
                if isinstance(obj, str) and (marker in obj or unquote(marker) in obj or marker in unquote(obj)):
                    return obj[:context].replace("\n", " ")
                elif isinstance(obj, dict):
                    for v in obj.values():
                        result = find_marker(v)
                        if result:
                            return result
                elif isinstance(obj, list):
                    for item in obj:
                        result = find_marker(item)
                        if result:
                            return result
                return None
            result = find_marker(data)
            if result:
                return "Evidence: " + result
        except json.JSONDecodeError:
            pass
        return "Evidence: " + text[:context].replace("\n", " ") if text else "No response content"
