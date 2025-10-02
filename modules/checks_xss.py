import uuid
import json
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin, unquote
from bs4 import BeautifulSoup
from modules.init import Logger

class XSSScanner:
    def __init__(self, logger=None, http=None, delay_between_requests=0.5):
        self.logger = logger if logger is not None else Logger(verbosity=0)
        self.http = http
        self.delay = delay_between_requests
        # payloads try multiple contexts; marker placeholder "XSSMARKER"
        self.payloads = [
            "XSSMARKER",
            "<script>XSSMARKER</script>",
            "<img src=x onerror=XSSMARKER>",
            "\"> <svg/onload=XSSMARKER>",
            "<svg><script>XSSMARKER</script>",
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

        # Test forms
        try:
            r = self.http.get(url, params=None)
            if r and r.text:
                findings.extend(self._test_forms(url, r.text, marker))
        except Exception as e:
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
                    time.sleep(self.delay)
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
                        self.logger.error(f"{method} {target_url} failed: {str(e)}")
        return findings

    def _is_xss(self, text: str, marker: str) -> bool:
        """
        Return True only if the marker appears in a context that can execute:
        - Inside a <script> tag content
        - As part of a tag's attribute value that begins with 'on' (e.g., onerror)
        - As an actual parsed tag/content (i.e., BeautifulSoup parsed a tag containing marker)
        If marker only appears as plain/escaped text (e.g., inside <pre> or as &lt;script&gt;)
        we do NOT consider it exploitable XSS.
        """
        if not text:
            return False
        soup = BeautifulSoup(text, "html.parser")

        # 1) Check script tags content
        for script in soup.find_all("script"):
            try:
                if script.string and marker in script.string:
                    self.logger.debug("XSS detected in <script> content")
                    return True
            except Exception:
                continue

        # 2) Check attributes (on* handlers or javascript: src/href)
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                val_str = " ".join(value) if isinstance(value, list) else str(value)
                if val_str and (marker in val_str or marker in unquote(val_str)):
                    if attr.lower().startswith("on") or "javascript:" in val_str.lower():
                        self.logger.debug(f"XSS detected in attribute {attr}")
                        return True

        # 3) If the payload created an actual new tag that contains the marker (e.g., <img ...>)
        for tag in soup.find_all(True):
            try:
                if tag.string and marker in tag.string:
                    if tag.name.lower() in ("script", "iframe", "img", "svg", "object", "embed", "body"):
                        self.logger.debug(f"XSS detected in tag content <{tag.name}>")
                        return True
            except Exception:
                continue

        # 4) JSON responses where marker appears in a value (API reflection)
        try:
            data = json.loads(text)
            def search_marker(obj):
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

        # If marker appears only as raw text but wasn't parsed into tags/attributes above, treat as non-executable
        if marker in text or unquote(marker) in text:
            self.logger.debug("Marker found but not in executable context (treated as safe reflection)")
            return False

        return False

    def _extract_evidence(self, text: str, marker: str, context: int = 200) -> str:
        # Try to return a safe snippet showing the marker context
        if not text:
            return "No response content"
        idx = text.find(marker)
        if idx != -1:
            start = max(0, idx - context)
            end = min(len(text), idx + len(marker) + context)
            snippet = text[start:end].replace("\n", " ").replace("\r", " ")
            return f"Evidence: {snippet}"
        # fallback
        return "Evidence: " + text[:context].replace("\n", " ").replace("\r", " ")
