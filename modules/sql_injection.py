import re
import time
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import requests

BASIC_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 -- ",
    "1' OR '1'='1' -- ",
    "1' OR 1=1#",
    "1' OR 'a'='a",
    "' OR 'x'='x",
    "1' UNION SELECT NULL,NULL -- ",
]

SQL_ERRORS = [
    "SQL syntax",
    "mysql_fetch",
    "mysql_fetch_array",  # For DVWA
    "mysql_num_rows",
    "ORA-",
    "Warning: mysql",
    "You have an error in your SQL syntax",
    "PostgreSQL query failed",
    "SQLite error",
    "SequelizeDatabaseError",
    "Unknown column",
    "Invalid query",
    "SQLITE_ERROR",
    "sqlite3.OperationalError",  # For Gruyere
]

class SQLInjectionScanner:
    def __init__(self, logger, http):
        self.logger = logger
        self.http = http

    def scan(self, url: str):
        findings = []
        self.logger.info("Running SQLInjectionScanner...")
        findings.extend(self._test_query_params(url))
        r = self.http.get(url)
        if r and r.text:
            findings.extend(self._test_forms(url, r.text))
        else:
            self.logger.debug(f"No response or empty body for {url}")
        # Deduplicate findings
        findings = self._deduplicate_findings(findings)
        return findings

    def _deduplicate_findings(self, findings):
        """Remove duplicate findings, keeping the first payload per param."""
        seen = set()
        unique_findings = []
        for finding in findings:
            key = (finding["url"], finding.get("param", ""), finding["type"], finding["location"])
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        return unique_findings

    def _test_query_params(self, url: str):
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            self.logger.debug(f"No query params found in {url}")
            return findings

        baseline_resp = self.http.get(url)
        baseline_text = baseline_resp.text if baseline_resp else ""
        baseline_status = baseline_resp.status_code if baseline_resp else 200

        for param in params.keys():
            found_vuln = False
            for payload in BASIC_PAYLOADS:
                if found_vuln:
                    break
                new_params = dict(params)
                new_params[param] = payload
                new_query = urlencode(new_params, doseq=True)
                new_url = urlunparse(
                    (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
                )
                time.sleep(0.5)
                try:
                    r = self.http.get(new_url)
                    if r and r.status_code != 500 and self._is_sqli(r.text, baseline_text, baseline_status):
                        findings.append({
                            "type": "SQL Injection",
                            "location": "query",
                            "url": new_url,
                            "method": "GET",
                            "param": param,
                            "payload": payload,
                            "evidence": self._extract_evidence(r.text, len(baseline_text), len(r.text)),
                        })
                        found_vuln = True
                    else:
                        self.logger.debug(f"No SQLi detected for {new_url} with payload {payload}")
                except requests.exceptions.RequestException as e:
                    self.logger.error(f"GET {new_url} failed: {str(e)}")
                    self.logger.debug(f"No SQLi detected for {new_url} with payload {payload}")
        return findings

    def _test_forms(self, base_url: str, html: str):
        findings = []
        soup = BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            self.logger.debug("No forms found for SQLi analysis")
            return findings

        for form in forms:
            action = form.get("action") or base_url
            method = (form.get("method") or "get").upper()
            inputs = form.find_all(["input", "textarea"])
            baseline_data = {i.get("name"): "test" for i in inputs if i.get("name")}
            target_url = urljoin(base_url, action)
            self.logger.debug(f"Resolved baseline form action to {target_url}")
            baseline_resp = self.http.post(target_url, baseline_data) if method == "POST" else self.http.get(target_url, baseline_data)
            baseline_text = baseline_resp.text if baseline_resp else ""
            baseline_status = baseline_resp.status_code if baseline_resp else 200
            if not baseline_resp:
                self.logger.debug(f"Baseline request failed for {target_url}")
            else:
                self.logger.debug(f"Baseline response for {target_url}: OK")

            for inp in inputs:
                name = inp.get("name")
                if not name:
                    continue
                found_vuln = False
                for payload in BASIC_PAYLOADS:
                    if found_vuln:
                        break
                    data = {i.get("name"): "test" for i in inputs if i.get("name")}
                    data[name] = payload
                    target_url = urljoin(base_url, action)
                    self.logger.debug(f"Resolved form action to {target_url}")
                    time.sleep(0.5)
                    try:
                        r = self.http.post(target_url, data) if method == "POST" else self.http.get(target_url, data)
                        if r and r.status_code != 500 and self._is_sqli(r.text, baseline_text, baseline_status):
                            findings.append({
                                "type": "SQL Injection",
                                "location": "form",
                                "url": target_url,
                                "method": method,
                                "param": name,
                                "payload": payload,
                                "evidence": self._extract_evidence(r.text, len(baseline_text), len(r.text)),
                            })
                            found_vuln = True
                        else:
                            self.logger.debug(f"No SQLi detected for {target_url} with payload {payload}")
                    except requests.exceptions.RequestException as e:
                        self.logger.error(f"{method} {target_url} failed: {str(e)}")
                        self.logger.debug(f"No SQLi detected for {target_url} with payload {payload}")
        return findings

    def _is_sqli(self, text: str, baseline: str = "", baseline_status: int = 200) -> bool:
        lower = text.lower()
        for err in SQL_ERRORS:
            if err.lower() in lower:
                self.logger.debug(f"SQLi detected via error: {err}")
                return True
        # Re-enable length-based for blind SQLi, with stricter conditions (response longer, no error)
        if baseline and baseline_status == 200 and len(text) - len(baseline) > 100:
            self.logger.debug("SQLi detected via response length difference (blind)")
            return True
        return False

    def _extract_evidence(self, text: str, baseline_len: int = 0, response_len: int = 0, context: int = 100) -> str:
        lower = text.lower()
        for err in SQL_ERRORS:
            idx = lower.find(err.lower())
            if idx != -1:
                start = max(0, idx - context)
                end = min(len(text), idx + len(err) + context)
                return text[start:end].replace("\n", " ")
        # For blind SQLi, explain length difference
        if response_len - baseline_len > 100:
            return f"Blind SQLi detected: Response length increased by {response_len - baseline_len} bytes, indicating data dump. Sample response: {text[:context].replace('\n', ' ')}"
        return text[:context].replace("\n", " ") if text else "No response content"
