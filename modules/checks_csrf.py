# modules/checks_csrf.py
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import requests
import time

class CSRFScanner:
    def __init__(self, logger, http):
        self.logger = logger
        self.http = http

    def scan(self, url: str):
        findings = []
        self.logger.info("Running CSRFScanner...")
        time.sleep(1.0)  # Delay for stability
        try:
            r = self.http.get(url)
            if not r or not r.text:
                self.logger.info("No response or empty body for CSRF analysis")
                return findings
        except requests.exceptions.RequestException as e:
            self.logger.error(f"GET {url} failed: {str(e)}")
            return findings

        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            self.logger.info("No <form> tags found; checking for input-based forms...")
            inputs = soup.find_all(["input", "textarea"])
            if not inputs:
                self.logger.info("No forms or inputs found for CSRF analysis")
                return findings

        self.logger.info(f"Testing {len(forms)} form(s) for CSRF protection...")
        for form in forms:
            action = form.get("action") or url
            method = (form.get("method") or "get").upper()
            inputs = form.find_all(["input", "textarea"])
            input_names = {i.get("name") for i in inputs if i.get("name")}
            self.logger.info(f"Form {method} {urljoin(url, action)} inputs: {input_names}")
            token_found = any(
                inp.get("name") and ("csrf" in inp.get("name").lower() or "token" in inp.get("name").lower())
                for inp in inputs
            )
            if not token_found:
                self.logger.debug(f"Form {method} {urljoin(url, action)} missing CSRF token.")
                findings.append({
                    "type": "Cross-Site Request Forgery (CSRF)",
                    "location": "form",
                    "url": urljoin(url, action),
                    "method": method,
                    "param": "",  # CSRF typically has no param
                    "payload": "",
                    "evidence": f"Form at {urljoin(url, action)} lacks CSRF token",
                })
        return findings
