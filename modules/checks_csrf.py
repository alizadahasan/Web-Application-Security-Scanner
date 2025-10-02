from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time
from modules.init import Logger

# Common token keywords (extendable)
TOKEN_KEYWORDS = [
    "csrf", "token", "authenticity_token", "xsrf", "_token", "_xsrf", "nonce", "anticsrf", "__requestverificationtoken"
]

class CSRFScanner:
    def __init__(self, logger=None, http=None, delay_between_requests=1.0):
        # Use provided logger or fallback to modules.init.Logger
        self.logger = logger if logger is not None else Logger(verbosity=0)
        self.http = http
        self.delay = delay_between_requests

    def scan(self, url: str):
        findings = []
        self.logger.info("Running CSRFScanner...")
        time.sleep(self.delay)  # Delay for stability
        try:
            r = self.http.get(url)
            if not r or not r.text:
                self.logger.info("No response or empty body for CSRF analysis")
                return findings
        except Exception as e:
            self.logger.error(f"GET {url} failed: {e}")
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

            # Detect candidate token fields
            candidate_tokens = []
            for inp in inputs:
                name = inp.get("name", "")
                if not name:
                    continue
                lower = name.lower()
                if any(tok in lower for tok in TOKEN_KEYWORDS):
                    candidate_tokens.append(name)

            if not candidate_tokens:
                # No obvious token fields
                self.logger.debug(f"Form {method} {urljoin(url, action)} missing obvious CSRF token.")
                findings.append({
                    "type": "Cross-Site Request Forgery (CSRF)",
                    "location": "form",
                    "url": urljoin(url, action),
                    "method": method,
                    "param": "",
                    "payload": "",
                    "evidence": f"Form at {urljoin(url, action)} lacks an obvious CSRF token",
                })
                continue

            # If candidate tokens exist, attempt to validate enforcement (only for POST)
            if method == "POST":
                target = urljoin(url, action)
                # Build baseline data: include all named inputs using their existing 'value' attributes when possible
                baseline_data = {}
                for inp in inputs:
                    n = inp.get("name")
                    if not n:
                        continue
                    val = inp.get("value") or "test"
                    baseline_data[n] = val
                # Submit baseline (with token)
                try:
                    time.sleep(self.delay)
                    resp_with = self.http.post(target, data=baseline_data)
                except Exception as e:
                    self.logger.debug(f"Baseline post failed for CSRF test: {e}")
                    resp_with = None

                # Remove token fields and re-submit
                data_without = dict(baseline_data)
                for t in candidate_tokens:
                    data_without.pop(t, None)

                try:
                    time.sleep(self.delay)
                    resp_without = self.http.post(target, data=data_without)
                except Exception as e:
                    self.logger.debug(f"Post without token failed: {e}")
                    resp_without = None

                # If server rejects without token (different status or significant body change), token enforced
                protected = False
                if resp_with and resp_without:
                    if resp_with.status_code != resp_without.status_code:
                        protected = True
                    else:
                        b1 = (resp_with.text or "").strip()
                        b2 = (resp_without.text or "").strip()
                        if abs(len(b1) - len(b2)) > 50:
                            protected = True
                        elif b1 != b2:
                            protected = True

                if not protected:
                    findings.append({
                        "type": "Cross-Site Request Forgery (CSRF)",
                        "location": "form",
                        "url": target,
                        "method": method,
                        "param": "",
                        "payload": "",
                        "evidence": f"Form at {target} contains token field(s) {candidate_tokens} but token appears not enforced",
                    })
                else:
                    self.logger.debug(f"Form at {target} appears protected by token(s): {candidate_tokens}")
            else:
                # For GET forms we only flag absence of tokens (can't reliably confirm enforcement)
                self.logger.debug(f"GET form at {urljoin(url, action)} token candidates: {candidate_tokens}")
        return findings
