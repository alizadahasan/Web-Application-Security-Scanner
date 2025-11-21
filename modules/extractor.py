import requests
import time

class HttpClient:
    def __init__(self, cookies=None, timeout=5):
        self.session = requests.Session()
        self.timeout = timeout
        if cookies:
            self.session.cookies.update(self._parse_cookies(cookies))

    def _parse_cookies(self, cookies):
        """Parse cookies string into dictionary."""
        cookie_dict = {}
        for cookie in cookies.split(";"):
            if "=" in cookie:
                key, value = cookie.strip().split("=", 1)
                cookie_dict[key] = value
        return cookie_dict

    def get(self, url, params=None, retries=2, backoff_factor=2):
        """Perform GET request with retries and exponential backoff."""
        for attempt in range(retries):
            try:
                response = self.session.get(url, params=params, timeout=self.timeout)
                # Do NOT raise for status to allow scanning of 500 responses
                return response
            except requests.exceptions.RequestException as e:
                if attempt < retries - 1:
                    sleep_time = backoff_factor ** attempt
                    time.sleep(sleep_time)
                    continue
                self.session.close()
                raise e
        return None

    def post(self, url, data=None, retries=2, backoff_factor=2):
        """Perform POST request with retries and exponential backoff."""
        for attempt in range(retries):
            try:
                response = self.session.post(url, data=data, timeout=self.timeout)
                # Do NOT raise for status
                return response
            except requests.exceptions.RequestException as e:
                if attempt < retries - 1:
                    sleep_time = backoff_factor ** attempt
                    time.sleep(sleep_time)
                    continue
                self.session.close()
                raise e
        return None
