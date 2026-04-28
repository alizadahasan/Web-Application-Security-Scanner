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
        if not cookies:  # Handle None or empty string
            return cookie_dict
        for cookie in cookies.split(";"):
            cookie = cookie.strip()
            if "=" in cookie:
                key, value = cookie.split("=", 1)
                cookie_dict[key.strip()] = value.strip()
        return cookie_dict

    def get(self, url, params=None, retries=2, backoff_factor=2):
        """Perform GET request with retries and exponential backoff."""
        for attempt in range(retries):
            try:
                response = self.session.get(url, params=params, timeout=self.timeout)
                # Do NOT raise for status to allow scanning of 500 responses
                return response
            except requests.exceptions.Timeout as e:
                if attempt < retries - 1:
                    sleep_time = backoff_factor ** attempt
                    time.sleep(sleep_time)
                    continue
                raise requests.exceptions.RequestException(f"GET request timed out after {retries} retries: {str(e)}") from e
            except requests.exceptions.ConnectionError as e:
                if attempt < retries - 1:
                    sleep_time = backoff_factor ** attempt
                    time.sleep(sleep_time)
                    continue
                raise requests.exceptions.RequestException(f"Connection error on GET {url}: {str(e)}") from e
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
        if data is None:
            data = {}
        
        for attempt in range(retries):
            try:
                response = self.session.post(url, data=data, timeout=self.timeout)
                # Do NOT raise for status to allow scanning of 500 responses
                return response
            except requests.exceptions.Timeout as e:
                if attempt < retries - 1:
                    sleep_time = backoff_factor ** attempt
                    time.sleep(sleep_time)
                    continue
                raise requests.exceptions.RequestException(f"POST request timed out after {retries} retries: {str(e)}") from e
            except requests.exceptions.ConnectionError as e:
                if attempt < retries - 1:
                    sleep_time = backoff_factor ** attempt
                    time.sleep(sleep_time)
                    continue
                raise requests.exceptions.RequestException(f"Connection error on POST {url}: {str(e)}") from e
            except requests.exceptions.RequestException as e:
                if attempt < retries - 1:
                    sleep_time = backoff_factor ** attempt
                    time.sleep(sleep_time)
                    continue
                self.session.close()
                raise e
        return None
