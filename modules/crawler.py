"""
Simple BFS crawler for discovering links and forms within the same domain.
This is intentionally small and conservative (no JS execution).
"""

from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import time

class Crawler:
    def __init__(self, http, logger, max_pages=50, delay_between_requests=0.2):
        self.http = http
        self.logger = logger
        self.max_pages = max_pages
        self.delay = delay_between_requests

    def crawl(self, start_url):
        parsed_start = urlparse(start_url)
        base_domain = parsed_start.netloc
        to_visit = [start_url]
        seen = set()
        discovered = []

        while to_visit and len(seen) < self.max_pages:
            url = to_visit.pop(0)
            if url in seen:
                continue
            seen.add(url)
            try:
                time.sleep(self.delay)
                r = self.http.get(url)
                if not r or not r.text:
                    continue
                soup = BeautifulSoup(r.text, "html.parser")
                discovered.append((url, soup))
                # find all href links
                for a in soup.find_all("a", href=True):
                    href = a.get("href")
                    target = urljoin(url, href)
                    p = urlparse(target)
                    if p.netloc == base_domain and target not in seen and target not in to_visit:
                        to_visit.append(target)
                # Note: forms are preserved in the 'soup' returned in discovered list for later analysis
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Crawler: failed to fetch {url}: {e}")
                continue

        return discovered
