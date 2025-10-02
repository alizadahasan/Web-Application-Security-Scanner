"""
Simple BFS crawler for discovering links and forms within the same domain.
This is intentionally small and conservative (no JS execution).
"""

from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import time

class Crawler:
    """Web crawler that discovers URLs and forms using breadth-first search within the same domain."""
    
    def __init__(self, http, logger, max_pages=50, delay_between_requests=0.2):
        """
        Initialize the crawler with HTTP client, logger, and configuration.
        
        Args:
            http: HTTP client for making requests
            logger: Logger instance for output
            max_pages: Maximum number of pages to crawl (prevents infinite loops)
            delay_between_requests: Delay between requests to avoid overwhelming the server
        """
        self.http = http
        self.logger = logger
        self.max_pages = max_pages
        self.delay = delay_between_requests

    def crawl(self, start_url):
        """
        Crawl the website starting from the given URL using BFS algorithm.
        
        Args:
            start_url: The URL to start crawling from
            
        Returns:
            List of tuples (url, BeautifulSoup object) for each discovered page
        """
        # Parse start URL to extract domain for same-domain constraint
        parsed_start = urlparse(start_url)
        base_domain = parsed_start.netloc
        
        # BFS queue and tracking sets
        to_visit = [start_url]  # URLs waiting to be crawled
        seen = set()            # URLs already visited
        discovered = []         # Results: (url, parsed_content) tuples

        # Continue crawling while there are URLs and we haven't hit the page limit
        while to_visit and len(seen) < self.max_pages:
            url = to_visit.pop(0)  # Get next URL from queue (FIFO)
            
            if url in seen:
                continue  # Skip if already visited
                
            seen.add(url)  # Mark as visited
            
            try:
                time.sleep(self.delay)  # Rate limiting
                r = self.http.get(url)
                
                if not r or not r.text:
                    continue  # Skip if no response or empty content
                    
                # Parse HTML content for link discovery
                soup = BeautifulSoup(r.text, "html.parser")
                discovered.append((url, soup))  # Store URL and parsed content
                
                # Find all href links in the page
                for a in soup.find_all("a", href=True):
                    href = a.get("href")
                    target = urljoin(url, href)  # Convert to absolute URL
                    p = urlparse(target)
                    
                    # Only follow same-domain links that haven't been seen
                    if (p.netloc == base_domain and 
                        target not in seen and 
                        target not in to_visit):
                        to_visit.append(target)  # Add to queue for crawling
                        
                # Note: forms are preserved in the 'soup' returned in discovered list for later analysis
                
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Crawler: failed to fetch {url}: {e}")
                continue  # Continue with next URL on error
                
        return discovered
