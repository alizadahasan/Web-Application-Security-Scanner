"""
Web Application Security Scanner - Modules Package

This package contains the core scanning modules for vulnerability detection.

Modules:
    - init: Logger configuration and utility functions
    - extractor: HTTP client with session management
    - reporter: Report generation and formatting
    - sql_injection: SQL injection vulnerability detection
    - checks_xss: Cross-Site Scripting vulnerability detection
    - checks_csrf: Cross-Site Request Forgery vulnerability detection
    - crawler: Web crawler for URL discovery
"""

from modules.init import Logger
from modules.extractor import HttpClient
from modules.reporter import Report
from modules.sql_injection import SQLInjectionScanner
from modules.checks_xss import XSSScanner
from modules.checks_csrf import CSRFScanner
from modules.crawler import Crawler

__all__ = [
    "Logger",
    "HttpClient",
    "Report",
    "SQLInjectionScanner",
    "XSSScanner",
    "CSRFScanner",
    "Crawler",
]

__version__ = "1.0.0"
