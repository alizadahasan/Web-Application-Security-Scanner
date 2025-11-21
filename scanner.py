import argparse
import os
from datetime import datetime
from modules.init import Logger
from modules.extractor import HttpClient
from modules.reporter import Report
from modules.sql_injection import SQLInjectionScanner
from modules.checks_xss import XSSScanner
from modules.checks_csrf import CSRFScanner
from modules.crawler import Crawler

def parse_args():
    """Parse command line arguments for the security scanner."""
    parser = argparse.ArgumentParser(description="Web Application Security Scanner")
    parser.add_argument("--url", required=True, help="Target URL to scan")
    parser.add_argument("--modules", default="sqli,xss,csrf", help="Comma-separated modules to run (sqli,xss,csrf,all)")
    parser.add_argument("--cookies", help="Cookies for authenticated requests (e.g., 'key=value;key2=value2')")
    parser.add_argument("--outdir", default="reports", help="Output directory for reports")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbosity level (e.g., -v, -vv)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests (seconds)")
    # Add crawl option
    parser.add_argument("--crawl", action="store_true", help="Enable crawling to discover URLs before scanning")
    parser.add_argument("--max-pages", type=int, default=50, help="Maximum pages to crawl (default: 50)")
    return parser.parse_args()

def deduplicate_findings(findings):
    """Remove duplicate findings based on URL, param, type, and location."""
    seen = set()
    unique_findings = []
    for finding in findings:
        # Create unique key from finding attributes to identify duplicates
        key = (finding["url"], finding.get("param", ""), finding["type"], finding["location"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)
    return unique_findings

def get_modules_to_scan(modules_arg):
    """Parse modules argument and return list of modules to scan."""
    modules_list = [m.strip() for m in modules_arg.split(",") if m.strip()]
    
    # Handle "all" keyword
    if "all" in modules_list:
        return ["sqli", "xss", "csrf"]
    
    return modules_list

def main():
    """Main entry point for the security scanner application."""
    # Parse command line arguments and initialize components
    args = parse_args()
    logger = Logger(args.verbose)
    http = HttpClient(cookies=args.cookies)
    report = Report(args.url, args.outdir)
    
    logger.info(f"Starting scan against: {args.url}")
    findings = []
    
    # Scanner factory - maps module names to scanner classes
    scanners = {
        "sqli": lambda: SQLInjectionScanner(logger, http, delay_between_requests=args.delay),
        "xss": lambda: XSSScanner(logger, http, delay_between_requests=args.delay),
        "csrf": lambda: CSRFScanner(logger, http, delay_between_requests=args.delay)
    }
    
    # Parse modules (handle "all" keyword)
    modules_list = get_modules_to_scan(args.modules)
    logger.info(f"Modules to run: {', '.join(modules_list)}")
    
    # Determine which URLs to scan
    urls_to_scan = [args.url]
    
    # If crawl is enabled, discover URLs first
    if args.crawl:
        logger.info(f"Crawling enabled. Discovering URLs (max: {args.max_pages} pages)...")
        crawler = Crawler(http, logger, max_pages=args.max_pages, delay_between_requests=args.delay)
        discovered = crawler.crawl(args.url)
        urls_to_scan = [url for url, soup in discovered]
        logger.info(f"Crawler discovered {len(urls_to_scan)} URLs to scan")
    
    # Process each requested module for each URL
    for url in urls_to_scan:
        logger.info(f"Scanning URL: {url}")
        for module in modules_list:
            if module in scanners:
                scanner = scanners[module]()
                module_findings = scanner.scan(url)
                findings.extend(module_findings)
                if module_findings:
                    logger.info(f"{scanner.__class__.__name__} found {len(module_findings)} vulnerability(s) in {url}")
            else:
                logger.warn(f"Unknown module: {module}")
    
    # Deduplicate findings to avoid reporting the same vulnerability multiple times
    findings = deduplicate_findings(findings)
    
    # Generate summary statistics
    if findings:
        sqli_count = sum(1 for f in findings if f["type"] == "SQL Injection")
        xss_count = sum(1 for f in findings if f["type"] == "Cross-Site Scripting (XSS)")
        csrf_count = sum(1 for f in findings if f["type"] == "Cross-Site Request Forgery (CSRF)")
        logger.info(f"Scan complete. Summary: {sqli_count} SQL Injection, {xss_count} XSS, {csrf_count} CSRF findings.")
    else:
        logger.info("Scan complete. No vulnerabilities found.")
    
    # Add all findings to the report
    for finding in findings:
        report.add_finding(finding)
    
    # Ensure output directory exists and generate report
    os.makedirs(args.outdir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(args.outdir, f"report_{timestamp}.txt")
    
    # Write the report file
    written = report.write_text(args.url, timestamp)
    if written:
        logger.success(f"Detailed findings saved to: {written}")
    else:
        logger.error("Failed to write detailed report")
    
    # Exit with code 1 if vulnerabilities found, 0 if clean
    exit(1 if findings else 0)

if __name__ == "__main__":
    main()
