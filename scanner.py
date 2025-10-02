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
    parser.add_argument("--modules", default="sqli,xss,csrf", help="Comma-separated modules to run (sqli,xss,csrf)")
    parser.add_argument("--cookies", help="Cookies for authenticated requests (e.g., 'key=value;key2=value2')")
    parser.add_argument("--outdir", default="reports", help="Output directory for reports")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbosity level (e.g., -v, -vv)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests (seconds)")
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
    
    # Process each requested module
    modules_list = [m.strip() for m in args.modules.split(",") if m.strip()]
    for module in modules_list:
        if module in scanners:
            scanner = scanners[module]()
            module_findings = scanner.scan(args.url)
            findings.extend(module_findings)
            logger.info(f"{scanner.__class__.__name__} completed: {len(module_findings)} finding(s).")
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
