import argparse
import os
from datetime import datetime
from modules.init import Logger
from modules.extractor import HttpClient
from modules.reporter import Report
from modules.sql_injection import SQLInjectionScanner
from modules.checks_xss import XSSScanner
from modules.checks_csrf import CSRFScanner

def parse_args():
    parser = argparse.ArgumentParser(description="Web Application Security Scanner")
    parser.add_argument("--url", required=True, help="Target URL to scan")
    parser.add_argument("--modules", default="sqli,xss,csrf", help="Comma-separated modules to run (sqli,xss,csrf)")
    parser.add_argument("--cookies", help="Cookies for authenticated requests (e.g., 'key=value;key2=value2')")
    parser.add_argument("--outdir", default="reports", help="Output directory for reports")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbosity level (e.g., -v, -vv)")
    return parser.parse_args()

def deduplicate_findings(findings):
    """Remove duplicate findings based on URL, param, type, and location."""
    seen = set()
    unique_findings = []
    for finding in findings:
        key = (finding["url"], finding.get("param", ""), finding["type"], finding["location"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)
    return unique_findings

def main():
    args = parse_args()
    logger = Logger(args.verbose)
    http = HttpClient(cookies=args.cookies)
    report = Report(args.url, args.outdir)  # Pass both url and outdir

    logger.info(f"Starting scan against: {args.url}")
    findings = []

    scanners = {
        "sqli": SQLInjectionScanner,
        "xss": XSSScanner,
        "csrf": CSRFScanner
    }

    modules = args.modules.split(",")
    for module in modules:
        if module in scanners:
            scanner = scanners[module](logger, http)
            module_findings = scanner.scan(args.url)
            findings.extend(module_findings)
            logger.info(f"{scanner.__class__.__name__} completed: {len(module_findings)} finding(s).")
        else:
            logger.warn(f"Unknown module: {module}")

    # Deduplicate findings
    findings = deduplicate_findings(findings)

    # Summarize findings by type
    if findings:
        sqli_count = sum(1 for f in findings if f["type"] == "SQL Injection")
        xss_count = sum(1 for f in findings if f["type"] == "Cross-Site Scripting (XSS)")
        csrf_count = sum(1 for f in findings if f["type"] == "Cross-Site Request Forgery (CSRF)")
        logger.info(f"Scan complete. Summary: {sqli_count} SQL Injection, {xss_count} XSS, {csrf_count} CSRF findings.")
    else:
        logger.info("Scan complete. No vulnerabilities found.")

    # Add findings to report
    for finding in findings:
        report.add_finding(finding)

    # Ensure output directory exists
    os.makedirs(args.outdir, exist_ok=True)
    # Generate report filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(args.outdir, f"report_{timestamp}.txt")
    # Write report
    report.write_text(args.url, timestamp)
    logger.success(f"Detailed findings saved to: {report_file}")

    # Exit with code 1 if findings exist
    if findings:
        exit(1)
    exit(0)

if __name__ == "__main__":
    main()
