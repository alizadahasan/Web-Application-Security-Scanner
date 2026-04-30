from datetime import datetime
import os
import json

class FindingValidator:
    """Validates vulnerability finding dictionaries."""
    
    REQUIRED_FIELDS = ["type", "url", "method", "param", "payload", "evidence", "location"]
    ALLOWED_TYPES = ["SQL Injection", "Cross-Site Scripting (XSS)", "Cross-Site Request Forgery (CSRF)"]
    ALLOWED_LOCATIONS = ["query", "form"]
    ALLOWED_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    
    @classmethod
    def validate(cls, finding):
        """
        Validate a finding dictionary.
        
        Args:
            finding: Dictionary containing vulnerability finding
            
        Returns:
            True if valid
            
        Raises:
            ValueError: If validation fails with descriptive message
            TypeError: If finding is not a dictionary
        """
        if not isinstance(finding, dict):
            raise TypeError(f"Finding must be a dictionary, got {type(finding).__name__}")
        
        # Check all required fields are present
        missing_fields = [f for f in cls.REQUIRED_FIELDS if f not in finding]
        if missing_fields:
            raise ValueError(f"Finding missing required fields: {', '.join(missing_fields)}")
        
        # Validate field types
        if not isinstance(finding["type"], str) or not finding["type"]:
            raise ValueError("Field 'type' must be a non-empty string")
        
        if not isinstance(finding["url"], str) or not finding["url"]:
            raise ValueError("Field 'url' must be a non-empty string")
        
        if not isinstance(finding["method"], str) or not finding["method"]:
            raise ValueError("Field 'method' must be a non-empty string")
        
        if not isinstance(finding["location"], str) or not finding["location"]:
            raise ValueError("Field 'location' must be a non-empty string")
        
        # param, payload, and evidence can be empty strings but must be strings
        if not isinstance(finding["param"], str):
            raise ValueError("Field 'param' must be a string")
        
        if not isinstance(finding["payload"], str):
            raise ValueError("Field 'payload' must be a string")
        
        if not isinstance(finding["evidence"], str):
            raise ValueError("Field 'evidence' must be a string")
        
        # Validate field values against allowed sets
        if finding["type"] not in cls.ALLOWED_TYPES:
            raise ValueError(
                f"Field 'type' must be one of {cls.ALLOWED_TYPES}, got '{finding['type']}'"
            )
        
        if finding["location"] not in cls.ALLOWED_LOCATIONS:
            raise ValueError(
                f"Field 'location' must be one of {cls.ALLOWED_LOCATIONS}, got '{finding['location']}'"
            )
        
        if finding["method"] not in cls.ALLOWED_METHODS:
            raise ValueError(
                f"Field 'method' must be one of {cls.ALLOWED_METHODS}, got '{finding['method']}'"
            )
        
        # Validate URL format (basic check)
        if not (finding["url"].startswith("http://") or finding["url"].startswith("https://")):
            raise ValueError(f"Field 'url' must start with http:// or https://, got '{finding['url']}'")
        
        return True


class Report:
    """Handles generation and formatting of security scan reports."""
    
    def __init__(self, url, outdir="reports"):
        """
        Initialize report with target URL and output directory.
        
        Args:
            url: The URL that was scanned
            outdir: Directory where reports will be saved
            
        Raises:
            ValueError: If url is invalid
            TypeError: If url or outdir are not strings
        """
        if not isinstance(url, str) or not url:
            raise TypeError("URL must be a non-empty string")
        
        if not isinstance(outdir, str) or not outdir:
            raise TypeError("Output directory must be a non-empty string")
        
        if not (url.startswith("http://") or url.startswith("https://")):
            raise ValueError(f"URL must start with http:// or https://, got '{url}'")
        
        self.findings = []  # List to store all vulnerability findings
        self.url = url
        self.outdir = outdir
        
        # Create output directory if it doesn't exist
        try:
            if not os.path.exists(outdir):
                os.makedirs(outdir)
        except OSError as e:
            raise OSError(f"Failed to create output directory '{outdir}': {str(e)}") from e

    def add_finding(self, finding):
        """
        Add a vulnerability finding to the report.
        
        Args:
            finding: Dictionary containing vulnerability details
            
        Raises:
            ValueError: If finding is invalid
            TypeError: If finding is not a dictionary
        """
        # Validate the finding before adding
        FindingValidator.validate(finding)
        self.findings.append(finding)

    def _sanitize_evidence(self, evidence, maxlen=4000):
        """
        Sanitize evidence text for safe display in reports.
        
        Args:
            evidence: Raw evidence text to sanitize
            maxlen: Maximum length before truncation
            
        Returns:
            Safe, sanitized evidence string
        """
        if not evidence:
            return "No response content"
        
        # Collapse whitespace and strip control characters
        safe = " ".join(evidence.split())
        
        # Escape angle brackets to prevent accidental HTML interpretation
        safe = safe.replace("<", "&lt;").replace(">", "&gt;")
        
        # Truncate if too long to maintain readable reports
        if len(safe) > maxlen:
            return safe[:maxlen] + " ...[truncated]"
            
        return safe

    def write_text(self, url, timestamp):
        """
        Write a comprehensive text report of all findings.
        
        Args:
            url: The scanned URL
            timestamp: Timestamp for report filename
            
        Returns:
            Filename if successful, None if failed
            
        Raises:
            TypeError: If url or timestamp are not strings
            ValueError: If timestamp format is invalid
        """
        if not isinstance(url, str) or not url:
            raise TypeError("URL must be a non-empty string")
        
        if not isinstance(timestamp, str) or not timestamp:
            raise TypeError("Timestamp must be a non-empty string")
        
        filename = os.path.join(self.outdir, f"report_{timestamp}.txt")
        
        try:
            with open(filename, "w", encoding="utf-8") as f:
                # Report header with scan information
                f.write("=" * 50 + "\n")
                f.write(f"Scan Report for {url}\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("-" * 50 + "\n")
                
                # Summary section with vulnerability counts
                f.write("Summary:\n")
                f.write(f"Total Findings: {len(self.findings)}\n")
                f.write(f"SQL Injection: {sum(1 for x in self.findings if x['type'] == 'SQL Injection')}\n")
                f.write(f"Cross-Site Scripting (XSS): {sum(1 for x in self.findings if x['type'] == 'Cross-Site Scripting (XSS)')}\n")
                f.write(f"Cross-Site Request Forgery (CSRF): {sum(1 for x in self.findings if x['type'] == 'Cross-Site Request Forgery (CSRF)')}\n")
                f.write("=" * 50 + "\n\n")
                
                # Detailed findings section
                if not self.findings:
                    f.write("No vulnerabilities found.\n")
                    
                for i, finding in enumerate(self.findings, 1):
                    f.write(f"[{finding['type']}] Finding {i}\n")
                    f.write(f"Location : {finding.get('location', '')}\n")
                    f.write(f"URL      : {finding.get('url', '')}\n")
                    f.write(f"Method   : {finding.get('method', '')}\n")
                    f.write(f"Parameter: {finding.get('param', '')}\n")
                    f.write(f"Payload  : {finding.get('payload', '')}\n")
                    
                    # Sanitize evidence before writing to prevent issues
                    evidence = self._sanitize_evidence(finding.get('evidence', ''))
                    f.write(f"Evidence : {evidence}\n")
                    f.write("-" * 50 + "\n")
                    
            return filename  # Return filename on success
            
        except OSError as e:
            raise OSError(f"Failed to write report to {filename}: {str(e)}") from e

    def write_json(self, url, timestamp):
        """
        Write findings as JSON for machine parsing.
        
        Args:
            url: The scanned URL
            timestamp: Timestamp for report filename
            
        Returns:
            Filename if successful, None if failed
            
        Raises:
            TypeError: If url or timestamp are not strings
            ValueError: If timestamp format is invalid
        """
        if not isinstance(url, str) or not url:
            raise TypeError("URL must be a non-empty string")
        
        if not isinstance(timestamp, str) or not timestamp:
            raise TypeError("Timestamp must be a non-empty string")
        
        filename = os.path.join(self.outdir, f"report_{timestamp}.json")
        
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump({
                    "url": url,
                    "timestamp": timestamp,
                    "total_findings": len(self.findings),
                    "findings": self.findings
                }, f, indent=2, ensure_ascii=False)
            
            return filename
            
        except (OSError, TypeError) as e:
            raise OSError(f"Failed to write JSON report to {filename}: {str(e)}") from e

    def get_summary(self):
        """
        Get a summary of findings by type.
        
        Returns:
            Dictionary with counts of each vulnerability type
        """
        return {
            "total": len(self.findings),
            "sqli": sum(1 for f in self.findings if f["type"] == "SQL Injection"),
            "xss": sum(1 for f in self.findings if f["type"] == "Cross-Site Scripting (XSS)"),
            "csrf": sum(1 for f in self.findings if f["type"] == "Cross-Site Request Forgery (CSRF)")
        }
