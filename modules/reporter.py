from datetime import datetime
import os

class Report:
    """Handles generation and formatting of security scan reports."""
    
    def __init__(self, url, outdir="reports"):
        """
        Initialize report with target URL and output directory.
        
        Args:
            url: The URL that was scanned
            outdir: Directory where reports will be saved
        """
        self.findings = []  # List to store all vulnerability findings
        self.url = url
        self.outdir = outdir
        
        # Create output directory if it doesn't exist
        if not os.path.exists(outdir):
            os.makedirs(outdir)

    def add_finding(self, finding):
        """Add a vulnerability finding to the report."""
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
        """
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
            print(f"[ERROR] Failed to write report to {filename}: {str(e)}")
            return None  # Return None on failure
