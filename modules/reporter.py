from datetime import datetime
import os

class Report:
    def __init__(self, url, outdir="reports"):
        self.findings = []
        self.url = url
        self.outdir = outdir
        if not os.path.exists(outdir):
            os.makedirs(outdir)

    def add_finding(self, finding):
        self.findings.append(finding)

    def write_text(self, url, timestamp):
        filename = os.path.join(self.outdir, f"report_{timestamp}.txt")
        try:
            with open(filename, "w") as f:
                f.write("=" * 50 + "\n")
                f.write(f"Scan Report for {url}\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("-" * 50 + "\n")
                f.write("Summary:\n")
                f.write(f"Total Findings: {len(self.findings)}\n")
                f.write(f"SQL Injection: {sum(1 for x in self.findings if x['type'] == 'SQL Injection')}\n")
                f.write(f"Cross-Site Scripting (XSS): {sum(1 for x in self.findings if x['type'] == 'Cross-Site Scripting (XSS)')}\n")
                f.write(f"Cross-Site Request Forgery (CSRF): {sum(1 for x in self.findings if x['type'] == 'Cross-Site Request Forgery (CSRF)')}\n")
                f.write("=" * 50 + "\n\n")
                if not self.findings:
                    f.write("No vulnerabilities found.\n")
                for i, finding in enumerate(self.findings, 1):
                    f.write(f"[{finding['type']}] Finding {i}\n")
                    f.write(f"Location : {finding.get('location', '')}\n")
                    f.write(f"URL      : {finding.get('url', '')}\n")
                    f.write(f"Method   : {finding.get('method', '')}\n")
                    f.write(f"Parameter: {finding.get('param', '')}\n")
                    f.write(f"Payload  : {finding.get('payload', '')}\n")
                    f.write(f"Evidence : {finding.get('evidence', '')}\n")
                    f.write("-" * 50 + "\n")
            if not os.path.exists(filename):
                raise OSError("Failed to create report file")
            return filename
        except OSError as e:
            print(f"[ERROR] Failed to write report to {filename}: {str(e)}")
            return None
