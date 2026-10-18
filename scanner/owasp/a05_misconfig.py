"""
OBSERVER — A05: Security Misconfiguration Detector
Tests for:
  - Missing or misconfigured Security Headers (CSP, X-Frame-Options, X-Content-Type-Options, etc.)
  - Directory Listing / Indexing enabled
  - Exposed environment files, version control repos, and backup configs
  - Verbose Server Error Stack Traces
"""
import re
from urllib.parse import urljoin
import requests

from core.database import Severity
from scanner.owasp.base import BaseDetector, ScanFinding
from scanner.crawler import CrawlResult


class SecurityMisconfigDetector(BaseDetector):
    category_id = "A05"
    category_name = "Security Misconfiguration"

    SECURITY_HEADERS = [
        ("Content-Security-Policy", Severity.MEDIUM, "Prevents XSS, data injection, and clickjacking by restricting resource origins."),
        ("X-Frame-Options", Severity.MEDIUM, "Protects against clickjacking attacks by forbidding framing in <iframe>."),
        ("X-Content-Type-Options", Severity.LOW, "Prevents MIME-sniffing vulnerabilities by setting 'nosniff'."),
        ("Referrer-Policy", Severity.LOW, "Controls how much referrer information should be included with requests."),
        ("Permissions-Policy", Severity.LOW, "Restricts access to browser features (camera, microphone, geolocation)."),
    ]

    COMMON_EXPOSED_FILES = [
        ("/.env", "Environment file containing database/API secrets", Severity.CRITICAL, r"DB_PASSWORD|APP_KEY|AWS_SECRET|SECRET_KEY|DATABASE_URL"),
        ("/.git/HEAD", "Git repository metadata exposed", Severity.HIGH, r"ref:\s*refs/heads/"),
        ("/.git/config", "Git configuration disclosing remote repos", Severity.HIGH, r"\[core\]|\[remote"),
        ("/web.config", "IIS Configuration file exposed", Severity.HIGH, r"<configuration>"),
        ("/phpinfo.php", "PHP Info debug dump page accessible", Severity.HIGH, r"PHP Version|phpinfo\(\)"),
        ("/server-status", "Apache Server Status monitor accessible", Severity.MEDIUM, r"Apache Server Status"),
    ]

    def run(self, crawl_result: CrawlResult) -> list[ScanFinding]:
        self.findings = []
        self.log("INFO", "[A05] Running Security Misconfiguration checks...")

        base_url = crawl_result.base_url
        self._check_missing_security_headers(crawl_result)
        self._check_exposed_files(base_url)
        self._check_directory_listing(crawl_result)
        self._check_stack_traces(crawl_result)

        return self.findings

    def _check_missing_security_headers(self, crawl_result: CrawlResult):
        """Evaluate presence of crucial HTTP security headers on main responses."""
        resp = crawl_result.responses.get(crawl_result.base_url)
        if not resp:
            try:
                resp = self.session.get(crawl_result.base_url, timeout=self.timeout, verify=False)
            except Exception:
                return

        headers_lower = {k.lower(): (k, v) for k, v in resp.headers.items()}

        for header_name, sev, explanation in self.SECURITY_HEADERS:
            h_lower = header_name.lower()
            if h_lower not in headers_lower:
                self.add_finding(
                    title=f"Missing Security Header: {header_name}",
                    severity=sev,
                    description=f"The '{header_name}' HTTP response header is missing on '{crawl_result.base_url}'. {explanation}",
                    url_affected=crawl_result.base_url,
                    evidence=f"Header '{header_name}' was not returned in the server response.",
                    cwe_id="CWE-1021" if header_name == "X-Frame-Options" else "CWE-693",
                    remediation=f"Configure web server / application headers to include '{header_name}' with appropriate directives."
                )

    def _check_exposed_files(self, base_url: str):
        """Check for publicly accessible configuration files, dotfiles, and debug endpoints."""
        for path, desc, sev, match_regex in self.COMMON_EXPOSED_FILES:
            target_url = urljoin(base_url, path)
            try:
                resp = self.session.get(target_url, timeout=self.timeout, allow_redirects=False, verify=False)
                if resp.status_code == 200 and re.search(match_regex, resp.text, re.IGNORECASE):
                    self.add_finding(
                        title=f"Exposed Sensitive File: {path}",
                        severity=sev,
                        description=f"Sensitive file or diagnostic interface ({desc}) is directly accessible at '{target_url}'.",
                        url_affected=target_url,
                        evidence=resp.text[:300],
                        cwe_id="CWE-552",
                        remediation=f"Restrict or block web access to '{path}' and all internal configuration files."
                    )
            except Exception as e:
                self.log("DEBUG", f"[A05] Error probing {target_url}: {e}")

    def _check_directory_listing(self, crawl_result: CrawlResult):
        """Check if directory listing / autoindexing is enabled."""
        for url in list(crawl_result.discovered_urls)[:5]:
            resp = crawl_result.responses.get(url)
            if resp and resp.status_code == 200:
                text_lower = resp.text.lower()
                if any(kw in text_lower for kw in ["index of /", "directory listing for", "parent directory"]):
                    self.add_finding(
                        title="Directory Listing Enabled",
                        severity=Severity.MEDIUM,
                        description=f"Directory browsing/listing is enabled on '{url}'. Attackers can discover sensitive files and directory layouts.",
                        url_affected=url,
                        evidence="Found 'Index of /' or directory listing title in response body.",
                        cwe_id="CWE-548",
                        remediation="Disable directory browsing in web server configuration (e.g. 'Options -Indexes' in Apache or 'autoindex off;' in Nginx)."
                    )

    def _check_stack_traces(self, crawl_result: CrawlResult):
        """Check for verbose stack traces and debug dumps in crawled error responses."""
        stack_patterns = [
            ("Java Stack Trace", r"at [a-zA-Z0-9_\.]+\([a-zA-Z0-9_\.]+\.java:\d+\)"),
            ("Python Traceback", r"Traceback \(most recent call last\):"),
            ("PHP Fatal Error", r"(?:Fatal error|Parse error):\s+.*in\s+.*\.php\s+on\s+line\s+\d+"),
            ("ASP.NET Exception", r"Server Error in '.*' Application\..*Exception Details:"),
            ("Node.js Error Dump", r"at [a-zA-Z0-9_\.]+\s+\([a-zA-Z0-9_\.\/\\:\d]+\)"),
        ]

        for url, resp in crawl_result.responses.items():
            if resp.status_code >= 400:
                for tech, pattern in stack_patterns:
                    match = re.search(pattern, resp.text)
                    if match:
                        self.add_finding(
                            title=f"Verbose Error Stack Trace Disclosed ({tech})",
                            severity=Severity.LOW,
                            description=(
                                f"The application returns a verbose error message with a full {tech} stack trace at '{url}'. "
                                f"This discloses internal source paths, software versions, and architectural details."
                            ),
                            url_affected=url,
                            evidence=match.group(0)[:300],
                            cwe_id="CWE-209",
                            remediation="Implement custom generic error pages for 4xx/5xx responses and log detailed error traces to secure server-side logs."
                        )
                        break
