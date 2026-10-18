"""
OBSERVER — A06: Vulnerable and Outdated Components Detector
Tests for:
  - Disclosed Server and Framework version headers (Server, X-Powered-By)
  - Outdated client-side JavaScript libraries with known CVEs (jQuery, Bootstrap, Angular, Lodash)
"""
import re
from urllib.parse import urlparse
import requests

from core.database import Severity
from scanner.owasp.base import BaseDetector, ScanFinding
from scanner.crawler import CrawlResult


class VulnerableComponentsDetector(BaseDetector):
    category_id = "A06"
    category_name = "Vulnerable and Outdated Components"

    # Known vulnerable JS library version ranges
    VULNERABLE_JS_LIBS = [
        ("jQuery", r"jquery[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js", "3.5.0", "CVE-2020-11022 / CVE-2020-11023 (Cross-Site Scripting via htmlPrefilter)"),
        ("Bootstrap", r"bootstrap[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js", "4.3.1", "CVE-2019-8331 (XSS in tooltip/popover data-template)"),
        ("AngularJS", r"angular[.-](1\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js", "1.8.0", "Legacy AngularJS with multiple sandbox bypass & XSS issues"),
        ("Lodash", r"lodash[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js", "4.17.21", "CVE-2021-23337 / CVE-2020-8203 (Command Injection & Prototype Pollution)"),
    ]

    def run(self, crawl_result: CrawlResult) -> list[ScanFinding]:
        self.findings = []
        self.log("INFO", "[A06] Running Vulnerable Components checks...")

        self._check_version_headers(crawl_result)
        self._check_script_libraries(crawl_result)

        return self.findings

    def _check_version_headers(self, crawl_result: CrawlResult):
        """Check for banner version disclosure in Server / X-Powered-By headers."""
        headers_checked = set()
        for url, resp in crawl_result.responses.items():
            for h in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]:
                val = resp.headers.get(h)
                if val and (h, val) not in headers_checked:
                    headers_checked.add((h, val))
                    # Check if it contains specific numbers / versions (e.g. Apache/2.4.41, PHP/7.4.3)
                    if re.search(r"\d+\.\d+", val):
                        self.add_finding(
                            title=f"Detailed Version Disclosure in '{h}' Header",
                            severity=Severity.LOW,
                            description=(
                                f"The '{h}' HTTP header exposes precise technology and version details ('{val}'). "
                                f"Attackers can use this information to pinpoint known CVEs targeting the specific software build."
                            ),
                            url_affected=url,
                            evidence=f"{h}: {val}",
                            cwe_id="CWE-200",
                            remediation=f"Disable or obscure the '{h}' header in web server / application configuration."
                        )

    def _check_script_libraries(self, crawl_result: CrawlResult):
        """Analyze discovered script tags and URLs for outdated versions."""
        for script_url in crawl_result.scripts:
            for lib_name, regex_pattern, min_safe_version, vuln_note in self.VULNERABLE_JS_LIBS:
                match = re.search(regex_pattern, script_url, re.IGNORECASE)
                if match:
                    detected_ver = match.group(1)
                    if self._is_version_older(detected_ver, min_safe_version):
                        self.add_finding(
                            title=f"Outdated JavaScript Library: {lib_name} v{detected_ver}",
                            severity=Severity.MEDIUM,
                            description=(
                                f"The application loads an outdated version of {lib_name} (v{detected_ver} < safe version {min_safe_version}). "
                                f"Known vulnerabilities: {vuln_note}."
                            ),
                            url_affected=script_url,
                            evidence=f"Discovered Script URL: {script_url}\nDetected Version: {detected_ver}",
                            cwe_id="CWE-1104",
                            remediation=f"Upgrade {lib_name} to the latest stable release (at least >= {min_safe_version})."
                        )

    def _is_version_older(self, ver1: str, min_safe: str) -> bool:
        """Simple semantic version comparison."""
        try:
            p1 = [int(x) for x in re.findall(r"\d+", ver1)]
            p2 = [int(x) for x in re.findall(r"\d+", min_safe)]
            # Pad
            while len(p1) < len(p2): p1.append(0)
            while len(p2) < len(p1): p2.append(0)
            return p1 < p2
        except Exception:
            return False
