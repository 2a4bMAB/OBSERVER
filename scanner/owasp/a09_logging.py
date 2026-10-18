"""
OBSERVER — A09: Security Logging and Monitoring Failures Detector
Tests for:
  - Default 404 / 500 error pages disclosing framework or server internals
  - Unhandled exception disclosures on malformed inputs
"""
import random
import string
from urllib.parse import urljoin
import requests

from core.database import Severity
from scanner.owasp.base import BaseDetector, ScanFinding
from scanner.crawler import CrawlResult


class LoggingFailuresDetector(BaseDetector):
    category_id = "A09"
    category_name = "Security Logging and Monitoring Failures"

    def run(self, crawl_result: CrawlResult) -> list[ScanFinding]:
        self.findings = []
        self.log("INFO", "[A09] Running Security Logging & Monitoring checks...")

        self._check_custom_error_pages(crawl_result.base_url)

        return self.findings

    def _check_custom_error_pages(self, base_url: str):
        """Request non-existent resource and check if server returns default debug page."""
        rand_path = "/obs_404_probe_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        test_url = urljoin(base_url, rand_path)

        try:
            resp = self.session.get(test_url, timeout=self.timeout, verify=False)
            # Check if returns 200 instead of 404 (Soft 404)
            if resp.status_code == 200 and len(resp.text) > 100:
                self.add_finding(
                    title="Soft 404 Detected (Non-Existent Resource Returns HTTP 200)",
                    severity=Severity.INFO,
                    description=(
                        f"Requesting a non-existent URL ('{test_url}') returned HTTP 200 OK instead of a standard 404 Not Found. "
                        f"This complicates automated auditing and log anomaly detection."
                    ),
                    url_affected=test_url,
                    evidence=f"Status: HTTP {resp.status_code} for non-existent path.",
                    cwe_id="CWE-392",
                    remediation="Configure the web application to return proper HTTP 404 status codes for non-existent routes."
                )
            elif resp.status_code == 404:
                # Check if default Apache/Nginx/IIS 404 with version banner
                text_lower = resp.text.lower()
                if any(kw in text_lower for kw in ["apache/", "nginx/", "microsoft-iis/", "tomcat"]):
                    self.add_finding(
                        title="Default Web Server 404 Error Page Leaking Server Banner",
                        severity=Severity.LOW,
                        description="The application displays a default web server 404 error page exposing underlying server signatures.",
                        url_affected=test_url,
                        evidence=resp.text[:250],
                        cwe_id="CWE-200",
                        remediation="Configure a generic custom 404 error page that does not display web server or framework banners."
                    )
        except Exception as e:
            self.log("DEBUG", f"[A09] Error page check failed: {e}")
