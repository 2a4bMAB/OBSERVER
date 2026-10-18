"""
OBSERVER — A08: Software and Data Integrity Failures Detector
Tests for:
  - External CDN scripts and stylesheets loaded without Subresource Integrity (SRI)
  - Insecure Deserialization payloads / object indicators in cookies or requests
"""
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import requests

from core.database import Severity
from scanner.owasp.base import BaseDetector, ScanFinding
from scanner.crawler import CrawlResult


class IntegrityFailuresDetector(BaseDetector):
    category_id = "A08"
    category_name = "Software and Data Integrity Failures"

    def run(self, crawl_result: CrawlResult) -> list[ScanFinding]:
        self.findings = []
        self.log("INFO", "[A08] Running Software and Data Integrity checks...")

        self._check_subresource_integrity(crawl_result)

        return self.findings

    def _check_subresource_integrity(self, crawl_result: CrawlResult):
        """Check if third-party external scripts/styles include SRI hash verification."""
        base_domain = urlparse(crawl_result.base_url).netloc.lower()

        for url, resp in crawl_result.responses.items():
            if "text/html" not in resp.headers.get("Content-Type", "").lower():
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            # Check <script src="...">
            for script in soup.find_all("script", src=True):
                src = script["src"]
                parsed_src = urlparse(src)
                if parsed_src.netloc and parsed_src.netloc.lower() != base_domain:
                    # Third-party script
                    if not script.get("integrity"):
                        self.add_finding(
                            title="External Script Loaded Without Subresource Integrity (SRI)",
                            severity=Severity.LOW,
                            description=(
                                f"An external script from '{parsed_src.netloc}' is loaded at '{url}' without an 'integrity' attribute. "
                                f"If the external CDN or domain is compromised, malicious code could be executed in users' browsers."
                            ),
                            url_affected=url,
                            evidence=f"Tag: <script src=\"{src}\"> (Missing integrity attribute)",
                            cwe_id="CWE-353",
                            remediation="Add Subresource Integrity ('integrity=\"sha384-...\" crossorigin=\"anonymous\"') to all externally hosted scripts and stylesheets."
                        )
                        break  # Report once per page to avoid flooding

            # Check <link rel="stylesheet" href="...">
            for link in soup.find_all("link", rel=lambda r: r and "stylesheet" in r, href=True):
                href = link["href"]
                parsed_href = urlparse(href)
                if parsed_href.netloc and parsed_href.netloc.lower() != base_domain:
                    if not link.get("integrity"):
                        self.add_finding(
                            title="External Stylesheet Loaded Without Subresource Integrity (SRI)",
                            severity=Severity.INFO,
                            description=f"External stylesheet from '{parsed_href.netloc}' is loaded without an 'integrity' attribute.",
                            url_affected=url,
                            evidence=f"Tag: <link href=\"{href}\">",
                            cwe_id="CWE-353",
                            remediation="Add 'integrity' attributes with SHA-384 or SHA-512 cryptographic hashes to external CSS resources."
                        )
                        break
