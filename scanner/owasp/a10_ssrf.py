"""
OBSERVER — A10: Server-Side Request Forgery (SSRF) Detector
Tests for:
  - URL / Webhook parameters accepting arbitrary remote destinations
  - Open redirect heuristics that could be chained for SSRF
"""
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests

from core.database import Severity
from scanner.owasp.base import BaseDetector, ScanFinding
from scanner.crawler import CrawlResult


class SSRFDetector(BaseDetector):
    category_id = "A10"
    category_name = "Server-Side Request Forgery (SSRF)"

    SSRF_PARAM_NAMES = [
        "url", "target", "dest", "destination", "redirect", "redirect_to",
        "redirect_url", "uri", "path", "feed", "proxy", "src", "link",
        "webhook", "fetch", "domain", "callback", "host", "endpoint"
    ]

    def run(self, crawl_result: CrawlResult) -> list[ScanFinding]:
        self.findings = []
        self.log("INFO", "[A10] Running SSRF checks on candidate parameters...")

        self._check_url_parameters(crawl_result)

        return self.findings

    def _check_url_parameters(self, crawl_result: CrawlResult):
        """Identify query parameters susceptible to arbitrary URL input."""
        for url, params in crawl_result.parameters.items():
            parsed = urlparse(url)
            if not parsed.query:
                continue

            query_dict = parse_qs(parsed.query)
            for param in params:
                param_lower = param.lower()
                if any(kw == param_lower or f"_{kw}" in param_lower or f"{kw}_" in param_lower for kw in self.SSRF_PARAM_NAMES):
                    # Test Open Redirect / SSRF reflection indicator
                    canary_domain = "example.com"
                    canary_url = f"https://{canary_domain}/obs_ssrf_test"

                    mutated = dict(query_dict)
                    mutated[param] = [canary_url]
                    test_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))

                    try:
                        resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False, verify=False)
                        location = resp.headers.get("Location", "")

                        if canary_domain in location or resp.status_code in (301, 302, 303, 307, 308) and canary_domain in location:
                            self.add_finding(
                                title=f"Potential SSRF / Open Redirection via Parameter '{param}'",
                                severity=Severity.HIGH,
                                description=(
                                    f"Parameter '{param}' on '{url}' accepts arbitrary external URLs and redirects the client "
                                    f"or triggers backend resolution to '{location}'. "
                                    f"This pattern may enable Server-Side Request Forgery (SSRF) if consumed server-side, or Open Redirection."
                                ),
                                url_affected=test_url,
                                parameter=param,
                                evidence=f"Injected URL: {canary_url}\nResponse Location Header: {location}",
                                cwe_id="CWE-918",
                                remediation="Validate user-supplied URLs against an allowlist of permitted internal/external domains and protocols. Disable following redirects on backend requests."
                            )
                        elif canary_url in resp.text:
                            self.add_finding(
                                title=f"Arbitrary URL Parameter Reflection in '{param}'",
                                severity=Severity.LOW,
                                description=(
                                    f"Parameter '{param}' accepts full URLs and reflects them in the response. "
                                    f"Verify that backend handlers validate target domains before making server-to-server requests."
                                ),
                                url_affected=test_url,
                                parameter=param,
                                evidence=f"Query: {param}={canary_url}",
                                cwe_id="CWE-918",
                                remediation="Enforce strict URL schema (https only) and DNS resolution allowlists to prevent accessing RFC 1918 private IP addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1, 169.254.169.254)."
                            )
                    except Exception as e:
                        self.log("DEBUG", f"[A10] SSRF probe error on {param}: {e}")
