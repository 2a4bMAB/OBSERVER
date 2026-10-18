"""
OBSERVER — A04: Insecure Design Detector
Tests for:
  - Missing Anti-CSRF Protection Tokens in state-changing HTML forms
  - Missing Rate Limiting / Anti-Automation controls
  - Predictable sequential ID heuristics in URL parameters
"""
import re
from urllib.parse import urlparse, parse_qs
import requests

from core.database import Severity
from scanner.owasp.base import BaseDetector, ScanFinding
from scanner.crawler import CrawlResult


class InsecureDesignDetector(BaseDetector):
    category_id = "A04"
    category_name = "Insecure Design"

    CSRF_TOKEN_NAMES = [
        "csrf", "xsrf", "_token", "authenticity_token", "csrftoken",
        "anti_forgery", "requestverificationtoken", "__requestverificationtoken"
    ]

    def run(self, crawl_result: CrawlResult) -> list[ScanFinding]:
        self.findings = []
        self.log("INFO", "[A04] Running Insecure Design checks...")

        self._check_csrf_protection_on_forms(crawl_result)
        self._check_rate_limiting(crawl_result)
        self._check_predictable_identifiers(crawl_result)

        return self.findings

    def _check_csrf_protection_on_forms(self, crawl_result: CrawlResult):
        """Check if POST forms contain anti-CSRF tokens."""
        for form in crawl_result.forms:
            if form.method != "POST":
                continue

            has_csrf = False
            for inp in form.inputs:
                name_lower = inp["name"].lower()
                if any(csrf_kw in name_lower for csrf_kw in self.CSRF_TOKEN_NAMES):
                    has_csrf = True
                    break

            if not has_csrf:
                self.add_finding(
                    title="Missing Anti-CSRF Token in State-Changing Form",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The HTML form submitting via POST to '{form.action}' does not contain an anti-CSRF token. "
                        f"If the application relies solely on cookies for session tracking, attackers could perform unauthorized actions on behalf of authenticated users."
                    ),
                    url_affected=form.action,
                    parameter=", ".join(inp["name"] for inp in form.inputs),
                    evidence=f"Form action: {form.action}\nInputs: {[i['name'] for i in form.inputs]}",
                    cwe_id="CWE-352",
                    remediation="Include a unique, cryptographically random Anti-CSRF token (e.g. Synchronizer Token Pattern) in all state-changing HTML forms."
                )

    def _check_rate_limiting(self, crawl_result: CrawlResult):
        """Check for rate limiting headers (X-RateLimit, Retry-After)."""
        base_url = crawl_result.base_url
        try:
            resp = crawl_result.responses.get(base_url)
            if not resp:
                resp = self.session.get(base_url, timeout=self.timeout, verify=False)

            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            has_rate_limit_header = any(
                h in headers_lower for h in ["x-ratelimit-limit", "ratelimit-limit", "retry-after", "x-rate-limit"]
            )

            if not has_rate_limit_header:
                self.add_finding(
                    title="No Explicit Rate Limiting Headers Detected",
                    severity=Severity.LOW,
                    description=(
                        "The application does not provide standard rate limiting indicators (e.g. RateLimit-Limit, Retry-After). "
                        "Ensure sensitive operations (login, registration, password reset, API endpoints) enforce request throttling."
                    ),
                    url_affected=base_url,
                    evidence="No RateLimit headers present in response.",
                    cwe_id="CWE-799",
                    remediation="Implement rate limiting and request throttling at the API gateway or application layer for all sensitive endpoints."
                )
        except Exception as e:
            self.log("DEBUG", f"[A04] Rate limiting check error: {e}")

    def _check_predictable_identifiers(self, crawl_result: CrawlResult):
        """Check for simple sequential integer IDs in parameters."""
        for url in crawl_result.discovered_urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue

            query_dict = parse_qs(parsed.query)
            for param, vals in query_dict.items():
                param_lower = param.lower()
                if any(id_kw in param_lower for id_kw in ["id", "user_id", "account", "order_id", "item_id", "doc_id"]):
                    for val in vals:
                        if val.isdigit() and len(val) <= 6:
                            self.add_finding(
                                title=f"Predictable Sequential Object Identifier in '{param}'",
                                severity=Severity.LOW,
                                description=(
                                    f"Parameter '{param}' on '{url}' appears to use simple sequential integers ({val}). "
                                    f"This pattern simplifies enumeration and IDOR exploitation if authorization checks are flawed."
                                ),
                                url_affected=url,
                                parameter=param,
                                evidence=f"Query parameter: {param}={val}",
                                cwe_id="CWE-330",
                                remediation="Use non-sequential, cryptographically random identifiers such as UUIDs (v4) for publicly exposed resource references."
                            )
                            break
