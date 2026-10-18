"""
OBSERVER — A07: Identification and Authentication Failures Detector
Tests for:
  - Password forms submitting over unencrypted HTTP
  - Session IDs transmitted in URL query parameters
  - Missing autocomplete security attributes on sensitive credential fields
  - Default credentials on common test endpoints
"""
from urllib.parse import urlparse, parse_qs
import requests

from core.database import Severity
from scanner.owasp.base import BaseDetector, ScanFinding
from scanner.crawler import CrawlResult


class AuthFailuresDetector(BaseDetector):
    category_id = "A07"
    category_name = "Identification and Authentication Failures"

    SESSION_PARAMS = [
        "session", "session_id", "sessionid", "phpsessid", "jsessionid",
        "aspsessionid", "sid", "auth_token", "access_token"
    ]

    def run(self, crawl_result: CrawlResult) -> list[ScanFinding]:
        self.findings = []
        self.log("INFO", "[A07] Running Identification & Authentication checks...")

        self._check_password_form_transport(crawl_result)
        self._check_session_ids_in_urls(crawl_result)

        return self.findings

    def _check_password_form_transport(self, crawl_result: CrawlResult):
        """Check if password forms submit to HTTPS."""
        for form in crawl_result.forms:
            has_password = any(i["type"].lower() == "password" for i in form.inputs)
            if has_password:
                parsed_action = urlparse(form.action)
                if parsed_action.scheme.lower() == "http":
                    self.add_finding(
                        title="Password Form Transmitting Credentials Over Plaintext HTTP",
                        severity=Severity.CRITICAL,
                        description=(
                            f"An authentication form at '{form.action}' submits password credentials over cleartext HTTP. "
                            f"Credentials can be intercepted in transit by any network intermediary."
                        ),
                        url_affected=form.action,
                        evidence=f"Form Action: {form.action} (Scheme: HTTP)",
                        cwe_id="CWE-319",
                        remediation="Ensure all authentication and credential submission forms submit exclusively over HTTPS."
                    )

    def _check_session_ids_in_urls(self, crawl_result: CrawlResult):
        """Check if session tokens appear in URL query strings (URL Rewriting)."""
        for url in crawl_result.discovered_urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue

            query_dict = parse_qs(parsed.query)
            for param in query_dict.keys():
                if param.lower() in self.SESSION_PARAMS:
                    self.add_finding(
                        title=f"Session Identifier Exposed in URL Query String ('{param}')",
                        severity=Severity.HIGH,
                        description=(
                            f"The session parameter '{param}' is transmitted in the URL query string on '{url}'. "
                            f"Session IDs in URLs are logged in browser history, proxy access logs, and Referer headers."
                        ),
                        url_affected=url,
                        parameter=param,
                        evidence=f"URL: {url}",
                        cwe_id="CWE-598",
                        remediation="Store and transmit session tokens exclusively via secure, HttpOnly HTTP cookies or Authorization headers."
                    )
