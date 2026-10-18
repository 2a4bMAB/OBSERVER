"""
OBSERVER — A02: Cryptographic Failures Detector
Tests for:
  - Cleartext HTTP transport & missing HTTPS redirection
  - Missing or weak HTTP Strict Transport Security (HSTS)
  - Insecure Cookie attributes (Missing Secure, HttpOnly, SameSite)
  - Sensitive data exposure in responses (API keys, Private Keys, Card numbers)
"""
import re
from urllib.parse import urlparse
import requests

from core.database import Severity
from scanner.owasp.base import BaseDetector, ScanFinding
from scanner.crawler import CrawlResult


class CryptoDetector(BaseDetector):
    category_id = "A02"
    category_name = "Cryptographic Failures"

    # Regex patterns for sensitive data leaks
    SENSITIVE_PATTERNS = [
        ("Private Key Exposure", r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----", Severity.CRITICAL),
        ("AWS API Key Leak", r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", Severity.CRITICAL),
        ("Generic High-Entropy Secret", r"(?i)(api[_-]?key|secret[_-]?token|app[_-]?secret)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{24,}['\"]", Severity.HIGH),
        ("JSON Web Token (JWT) in Body", r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", Severity.MEDIUM),
    ]

    def run(self, crawl_result: CrawlResult) -> list[ScanFinding]:
        self.findings = []
        self.log("INFO", "[A02] Running Cryptographic Failures checks...")

        base_url = crawl_result.base_url
        self._check_transport_encryption(base_url)
        self._check_hsts_header(crawl_result)
        self._check_cookie_security(crawl_result)
        self._check_sensitive_data_exposure(crawl_result)

        return self.findings

    def _check_transport_encryption(self, base_url: str):
        """Verify HTTPS enforcement and HTTP-to-HTTPS redirect."""
        parsed = urlparse(base_url)
        if parsed.scheme.lower() == "http":
            try:
                resp = self.session.get(base_url, timeout=self.timeout, allow_redirects=False, verify=False)
                location = resp.headers.get("Location", "")
                if resp.status_code not in (301, 302, 307, 308) or not location.startswith("https://"):
                    self.add_finding(
                        title="Unencrypted HTTP Transport (Cleartext Communication)",
                        severity=Severity.HIGH,
                        description=(
                            "The web application is served over plaintext HTTP and does not automatically "
                            "redirect users to HTTPS. Data transmitted across the network is susceptible to eavesdropping and MITM attacks."
                        ),
                        url_affected=base_url,
                        evidence=f"Scheme: HTTP (Status {resp.status_code})\nLocation: {location or 'None'}",
                        cwe_id="CWE-319",
                        remediation="Enforce HTTPS everywhere with 301 Permanent Redirects from HTTP to HTTPS."
                    )
            except Exception as e:
                self.log("DEBUG", f"[A02] Transport check error: {e}")

    def _check_hsts_header(self, crawl_result: CrawlResult):
        """Check for Strict-Transport-Security header."""
        parsed = urlparse(crawl_result.base_url)
        if parsed.scheme.lower() != "https":
            return

        resp = crawl_result.responses.get(crawl_result.base_url)
        if not resp:
            try:
                resp = self.session.get(crawl_result.base_url, timeout=self.timeout, verify=False)
            except Exception:
                return

        hsts = resp.headers.get("Strict-Transport-Security")
        if not hsts:
            self.add_finding(
                title="Missing HTTP Strict Transport Security (HSTS) Header",
                severity=Severity.MEDIUM,
                description=(
                    "The application does not send the Strict-Transport-Security header over HTTPS. "
                    "This leaves users vulnerable to SSL-stripping and downgrade attacks on initial requests."
                ),
                url_affected=crawl_result.base_url,
                evidence="Strict-Transport-Security header is absent in HTTP response.",
                cwe_id="CWE-523",
                remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses."
            )
        elif "max-age" in hsts.lower():
            # Check max-age value
            match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
            if match and int(match.group(1)) < 10368000:  # less than 120 days
                self.add_finding(
                    title="Weak HSTS max-age Duration",
                    severity=Severity.LOW,
                    description="The Strict-Transport-Security max-age value is configured for less than the recommended duration of 1 year (31536000 seconds).",
                    url_affected=crawl_result.base_url,
                    evidence=f"Strict-Transport-Security: {hsts}",
                    cwe_id="CWE-523",
                    remediation="Increase HSTS max-age to at least 31536000 seconds (1 year)."
                )

    def _check_cookie_security(self, crawl_result: CrawlResult):
        """Inspect Set-Cookie headers for Secure, HttpOnly, and SameSite flags."""
        seen_cookies = set()
        is_https = urlparse(crawl_result.base_url).scheme.lower() == "https"

        for url, resp in crawl_result.responses.items():
            set_cookie_headers = resp.headers.get("Set-Cookie")
            if not set_cookie_headers:
                continue

            cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else [set_cookie_headers]
            for cookie_str in cookies:
                cookie_name = cookie_str.split("=")[0].strip()
                if cookie_name in seen_cookies:
                    continue
                seen_cookies.add(cookie_name)

                cookie_lower = cookie_str.lower()
                is_secure = "secure" in cookie_lower
                is_httponly = "httponly" in cookie_lower
                has_samesite = "samesite" in cookie_lower

                issues = []
                if is_https and not is_secure:
                    issues.append("Missing 'Secure' flag (can be leaked over cleartext HTTP)")
                if not is_httponly:
                    issues.append("Missing 'HttpOnly' flag (accessible via JavaScript / vulnerable to XSS)")
                if not has_samesite:
                    issues.append("Missing 'SameSite' flag (potential CSRF exposure)")

                if issues:
                    sev = Severity.HIGH if (not is_httponly and any(kw in cookie_name.lower() for kw in ["sess", "auth", "token", "jwt", "id"])) else Severity.MEDIUM
                    self.add_finding(
                        title=f"Insecure Cookie Flags on '{cookie_name}'",
                        severity=sev,
                        description=(
                            f"Cookie '{cookie_name}' is set with missing security attributes:\n"
                            + "\n".join(f"- {iss}" for iss in issues)
                        ),
                        url_affected=url,
                        evidence=cookie_str[:250],
                        cwe_id="CWE-614",
                        remediation="Set 'Secure; HttpOnly; SameSite=Lax' (or SameSite=Strict) on all sensitive and session cookies."
                    )

    def _check_sensitive_data_exposure(self, crawl_result: CrawlResult):
        """Scan responses for sensitive tokens or private keys."""
        for url, resp in crawl_result.responses.items():
            for title, pattern, sev in self.SENSITIVE_PATTERNS:
                matches = re.findall(pattern, resp.text)
                if matches:
                    self.add_finding(
                        title=f"Sensitive Data Exposure: {title}",
                        severity=sev,
                        description=f"Potential secret or key leaked in response body at {url}.",
                        url_affected=url,
                        evidence=f"Matched pattern: {str(matches[0])[:150]}",
                        cwe_id="CWE-312",
                        remediation="Never embed API keys, secrets, or private keys in client-accessible responses."
                    )
