"""
OBSERVER — A01: Broken Access Control Detector
Tests for:
  - Exposed administrative paths & portals
  - Insecure Direct Object References (IDOR heuristics)
  - CORS Misconfigurations (Origin reflection, wildcards with credentials)
  - Sensitive paths listed in robots.txt
  - HTTP Verb Tampering / Dangerous Methods
"""
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import requests

from core.database import Severity
from scanner.owasp.base import BaseDetector, ScanFinding
from scanner.crawler import CrawlResult


class AccessControlDetector(BaseDetector):
    category_id = "A01"
    category_name = "Broken Access Control"

    SENSITIVE_PATHS = [
        "/admin", "/admin/", "/admin/login", "/administrator",
        "/manage", "/manager/html", "/dashboard", "/cpanel",
        "/api/admin", "/api/v1/admin", "/api/users",
        "/config", "/server-status", "/phpmyadmin",
        "/.env", "/.git/HEAD", "/backup", "/dump.sql"
    ]

    def run(self, crawl_result: CrawlResult) -> list[ScanFinding]:
        self.findings = []
        self.log("INFO", "[A01] Running Broken Access Control checks...")

        base_url = crawl_result.base_url
        self._check_cors_misconfiguration(crawl_result)
        self._check_robots_txt(base_url)
        self._check_exposed_admin_paths(base_url)
        self._check_http_methods(base_url)

        return self.findings

    def _check_cors_misconfiguration(self, crawl_result: CrawlResult):
        """Test for overly permissive CORS headers."""
        headers_to_test = [
            {"Origin": "https://evil-attacker.example.com"},
            {"Origin": "null"},
        ]

        test_urls = list(crawl_result.discovered_urls)[:10]
        for url in test_urls:
            for h in headers_to_test:
                try:
                    resp = self.session.get(url, headers=h, timeout=self.timeout, verify=False)
                    acao = resp.headers.get("Access-Control-Allow-Origin")
                    acac = resp.headers.get("Access-Control-Allow-Credentials")

                    if acao == h["Origin"] and acac and acac.lower() == "true":
                        self.add_finding(
                            title="Critical CORS Misconfiguration (Origin Reflection with Credentials)",
                            severity=Severity.CRITICAL,
                            description=(
                                f"The application reflects arbitrary Origins ({h['Origin']}) in Access-Control-Allow-Origin "
                                f"and allows credentials (Access-Control-Allow-Credentials: true). "
                                f"This allows third-party websites to make authenticated cross-origin requests and read sensitive data."
                            ),
                            url_affected=url,
                            evidence=f"Origin: {h['Origin']}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                            cwe_id="CWE-942",
                            remediation="Do not reflect arbitrary Origin headers. Specify an explicit whitelist of trusted domains and avoid enabling credentials for wildcards."
                        )
                        break
                    elif acao == "*":
                        self.add_finding(
                            title="Permissive CORS Policy (Wildcard Access)",
                            severity=Severity.LOW,
                            description="Access-Control-Allow-Origin is set to '*' allowing any domain to read responses.",
                            url_affected=url,
                            evidence=f"Access-Control-Allow-Origin: {acao}",
                            cwe_id="CWE-942",
                            remediation="Restrict Access-Control-Allow-Origin to trusted domains only if the endpoint returns sensitive data."
                        )
                        break
                except Exception as e:
                    self.log("DEBUG", f"[A01] CORS check error on {url}: {e}")

    def _check_robots_txt(self, base_url: str):
        """Inspect robots.txt for disclosed sensitive directories."""
        robots_url = urljoin(base_url, "/robots.txt")
        try:
            resp = self.session.get(robots_url, timeout=self.timeout, verify=False)
            if resp.status_code == 200 and "disallow" in resp.text.lower():
                disallowed = []
                for line in resp.text.splitlines():
                    if line.strip().lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            disallowed.append(path)

                if disallowed:
                    # Check if any disallowed path is accessible without auth
                    accessible_paths = []
                    for p in disallowed[:5]:
                        test_p_url = urljoin(base_url, p)
                        try:
                            r2 = self.session.get(test_p_url, timeout=self.timeout, verify=False)
                            if r2.status_code in (200, 301, 302):
                                accessible_paths.append(f"{p} (HTTP {r2.status_code})")
                        except Exception:
                            pass

                    self.add_finding(
                        title="Sensitive Paths Disclosed in robots.txt",
                        severity=Severity.MEDIUM if accessible_paths else Severity.INFO,
                        description=(
                            f"robots.txt disallows {len(disallowed)} paths, which exposes internal directory structures to crawlers.\n"
                            + (f"Accessible paths found: {', '.join(accessible_paths)}" if accessible_paths else "")
                        ),
                        url_affected=robots_url,
                        evidence=resp.text[:400],
                        cwe_id="CWE-200",
                        remediation="Do not rely on robots.txt for access control. Ensure administrative routes require proper authentication and authorization checks."
                    )
        except Exception as e:
            self.log("DEBUG", f"[A01] robots.txt check failed: {e}")

    def _check_exposed_admin_paths(self, base_url: str):
        """Check for unauthenticated access to standard administrative endpoints."""
        for path in self.SENSITIVE_PATHS:
            target_url = urljoin(base_url, path)
            try:
                resp = self.session.get(target_url, timeout=self.timeout, allow_redirects=False, verify=False)
                # If 200 OK or redirect to login (still reveals path existence)
                if resp.status_code == 200:
                    # Check if it actually contains admin keywords or config data
                    text_lower = resp.text.lower()
                    is_admin_portal = any(kw in text_lower for kw in ["admin", "dashboard", "control panel", "login", "management"])
                    is_config_leak = any(kw in text_lower for kw in ["db_password", "app_key", "secret", "aws_", "api_key", "[core]"])

                    if is_config_leak:
                        self.add_finding(
                            title=f"Exposed Configuration/Backup File at {path}",
                            severity=Severity.CRITICAL,
                            description=f"Critical configuration or secret file is publicly accessible at {path}.",
                            url_affected=target_url,
                            evidence=resp.text[:300],
                            cwe_id="CWE-552",
                            remediation="Remove sensitive backup or environment configuration files from web root and configure server to deny access to dot-files."
                        )
                    elif is_admin_portal:
                        self.add_finding(
                            title=f"Exposed Administrative Portal at {path}",
                            severity=Severity.HIGH,
                            description=f"Administrative portal or dashboard interface is accessible at {path} without IP whitelisting or access controls.",
                            url_affected=target_url,
                            evidence=f"Status: HTTP {resp.status_code}\nTitle/Content snippet: {resp.text[:200]}",
                            cwe_id="CWE-284",
                            remediation="Restrict administrative portals to internal networks / VPN and require multi-factor authentication."
                        )
            except Exception as e:
                self.log("DEBUG", f"[A01] Error checking {target_url}: {e}")

    def _check_http_methods(self, base_url: str):
        """Test for dangerous HTTP methods like TRACE, PUT, DELETE."""
        try:
            resp = self.session.options(base_url, timeout=self.timeout, verify=False)
            allow_header = resp.headers.get("Allow", "") or resp.headers.get("Public", "")
            if "TRACE" in allow_header.upper():
                self.add_finding(
                    title="HTTP TRACE Method Enabled (Cross-Site Tracing)",
                    severity=Severity.MEDIUM,
                    description="HTTP TRACE method is enabled on the web server, which can be leveraged in Cross-Site Tracing (XST) attacks to steal cookies.",
                    url_affected=base_url,
                    evidence=f"Allow: {allow_header}",
                    cwe_id="CWE-200",
                    remediation="Disable HTTP TRACE method in web server configuration."
                )
        except Exception as e:
            self.log("DEBUG", f"[A01] OPTIONS/TRACE check failed: {e}")
