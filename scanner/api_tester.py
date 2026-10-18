"""
OBSERVER — API Endpoint Tester
Tests manually declared JSON API endpoints using the authenticated session.

For each endpoint the tester:
  1. Builds a JSON request body from user-supplied key/value parameters.
  2. Adds Content-Type: application/json + X-CSRFToken header (when available).
  3. Sends the request through the (possibly authenticated) session.
  4. Analyses the JSON (and non-JSON) response for OWASP-relevant issues:
       - A04 / Verbose error messages (stack traces, exception info)
       - A02 / Sensitive data exposure in response body
       - A05 / Missing rate-limit headers on sensitive endpoints
       - A09 / Server errors (5xx) indicating missing error handling
  5. Returns findings in the same ScanFinding format as OWASP detectors.
"""
import json
import re
from datetime import datetime, timezone
from typing import Callable

import requests

from core.database import Severity
from scanner.owasp.base import ScanFinding

# Patterns that indicate verbose / leaked server error details
_VERBOSE_ERROR_PATTERNS = [
    r"traceback \(most recent call last\)",
    r"exception in thread",
    r"syntaxerror",
    r"file \".*\.py\", line \d+",
    r"django\.core\.",
    r"django\.db\.",
    r"sqlalchemy",
    r"psycopg2",
    r"pymysql",
    r"operationalerror",
    r"programmingError",
    r"stack trace",
    r"at [a-zA-Z]+\.[a-zA-Z]+\(.*\.java:\d+\)",   # Java stack frame
    r"NullPointerException",
    r"IndexOutOfBoundsException",
]

# Keys in JSON response that may expose sensitive data
_SENSITIVE_KEY_PATTERNS = [
    r"password",
    r"passwd",
    r"secret",
    r"token",
    r"api_?key",
    r"private_?key",
    r"auth",
    r"credential",
    r"salt",
    r"hash",
    r"ssn",
    r"credit_?card",
    r"cvv",
]

# Rate-limit related response headers
_RATE_LIMIT_HEADERS = {
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "retry-after",
    "ratelimit-limit",
    "ratelimit-remaining",
}

# Methods that modify server state and warrant CSRF protection
_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class ApiEndpointTester:
    """
    Tests a list of user-declared API endpoints and returns OWASP findings.

    Parameters
    ----------
    session : requests.Session
        The (possibly authenticated) HTTP session to use.
    auth_manager : AuthManager | None
        If provided, used to inject CSRF tokens into mutating requests.
    timeout : int
        Per-request timeout in seconds.
    """

    def __init__(self, session: requests.Session, auth_manager=None, timeout: int = 10):
        self.session = session
        self.auth_manager = auth_manager
        self.timeout = timeout
        self._findings: list[ScanFinding] = []

    # ──────────────────────────────────────────────────────────────────────────
    # Public
    # ──────────────────────────────────────────────────────────────────────────

    def test_endpoints(
        self,
        endpoints: list[dict],
        log_callback: Callable | None = None,
    ) -> list[ScanFinding]:
        """
        Test each endpoint and return the list of findings.

        Each entry in `endpoints` must contain:
            {
                "url":    "http://…/api/endpoint/",
                "method": "POST",         # GET / POST / PUT / DELETE
                "params": {               # optional – key/value pairs
                    "key1": "value1",
                    "key2": 42
                }
            }
        """
        self._findings = []

        def _log(level: str, msg: str):
            if log_callback:
                log_callback(level, f"[ApiTester] {msg}")

        _log("INFO", f"Testing {len(endpoints)} manually declared API endpoint(s)")

        for ep in endpoints:
            url = ep.get("url", "").strip()
            method = ep.get("method", "GET").upper()
            params = ep.get("params") or {}

            if not url:
                _log("WARNING", "Skipping endpoint with empty URL")
                continue

            _log("INFO", f"→ {method} {url}" + (f" params={list(params.keys())}" if params else ""))

            resp = self._send_request(url, method, params, _log)
            if resp is None:
                continue

            self._analyse_response(url, method, resp, _log)

        _log("INFO", f"API endpoint testing complete — {len(self._findings)} finding(s)")
        return self._findings

    # ──────────────────────────────────────────────────────────────────────────
    # Private — request sending
    # ──────────────────────────────────────────────────────────────────────────

    def _send_request(
        self,
        url: str,
        method: str,
        params: dict,
        log: Callable,
    ) -> requests.Response | None:
        """Build and send the HTTP request. Returns the response or None on error."""
        headers = {
            "Accept": "application/json, */*",
        }

        body = None
        query_params = None

        if method in _MUTATING_METHODS:
            # JSON body for mutating requests
            headers["Content-Type"] = "application/json"
            body = json.dumps(params) if params else None

            # Inject CSRF token if available
            if self.auth_manager:
                csrf_headers = self.auth_manager.prepare_post_headers(url)
                headers.update(csrf_headers)
                if csrf_headers.get("X-CSRFToken"):
                    log("DEBUG", f"  CSRF token injected: {csrf_headers['X-CSRFToken'][:12]}…")
        else:
            # Query-string parameters for GET/HEAD
            query_params = params if params else None

        try:
            resp = self.session.request(
                method=method,
                url=url,
                headers=headers,
                data=body,
                params=query_params,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
            )
            log("DEBUG", f"  HTTP {resp.status_code} — {len(resp.content)} bytes — "
                         f"Content-Type: {resp.headers.get('Content-Type', '?')}")
            return resp

        except requests.exceptions.Timeout:
            log("WARNING", f"  Request timed out after {self.timeout}s")
        except requests.exceptions.ConnectionError as exc:
            log("WARNING", f"  Connection error: {exc}")
        except Exception as exc:
            log("ERROR", f"  Unexpected error: {exc}")

        return None

    # ──────────────────────────────────────────────────────────────────────────
    # Private — response analysis
    # ──────────────────────────────────────────────────────────────────────────

    def _analyse_response(
        self,
        url: str,
        method: str,
        resp: requests.Response,
        log: Callable,
    ) -> None:
        """Run all checks against the response and add findings."""
        body_text = resp.text or ""
        body_lower = body_text.lower()
        status = resp.status_code

        # Parse JSON if possible
        json_body = None
        ct = resp.headers.get("Content-Type", "").lower()
        if "json" in ct:
            try:
                json_body = resp.json()
            except Exception:
                pass

        # ── Check 1: Server error (5xx) ───────────────────────────────────
        if status >= 500:
            self._add_finding(
                title=f"Server Error (HTTP {status}) on API Endpoint",
                severity=Severity.HIGH,
                description=(
                    f"The API endpoint {url} returned HTTP {status}, indicating an unhandled "
                    f"server-side error. This may expose internal implementation details and "
                    f"signals insufficient error handling."
                ),
                url_affected=url,
                owasp_category="A09",
                owasp_name="Security Logging & Monitoring Failures",
                evidence=f"HTTP {status} — {body_text[:300]}",
                cwe_id="CWE-390",
                remediation=(
                    "Implement a global exception handler that returns a generic error "
                    "response without leaking server internals. Log the full exception "
                    "server-side and monitor for repeated 5xx occurrences."
                ),
            )
            log("WARNING", f"  [A09] Server error HTTP {status} on {url}")

        # ── Check 2: Verbose error / stack trace in response ──────────────
        for pattern in _VERBOSE_ERROR_PATTERNS:
            if re.search(pattern, body_lower, re.IGNORECASE):
                snippet = self._extract_snippet(body_text, pattern)
                self._add_finding(
                    title="Verbose Error / Stack Trace Exposed in API Response",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The API response from {url} contains internal error details "
                        f"(e.g. stack trace, exception class, file paths). This information "
                        f"aids attackers in understanding server architecture."
                    ),
                    url_affected=url,
                    owasp_category="A04",
                    owasp_name="Insecure Design",
                    evidence=f"Pattern '{pattern}' matched. Snippet: {snippet}",
                    cwe_id="CWE-209",
                    remediation=(
                        "Disable debug mode in production (DEBUG=False in Django). "
                        "Return only generic error messages in API responses. "
                        "Log full details server-side only."
                    ),
                )
                log("WARNING", f"  [A04] Verbose error pattern '{pattern}' in response from {url}")
                break  # One finding per endpoint is enough for this check

        # ── Check 3: Sensitive data in JSON response ───────────────────────
        if json_body is not None:
            exposed_keys = self._find_sensitive_keys(json_body)
            if exposed_keys:
                self._add_finding(
                    title=f"Sensitive Data Exposed in API Response ({', '.join(exposed_keys[:3])})",
                    severity=Severity.HIGH,
                    description=(
                        f"The API response from {url} contains field(s) with potentially "
                        f"sensitive names: {', '.join(exposed_keys)}. Returning such fields "
                        f"to the client may expose credentials, secrets, or PII."
                    ),
                    url_affected=url,
                    owasp_category="A02",
                    owasp_name="Cryptographic Failures",
                    evidence=f"Sensitive field(s) found in JSON: {exposed_keys}",
                    cwe_id="CWE-312",
                    remediation=(
                        "Review the API serializer/view to ensure sensitive fields are "
                        "excluded from responses. Use an allowlist approach when serializing "
                        "model data (only expose fields that clients truly need)."
                    ),
                )
                log("WARNING", f"  [A02] Sensitive field(s) in JSON response: {exposed_keys}")

        # ── Check 4: Missing rate-limit headers ────────────────────────────
        response_headers_lower = {k.lower() for k in resp.headers}
        has_rate_limit = bool(response_headers_lower & _RATE_LIMIT_HEADERS)
        if not has_rate_limit and method in _MUTATING_METHODS:
            self._add_finding(
                title="No Rate-Limiting Headers on API Endpoint",
                severity=Severity.LOW,
                description=(
                    f"The API endpoint {url} ({method}) does not return any rate-limiting "
                    f"headers (X-RateLimit-*, Retry-After). Without rate limiting, this "
                    f"endpoint may be vulnerable to brute-force or denial-of-service attacks."
                ),
                url_affected=url,
                owasp_category="A05",
                owasp_name="Security Misconfiguration",
                evidence=f"Response headers: {dict(resp.headers)}",
                cwe_id="CWE-770",
                remediation=(
                    "Implement rate limiting (e.g. django-ratelimit, DRF throttling). "
                    "Return X-RateLimit-Limit, X-RateLimit-Remaining, and Retry-After headers."
                ),
            )
            log("INFO", f"  [A05] No rate-limit headers on {method} {url}")

    # ──────────────────────────────────────────────────────────────────────────
    # Private — helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _add_finding(
        self,
        title: str,
        severity: Severity,
        description: str,
        url_affected: str,
        owasp_category: str,
        owasp_name: str,
        evidence: str | None = None,
        cwe_id: str | None = None,
        remediation: str | None = None,
    ) -> None:
        """Create and store a ScanFinding."""
        finding = ScanFinding(
            owasp_category=owasp_category,
            owasp_name=owasp_name,
            title=title,
            severity=severity,
            description=description,
            url_affected=url_affected,
            evidence=evidence,
            cwe_id=cwe_id,
            remediation=remediation,
            found_at=datetime.now(timezone.utc),
        )
        self._findings.append(finding)

    def _find_sensitive_keys(self, obj, _depth: int = 0) -> list[str]:
        """Recursively walk a JSON object and return keys matching sensitive patterns."""
        if _depth > 5:
            return []
        found = []
        if isinstance(obj, dict):
            for key, value in obj.items():
                key_lower = key.lower()
                for pat in _SENSITIVE_KEY_PATTERNS:
                    if re.search(pat, key_lower):
                        found.append(key)
                        break
                found.extend(self._find_sensitive_keys(value, _depth + 1))
        elif isinstance(obj, list):
            for item in obj[:10]:  # limit list traversal
                found.extend(self._find_sensitive_keys(item, _depth + 1))
        return list(dict.fromkeys(found))  # deduplicate preserving order

    @staticmethod
    def _extract_snippet(text: str, pattern: str, context: int = 120) -> str:
        """Return a short text snippet around the first match of `pattern`."""
        m = re.search(pattern, text, re.IGNORECASE)
        if not m:
            return text[:context]
        start = max(0, m.start() - 40)
        end = min(len(text), m.end() + context)
        return text[start:end]
