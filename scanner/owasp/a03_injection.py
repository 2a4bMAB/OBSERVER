"""
OBSERVER — A03: Injection Detector (SQLi, XSS, Command Injection)
Tests for:
  - SQL Injection syntax error triggers & boolean indicators
  - Reflected Cross-Site Scripting (XSS) input reflection without entity encoding
  - HTML Injection in forms and URL query parameters
"""
import re
import random
import string
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
import requests

from core.database import Severity
from scanner.owasp.base import BaseDetector, ScanFinding
from scanner.crawler import CrawlResult


class InjectionDetector(BaseDetector):
    category_id = "A03"
    category_name = "Injection"

    # SQL error signatures for popular databases
    SQL_ERRORS = [
        ("MySQL", r"(?:You have an error in your SQL syntax|Warning.*mysql_|valid MySQL result|MySqlClient\.)"),
        ("PostgreSQL", r"(?:PostgreSQL.*ERROR|Warning.*\Wpg_|valid PostgreSQL result|Npgsql\.)"),
        ("Microsoft SQL Server", r"(?:Driver.*SQL[\-\_\ ]*Server|OLE DB.*SQL Server|\bSQLServer JDBC Driver\b|SqlClient\.)"),
        ("Oracle", r"(?:ORA-\d{5}|Oracle error|Oracle.*Driver)"),
        ("SQLite", r"(?:SQLite/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite\.SQLiteException|unrecognized token:)"),
    ]

    def run(self, crawl_result: CrawlResult) -> list[ScanFinding]:
        self.findings = []
        self.log("INFO", "[A03] Running Injection checks (SQLi & XSS)...")

        self._audit_url_query_parameters(crawl_result)
        self._audit_forms(crawl_result)

        return self.findings

    def _audit_url_query_parameters(self, crawl_result: CrawlResult):
        """Test URL query parameters for SQLi and reflected XSS."""
        for url, params in crawl_result.parameters.items():
            parsed = urlparse(url)
            if not parsed.query:
                continue

            query_dict = parse_qs(parsed.query, keep_blank_values=True)
            for param_name in list(params)[:5]:  # Test up to 5 params per URL
                orig_val = query_dict.get(param_name, [""])[0]

                # 1. SQL Injection Probe
                self._test_sqli_param(url, parsed, query_dict, param_name, orig_val)

                # 2. Reflected XSS / HTML Injection Probe
                self._test_xss_param(url, parsed, query_dict, param_name)

    def _test_sqli_param(self, url: str, parsed, query_dict: dict, param: str, orig_val: str):
        """Send diagnostic SQL syntax markers and inspect for database errors."""
        probes = ["'", "''", "';", '"', '\\']
        for probe in probes:
            mutated_query = dict(query_dict)
            mutated_query[param] = [orig_val + probe]
            test_url = urlunparse(parsed._replace(query=urlencode(mutated_query, doseq=True)))

            try:
                resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                for db_name, error_regex in self.SQL_ERRORS:
                    match = re.search(error_regex, resp.text, re.IGNORECASE)
                    if match:
                        self.add_finding(
                            title=f"SQL Injection Vulnerability in parameter '{param}' ({db_name})",
                            severity=Severity.CRITICAL,
                            description=(
                                f"A database error signature ({db_name}) was triggered when sending diagnostic SQL characters "
                                f"to parameter '{param}'. This indicates user input is directly concatenated into SQL queries."
                            ),
                            url_affected=test_url,
                            parameter=param,
                            evidence=f"Payload: {probe}\nMatched DB Error: {match.group(0)}",
                            cwe_id="CWE-89",
                            remediation="Use parameterized queries (Prepared Statements) or an Object-Relational Mapper (ORM). Never concatenate unvalidated user inputs."
                        )
                        return  # Found on this param, skip further probes
            except Exception as e:
                self.log("DEBUG", f"[A03] SQLi probe error on {param}: {e}")

    def _test_xss_param(self, url: str, parsed, query_dict: dict, param: str):
        """Test for reflection of unescaped HTML characters (Reflected XSS heuristic)."""
        rand_token = "obs" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        canary = f"<{rand_token} obs_attr=\"test\">"

        mutated_query = dict(query_dict)
        mutated_query[param] = [canary]
        test_url = urlunparse(parsed._replace(query=urlencode(mutated_query, doseq=True)))

        try:
            resp = self.session.get(test_url, timeout=self.timeout, verify=False)
            content_type = resp.headers.get("Content-Type", "").lower()

            if "text/html" in content_type and canary in resp.text:
                self.add_finding(
                    title=f"Reflected Cross-Site Scripting (XSS) / Unencoded Input in '{param}'",
                    severity=Severity.HIGH,
                    description=(
                        f"The parameter '{param}' is reflected in the HTML response without adequate context-aware "
                        f"HTML encoding. Special characters (<, \", >) were returned verbatim, enabling script injection."
                    ),
                    url_affected=test_url,
                    parameter=param,
                    evidence=f"Injected Canary: {canary}\nReflected in response body.",
                    cwe_id="CWE-79",
                    remediation="Apply context-sensitive output encoding (HTML Entity Encoding) and implement a robust Content-Security-Policy (CSP)."
                )
        except Exception as e:
            self.log("DEBUG", f"[A03] XSS probe error on {param}: {e}")

    def _audit_forms(self, crawl_result: CrawlResult):
        """Audit HTML form inputs for reflection and basic injection vulnerabilities."""
        for form in crawl_result.forms[:10]:
            rand_token = "obsform" + "".join(random.choices(string.digits, k=4))
            canary = f"<{rand_token}>"

            data = {}
            for inp in form.inputs:
                if inp["type"] in ("text", "search", "email", "url", ""):
                    data[inp["name"]] = canary
                else:
                    data[inp["name"]] = inp["value"] or "test"

            try:
                if form.method == "POST":
                    resp = self.session.post(form.action, data=data, timeout=self.timeout, verify=False)
                else:
                    resp = self.session.get(form.action, params=data, timeout=self.timeout, verify=False)

                if canary in resp.text:
                    self.add_finding(
                        title="Form Input Reflection Without HTML Sanitization",
                        severity=Severity.HIGH,
                        description=(
                            f"A form submission at '{form.action}' reflected unescaped HTML characters into the response."
                        ),
                        url_affected=form.action,
                        parameter=", ".join(data.keys()),
                        evidence=f"Form Method: {form.method}\nInjected Canary: {canary}",
                        cwe_id="CWE-79",
                        remediation="Ensure all form input parameters are sanitized and properly HTML-encoded when rendered."
                    )
            except Exception as e:
                self.log("DEBUG", f"[A03] Form audit error on {form.action}: {e}")
