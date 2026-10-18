"""
OBSERVER — Base Detector Interface
Provides common helper methods, logging, and finding models.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import requests

from core.database import Severity
from scanner.crawler import CrawlResult


@dataclass
class ScanFinding:
    """Represents a discovered finding before DB persistence."""
    owasp_category: str
    owasp_name: str
    title: str
    severity: Severity
    description: str
    url_affected: str
    parameter: str | None = None
    evidence: str | None = None
    cwe_id: str | None = None
    remediation: str | None = None
    found_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class BaseDetector:
    """Base class for all OWASP vulnerability detectors."""

    category_id: str = "A00"
    category_name: str = "Base Detector"

    def __init__(self, session: requests.Session, timeout: int = 10):
        self.session = session
        self.timeout = timeout
        self.findings: list[ScanFinding] = []

    def log(self, level: str, message: str):
        if hasattr(self, "_log_callback") and self._log_callback:
            self._log_callback(level, message)

    def set_log_callback(self, callback):
        self._log_callback = callback

    def run(self, crawl_result: CrawlResult) -> list[ScanFinding]:
        """Execute detector checks against the crawl results."""
        raise NotImplementedError("Detectors must implement run()")

    def add_finding(
        self,
        title: str,
        severity: Severity,
        description: str,
        url_affected: str,
        parameter: str | None = None,
        evidence: str | None = None,
        cwe_id: str | None = None,
        remediation: str | None = None
    ):
        """Helper to append a finding."""
        finding = ScanFinding(
            owasp_category=self.category_id,
            owasp_name=self.category_name,
            title=title,
            severity=severity,
            description=description,
            url_affected=url_affected,
            parameter=parameter,
            evidence=evidence,
            cwe_id=cwe_id,
            remediation=remediation
        )
        self.findings.append(finding)
        self.log(
            "WARNING" if severity in (Severity.LOW, Severity.INFO) else "ERROR",
            f"[{self.category_id}] [{severity.value.upper()}] {title} on {url_affected}"
        )
