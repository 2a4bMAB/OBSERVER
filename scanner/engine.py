"""
OBSERVER — Central Vulnerability Scan Engine
Asynchronous QThread-based scan runner that orchestrates:
  - Web Crawler (target mapping)
  - OWASP Top 10 Detectors execution
  - Real-time logging to SQLite (`ScanLog`) and Qt signals
  - Findings persistence (`Finding`) and critical vulnerability email alerting
"""
import json
import logging
import traceback
from datetime import datetime, timezone
from PyQt6.QtCore import QThread, pyqtSignal
import requests

logger = logging.getLogger("observer.engine")

from core.database import (
    get_db, Scan, ScanStatus, Finding, Severity, ScanLog, LogLevel, Target, User
)
from core.mailer import send_critical_alert
from scanner.auth_manager import AuthManager
from scanner.api_tester import ApiEndpointTester
from scanner.crawler import WebCrawler, CrawlResult
from scanner.owasp import DETECTOR_REGISTRY
from scanner.owasp.base import ScanFinding


class ScanEngineWorker(QThread):
    """
    Background worker thread executing a single scan pipeline.
    """
    log_signal = pyqtSignal(str, str, str, str)  # (timestamp, level, message, module)
    finding_signal = pyqtSignal(dict)           # finding dict for immediate UI updates
    progress_signal = pyqtSignal(int, str)       # (percentage, status_text)
    finished_signal = pyqtSignal(int, bool, str) # (scan_id, success, message)

    def __init__(
        self,
        scan_id: int,
        target_url: str,
        categories: list[str] | None = None,
        max_depth: int = 3,
        max_pages: int = 30,
        timeout: int = 10,
        # Optional pre-scan authentication
        login_url: str | None = None,
        login_username: str | None = None,
        login_password: str | None = None,
        # Optional manual API endpoints to test
        api_endpoints: list[dict] | None = None,
        parent=None
    ):
        super().__init__(parent)
        self.scan_id = scan_id
        self.target_url = target_url
        self.categories = categories or list(DETECTOR_REGISTRY.keys())
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.login_url = login_url
        self.login_username = login_username
        self.login_password = login_password
        self.api_endpoints = api_endpoints or []
        self._is_cancelled = False

    def cancel(self):
        """Request worker cancellation."""
        self._is_cancelled = True

    def _log(self, level_str: str, message: str, module: str = "engine"):
        """Save log to database, logger file/console, and emit Qt signal."""
        # Mirror to standard python logger so it goes to observer.log and console
        log_lvl = getattr(logging, level_str.upper(), logging.INFO)
        logger.log(log_lvl, "[%s] %s", module, message)

        level_map = {
            "DEBUG": LogLevel.DEBUG,
            "INFO": LogLevel.INFO,
            "WARNING": LogLevel.WARNING,
            "ERROR": LogLevel.ERROR,
        }
        level_enum = level_map.get(level_str.upper(), LogLevel.INFO)
        now = datetime.now(timezone.utc)
        ts_str = now.strftime("%H:%M:%S")

        # Emit to UI
        self.log_signal.emit(ts_str, level_str.upper(), message, module)

        # Persist to DB
        db = get_db()
        try:
            log_entry = ScanLog(
                scan_id=self.scan_id,
                level=level_enum,
                message=message,
                module=module,
                timestamp=now
            )
            db.add(log_entry)
            db.commit()
        except Exception:
            pass
        finally:
            db.close()

    def run(self):
        logger.info("=" * 60)
        logger.info("ScanEngineWorker thread STARTED for Scan #%d on %s", self.scan_id, self.target_url)
        logger.info("Selected OWASP categories: %s", self.categories)
        logger.info("Pre-scan auth: login_url=%s, user=%s", self.login_url, self.login_username)
        logger.info("API endpoints declared: %d", len(self.api_endpoints))

        self.progress_signal.emit(5, "Initializing scan engine…")
        self._log("INFO", f"Starting audit pipeline for Scan #{self.scan_id} on {self.target_url}")

        # Update Scan status in DB
        db = get_db()
        try:
            scan = db.query(Scan).filter(Scan.id == self.scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.now(timezone.utc)
                db.commit()
                logger.info("Scan #%d status updated to RUNNING in database.", self.scan_id)
        except Exception as exc:
            logger.error("Failed to update Scan status to RUNNING: %s", exc)
        finally:
            db.close()

        try:
            # ── Shared session (used by all phases) ───────────────────────────
            session = requests.Session()
            session.headers.update({
                "User-Agent": "OBSERVER-Security-Audit/1.0",
                "Accept": "*/*"
            })
            auth_manager: AuthManager | None = None

            # ── Phase 0: Pre-scan Authentication (optional) ───────────────────
            if self.login_url and self.login_username and self.login_password:
                self.progress_signal.emit(5, "Authenticating against target…")
                self._log("INFO", f"Pre-scan authentication enabled — login URL: {self.login_url}")
                auth_manager = AuthManager(session=session, timeout=self.timeout)
                auth_ok = auth_manager.login(
                    login_url=self.login_url,
                    username=self.login_username,
                    password=self.login_password,
                    log_callback=lambda lvl, msg: self._log(lvl, msg, "auth"),
                )
                if auth_ok:
                    self._log("INFO",
                        "[Auth] Session authenticated — crawler and detectors will use authenticated session.",
                        "auth")
                else:
                    self._log("WARNING",
                        "[Auth] Authentication failed — continuing with public scope only.",
                        "auth")
                    auth_manager = None  # Don't use broken auth for CSRF
            else:
                self._log("INFO", "No authentication credentials provided — scanning public scope.")

            if self._is_cancelled:
                self._handle_cancellation()
                return

            # ── Phase 1: Crawling & Scope Mapping ─────────────────────────────
            self.progress_signal.emit(10, "Crawling target website…")
            self._log("INFO", f"Starting crawler on {self.target_url} (depth={self.max_depth}, max_pages={self.max_pages})", "crawler")
            crawler = WebCrawler(
                base_url=self.target_url,
                max_depth=self.max_depth,
                max_pages=self.max_pages,
                timeout=self.timeout,
                session=session,   # shared authenticated session
            )
            crawl_result = crawler.crawl(
                log_callback=lambda lvl, msg: self._log(lvl, msg, "crawler")
            )
            self._log("INFO", f"Crawl complete — {len(crawl_result.discovered_urls)} URLs, {len(crawl_result.forms)} forms discovered.", "crawler")

            if self._is_cancelled:
                self._handle_cancellation()
                return

            self.progress_signal.emit(30, f"Crawl complete. Running {len(self.categories)} OWASP detectors…")

            # ── Phase 2: Running OWASP Detectors ──────────────────────────────
            # Re-use the same (possibly authenticated) session
            total_cats = len(self.categories)
            critical_findings = []

            for idx, cat_code in enumerate(self.categories):
                if self._is_cancelled:
                    self._handle_cancellation()
                    return

                detector_cls = DETECTOR_REGISTRY.get(cat_code)
                if not detector_cls:
                    self._log("WARNING", f"Detector for [{cat_code}] not found in registry — skipping.", cat_code)
                    continue

                pct = 30 + int((idx / total_cats) * 60)
                self.progress_signal.emit(pct, f"Running [{cat_code}] {detector_cls.category_name}…")
                self._log("INFO", f"--> STARTING detector [{cat_code}] {detector_cls.category_name}", cat_code)

                detector = detector_cls(session=session, timeout=self.timeout)
                detector.set_log_callback(lambda lvl, msg, code=cat_code: self._log(lvl, msg, code))

                try:
                    findings: list[ScanFinding] = detector.run(crawl_result)
                    self._persist_findings(findings)
                    for f in findings:
                        if f.severity == Severity.CRITICAL:
                            critical_findings.append(f)
                    self._log("INFO", f"<-- FINISHED detector [{cat_code}] — {len(findings)} finding(s) detected.", cat_code)
                except Exception as e:
                    err_trace = traceback.format_exc()
                    self._log("ERROR", f"Detector [{cat_code}] FAILED: {e}\n{err_trace}", cat_code)

            # ── Phase 2b: API Endpoint Testing (optional) ─────────────────────
            if self.api_endpoints:
                ep_count = len(self.api_endpoints)
                self.progress_signal.emit(92, f"Testing {ep_count} API endpoint(s)…")
                self._log("INFO", f"Starting API endpoint testing ({ep_count} endpoint(s))", "api_tester")

                api_tester = ApiEndpointTester(
                    session=session,
                    auth_manager=auth_manager,
                    timeout=self.timeout,
                )
                api_findings: list[ScanFinding] = api_tester.test_endpoints(
                    endpoints=self.api_endpoints,
                    log_callback=lambda lvl, msg: self._log(lvl, msg, "api_tester"),
                )
                self._persist_findings(api_findings)
                for f in api_findings:
                    if f.severity == Severity.CRITICAL:
                        critical_findings.append(f)
                self._log("INFO", f"API endpoint testing finished — {len(api_findings)} finding(s).", "api_tester")

                if self._is_cancelled:
                    self._handle_cancellation()
                    return

            # ── Phase 3: Finalizing ───────────────────────────────────────────
            self.progress_signal.emit(95, "Finalizing report data…")
            self._finalize_scan(ScanStatus.COMPLETED)

            # Send Email Alert if Critical vulnerabilities were identified
            if critical_findings:
                self._send_critical_alerts(critical_findings)

            self.progress_signal.emit(100, "Audit completed successfully.")
            self._log("INFO", f"Scan #{self.scan_id} finished successfully.")
            self.finished_signal.emit(self.scan_id, True, "Scan completed successfully.")

        except Exception as e:
            err_msg = f"Fatal scan error: {e}"
            err_trace = traceback.format_exc()
            logger.critical("ScanEngineWorker FATAL EXCEPTION: %s\n%s", err_msg, err_trace)
            self._log("ERROR", f"{err_msg}\n{err_trace}", "engine")
            self._finalize_scan(ScanStatus.FAILED)
            self.finished_signal.emit(self.scan_id, False, str(e))

    def _persist_findings(self, findings: list[ScanFinding]):
        """Persist findings to SQLite and emit UI signal."""
        if not findings:
            return

        db = get_db()
        try:
            for f in findings:
                finding_row = Finding(
                    scan_id=self.scan_id,
                    owasp_category=f.owasp_category,
                    owasp_name=f.owasp_name,
                    title=f.title,
                    severity=f.severity,
                    description=f.description,
                    url_affected=f.url_affected,
                    parameter=f.parameter,
                    evidence=f.evidence,
                    cwe_id=f.cwe_id,
                    remediation=f.remediation,
                    found_at=f.found_at
                )
                db.add(finding_row)
                db.commit()
                db.refresh(finding_row)

                # Emit for live UI update
                self.finding_signal.emit({
                    "id": finding_row.id,
                    "owasp_category": f.owasp_category,
                    "owasp_name": f.owasp_name,
                    "title": f.title,
                    "severity": f.severity.value,
                    "url_affected": f.url_affected,
                    "found_at": f.found_at.strftime("%H:%M:%S")
                })
        finally:
            db.close()

    def _finalize_scan(self, status: ScanStatus):
        db = get_db()
        try:
            scan = db.query(Scan).filter(Scan.id == self.scan_id).first()
            if scan:
                scan.status = status
                scan.finished_at = datetime.now(timezone.utc)
                db.commit()
        finally:
            db.close()

    def _handle_cancellation(self):
        self._log("WARNING", f"Scan #{self.scan_id} was cancelled by operator.")
        self._finalize_scan(ScanStatus.CANCELLED)
        self.finished_signal.emit(self.scan_id, False, "Scan was cancelled.")

    def _send_critical_alerts(self, critical_findings: list[ScanFinding]):
        """Trigger SMTP alert to admin/operator."""
        db = get_db()
        try:
            scan = db.query(Scan).filter(Scan.id == self.scan_id).first()
            if not scan:
                return
            user = db.query(User).filter(User.id == scan.created_by).first()
            if user and user.email:
                for f in critical_findings[:3]:  # Alert top 3 criticals
                    send_critical_alert(
                        user.email,
                        user.full_name,
                        self.target_url,
                        f.title,
                        f.severity.value,
                        f.description
                    )
        except Exception as e:
            self._log("WARNING", f"Failed to send email alert: {e}")
        finally:
            db.close()
