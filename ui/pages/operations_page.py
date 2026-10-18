"""
OBSERVER — Operations Page (Phase 3)
Full scan management: add targets, launch scans, live results, report generation.
"""
import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger("observer.operations")

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QSplitter, QTextEdit, QTableWidget,
    QTableWidgetItem, QHeaderView, QDialog, QLineEdit,
    QCheckBox, QGridLayout, QAbstractItemView, QSizePolicy,
    QMessageBox, QComboBox, QPushButton
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
from PyQt6.QtGui import QFont, QColor

from core.database import (
    get_db, Target, TargetStatus, Scan, ScanStatus,
    Finding, Severity, ScanLog, LogLevel
)
from core.rbac import session, Permission
from ui.design import theme as T
from ui.design.widgets import (
    PrimaryButton, SecondaryButton, DangerButton, GhostButton,
    Card, SectionLabel, AlertBanner, LoadingSpinner,
    SeverityBadge, StatusDot, HudFrame, LabeledInput
)


# ─── Add Target Dialog ────────────────────────────────────────────────────────

class AddTargetDialog(QDialog):
    """Dialog to propose / add a new scan target."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Scan Target")
        self.setMinimumWidth(480)
        self.setStyleSheet(f"background: {T.c('bg_primary')};")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        title = QLabel("New Scan Target")
        title.setFont(QFont(T.FONT_UI, T.FONT_SIZE_LG, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")
        layout.addWidget(title)

        desc = QLabel(
            "Add a target URL for vulnerability scanning. "
            "Targets require admin approval before a scan can be launched."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;")
        layout.addWidget(desc)

        self.alert = AlertBanner("error")
        layout.addWidget(self.alert)

        self.url_input = LabeledInput("Target URL", "https://target.example.com")
        self.label_input = LabeledInput("Label (optional)", "Production API")
        self.notes_input = LabeledInput("Notes (optional)", "Authorized by security team on...")

        for w in [self.url_input, self.label_input, self.notes_input]:
            layout.addWidget(w)

        # Warning
        warn = QFrame()
        warn.setStyleSheet(
            f"background: {T.c('severity_medium')}0f; border: 1px solid {T.c('severity_medium')}44; "
            f"border-radius: {T.RADIUS_MD}px;"
        )
        wl = QHBoxLayout(warn)
        wl.setContentsMargins(12, 8, 12, 8)
        wl.setSpacing(8)
        wi = QLabel("⚠")
        wi.setStyleSheet(f"color: {T.c('severity_medium')}; background: transparent; font-size: 14px;")
        wt = QLabel("Only scan systems you are explicitly authorized to test.")
        wt.setWordWrap(True)
        wt.setStyleSheet(f"color: {T.c('severity_medium')}; font-size: {T.FONT_SIZE_XS}px; background: transparent;")
        wl.addWidget(wi)
        wl.addWidget(wt, 1)
        layout.addWidget(warn)

        # Buttons
        btn_layout = QHBoxLayout()
        cancel_btn = SecondaryButton("Cancel")
        cancel_btn.setAutoDefault(False)
        cancel_btn.clicked.connect(self.reject)
        self.submit_btn = PrimaryButton("Add & Approve")
        self.submit_btn.setDefault(True)
        self.submit_btn.setAutoDefault(True)
        self.submit_btn.clicked.connect(self._submit)

        # Enter/Return key submissions on all inputs
        self.url_input.input.returnPressed.connect(self._submit)
        self.label_input.input.returnPressed.connect(self._submit)
        self.notes_input.input.returnPressed.connect(self._submit)

        btn_layout.addWidget(cancel_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.submit_btn)
        layout.addLayout(btn_layout)

        self.result_target = None

    def _submit(self):
        url = self.url_input.text().strip()
        logger.info("--- AddTargetDialog._submit() called ---")
        logger.info("URL received from form: %r", url)
        logger.info("Session: user_id=%s, role=%s, is_admin=%s, is_authenticated=%s",
                    session.user_id, session.role, session.is_admin_user(), session.is_authenticated)

        if not url:
            logger.warning("Validation failed: URL is empty")
            self.alert.show_message("URL is required.")
            return
        if not url.startswith(("http://", "https://")):
            logger.warning("Validation failed: URL does not start with http(s)://")
            self.alert.show_message("URL must start with http:// or https://")
            return

        from core.config import config
        logger.info("DATABASE_URL in use: %s", config.DATABASE_URL)
        logger.info("DB file path: %s  |  exists: %s", config.DB_PATH, config.DB_PATH.exists())

        db = get_db()
        try:
            status = TargetStatus.APPROVED  # All users add targets directly as approved
            logger.info("Target status will be: %s", status.value)

            # Ensure valid creator_id even if session is unauthenticated or user_id missing
            creator_id = session.user_id if (session.is_authenticated and session.user_id) else None
            if not creator_id:
                first_admin = db.query(User).filter(User.role == UserRole.ADMIN).first()
                creator_id = first_admin.id if first_admin else 1

            target = Target(
                url=url,
                label=self.label_input.text().strip() or None,
                notes=self.notes_input.text().strip() or None,
                status=status,
                created_by=creator_id,
                approved_by=creator_id,
                approved_at=datetime.now(timezone.utc),
            )
            logger.info("Calling db.add(target)...")
            db.add(target)
            logger.info("Calling db.commit()...")
            db.commit()
            logger.info("Calling db.refresh(target)...")
            db.refresh(target)
            logger.info("SUCCESS: Target written to DB — id=%s, url=%s, status=%s, created_by=%s",
                        target.id, target.url, target.status.value, target.created_by)
            self.result_target = target
            self.accept()
        except Exception as e:
            import traceback
            logger.error("EXCEPTION in _submit(): %s", e)
            logger.error("Full traceback:\n%s", traceback.format_exc())
            self.alert.show_message(f"Failed to add target: {e}")
        finally:
            db.close()
            logger.info("DB session closed.")



# ─── Scan Launch Dialog ───────────────────────────────────────────────────────

class LaunchScanDialog(QDialog):
    """Legal disclaimer + OWASP category selection before scan launch."""

    OWASP_CATEGORIES = [
        ("A01", "Broken Access Control"),
        ("A02", "Cryptographic Failures"),
        ("A03", "Injection (SQL, XSS, Command)"),
        ("A04", "Insecure Design"),
        ("A05", "Security Misconfiguration"),
        ("A06", "Vulnerable & Outdated Components"),
        ("A07", "Identification & Auth Failures"),
        ("A08", "Software & Data Integrity Failures"),
        ("A09", "Security Logging & Monitoring Failures"),
        ("A10", "Server-Side Request Forgery (SSRF)"),
    ]

    def __init__(self, target: Target, parent=None):
        super().__init__(parent)
        self.target = target
        self.setWindowTitle("Launch Vulnerability Scan")
        self.setMinimumWidth(560)
        self.setMaximumHeight(820)
        self.setStyleSheet(f"background: {T.c('bg_primary')};")

        # Outer layout contains only the scroll area
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet(f"background: {T.c('bg_primary')}; border: none;")

        content_widget = QWidget()
        content_widget.setStyleSheet(f"background: {T.c('bg_primary')};")

        layout = QVBoxLayout(content_widget)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        scroll.setWidget(content_widget)
        outer_layout.addWidget(scroll)

        title = QLabel("Launch Scan")
        title.setFont(QFont(T.FONT_UI, T.FONT_SIZE_LG, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")

        target_frame = QFrame()
        target_frame.setStyleSheet(
            f"background: {T.c('bg_elevated')}; border: 1px solid {T.c('border')}; "
            f"border-radius: {T.RADIUS_MD}px;"
        )
        tf_layout = QVBoxLayout(target_frame)
        tf_layout.setContentsMargins(12, 10, 12, 10)
        tf_layout.setSpacing(4)
        QLabel("TARGET").setParent(target_frame)
        tl1 = QLabel("TARGET")
        tl1.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; letter-spacing: 2px; background: transparent;"
        )
        tl2 = QLabel(target.url)
        tl2.setStyleSheet(
            f"color: {T.c('accent')}; font-size: {T.FONT_SIZE_SM}px; font-family: {T.FONT_MONO}; "
            f"font-weight: 600; background: transparent;"
        )
        tl2.setWordWrap(True)
        tf_layout.addWidget(tl1)
        tf_layout.addWidget(tl2)
        if target.label:
            tl3 = QLabel(target.label)
            tl3.setStyleSheet(f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; background: transparent;")
            tf_layout.addWidget(tl3)

        layout.addWidget(title)
        layout.addWidget(target_frame)

        # Category selection
        cat_label = QLabel("SELECT OWASP CATEGORIES")
        cat_label.setStyleSheet(
            f"color: {T.c('text_secondary')}; font-size: {T.FONT_SIZE_XS}px; "
            f"letter-spacing: 2px; font-weight: 600; background: transparent;"
        )
        layout.addWidget(cat_label)

        cat_frame = QFrame()
        cat_frame.setStyleSheet(
            f"background: {T.c('bg_card')}; border: 1px solid {T.c('border')}; "
            f"border-radius: {T.RADIUS_MD}px;"
        )
        cf_layout = QVBoxLayout(cat_frame)
        cf_layout.setContentsMargins(12, 10, 12, 10)
        cf_layout.setSpacing(6)

        # Select all
        self.select_all_cb = QCheckBox("Select All")
        self.select_all_cb.setChecked(True)
        self.select_all_cb.stateChanged.connect(self._toggle_all)
        self.select_all_cb.setStyleSheet(f"color: {T.c('text_secondary')}; font-weight: 600; background: transparent;")
        cf_layout.addWidget(self.select_all_cb)

        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background: {T.c('border')}; border: none;")
        cf_layout.addWidget(sep)

        self._cat_checkboxes = []
        grid = QGridLayout()
        grid.setSpacing(6)
        for i, (code, name) in enumerate(self.OWASP_CATEGORIES):
            cb = QCheckBox(f"{code} — {name}")
            cb.setChecked(True)
            cb.setStyleSheet(f"color: {T.c('text_secondary')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;")
            cb.stateChanged.connect(self._update_select_all)
            self._cat_checkboxes.append((code, cb))
            grid.addWidget(cb, i // 2, i % 2)
        cf_layout.addLayout(grid)
        layout.addWidget(cat_frame)

        # ── Optional: Pre-scan Authentication ────────────────────────────────
        self._enable_auth_cb = QCheckBox("🔐  Enable pre-scan authentication (optional)")
        self._enable_auth_cb.setStyleSheet(
            f"color: {T.c('text_secondary')}; font-weight: 600; font-size: {T.FONT_SIZE_SM}px; "
            f"background: transparent;"
        )
        self._enable_auth_cb.stateChanged.connect(self._toggle_auth_section)
        layout.addWidget(self._enable_auth_cb)

        self._auth_fields_frame = QFrame()
        self._auth_fields_frame.setStyleSheet(
            f"background: {T.c('bg_card')}; border: 1px solid {T.c('border')}; "
            f"border-radius: {T.RADIUS_MD}px;"
        )
        auth_fl = QVBoxLayout(self._auth_fields_frame)
        auth_fl.setContentsMargins(14, 12, 14, 12)
        auth_fl.setSpacing(10)

        auth_desc = QLabel(
            "If the target requires login, provide credentials here. "
            "The scanner will authenticate before crawling and use the session "
            "for all subsequent requests (including API endpoints)."
        )
        auth_desc.setWordWrap(True)
        auth_desc.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; background: transparent;"
        )
        auth_fl.addWidget(auth_desc)

        self._login_url_input  = LabeledInput("Login URL",  "http://127.0.0.1:8000/accounts/login/")
        self._login_user_input = LabeledInput("Username / E-mail", "admin")
        self._login_pass_input = LabeledInput("Password", "", password=True)
        for w in [self._login_url_input, self._login_user_input, self._login_pass_input]:
            auth_fl.addWidget(w)

        self._auth_fields_frame.setVisible(False)  # collapsed by default
        layout.addWidget(self._auth_fields_frame)

        # ── Optional: API Endpoints ───────────────────────────────────────────
        self._enable_api_cb = QCheckBox("🔌  Add API endpoints to test (optional)")
        self._enable_api_cb.setStyleSheet(
            f"color: {T.c('text_secondary')}; font-weight: 600; font-size: {T.FONT_SIZE_SM}px; "
            f"background: transparent;"
        )
        self._enable_api_cb.stateChanged.connect(self._toggle_api_section)
        layout.addWidget(self._enable_api_cb)

        self._api_fields_frame = QFrame()
        self._api_fields_frame.setStyleSheet(
            f"background: {T.c('bg_card')}; border: 1px solid {T.c('border')}; "
            f"border-radius: {T.RADIUS_MD}px;"
        )
        api_fl = QVBoxLayout(self._api_fields_frame)
        api_fl.setContentsMargins(14, 12, 14, 12)
        api_fl.setSpacing(8)

        api_desc = QLabel(
            "Declare API endpoints to test in addition to the automatic crawl. "
            "Parameters are sent as a JSON body (for POST/PUT/DELETE) or query string (for GET)."
        )
        api_desc.setWordWrap(True)
        api_desc.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; background: transparent;"
        )
        api_fl.addWidget(api_desc)

        # Table
        self._api_table = QTableWidget(0, 3)
        self._api_table.setHorizontalHeaderLabels(["URL", "Method", "Parameters (JSON)"])
        self._api_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._api_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self._api_table.horizontalHeader().resizeSection(1, 80)
        self._api_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._api_table.verticalHeader().setVisible(False)
        self._api_table.setAlternatingRowColors(True)
        self._api_table.setMinimumHeight(130)
        self._api_table.setStyleSheet(
            f"QTableWidget {{ background: {T.c('bg_elevated')}; "
            f"color: {T.c('text_primary')}; "
            f"border: 1px solid {T.c('border')}; "
            f"gridline-color: {T.c('border')}; "
            f"font-size: {T.FONT_SIZE_SM}px; }}"
            f"QHeaderView::section {{ background: {T.c('bg_secondary')}; "
            f"color: {T.c('text_secondary')}; "
            f"border: none; border-bottom: 1px solid {T.c('border')}; "
            f"padding: 4px 8px; font-size: {T.FONT_SIZE_XS}px; font-weight: 600; "
            f"letter-spacing: 1px; }}"
            f"QTableWidget::item {{ padding: 4px 8px; }}"
            f"QTableWidget::item:selected {{ background: {T.c('accent')}22; }}"
        )
        api_fl.addWidget(self._api_table)

        # Row management buttons
        row_btn_layout = QHBoxLayout()
        add_row_btn = QPushButton("+ Add Row")
        add_row_btn.setStyleSheet(
            f"background: transparent; color: {T.c('accent')}; "
            f"border: 1px solid {T.c('accent')}44; border-radius: {T.RADIUS_MD}px; "
            f"padding: 4px 12px; font-size: {T.FONT_SIZE_SM}px;"
        )
        add_row_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        add_row_btn.clicked.connect(self._add_endpoint_row)

        remove_row_btn = QPushButton("✕ Remove Row")
        remove_row_btn.setStyleSheet(
            f"background: transparent; color: {T.c('severity_medium')}; "
            f"border: 1px solid {T.c('severity_medium')}44; border-radius: {T.RADIUS_MD}px; "
            f"padding: 4px 12px; font-size: {T.FONT_SIZE_SM}px;"
        )
        remove_row_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        remove_row_btn.clicked.connect(self._remove_endpoint_row)

        row_btn_layout.addWidget(add_row_btn)
        row_btn_layout.addWidget(remove_row_btn)
        row_btn_layout.addStretch()
        api_fl.addLayout(row_btn_layout)

        self._api_fields_frame.setVisible(False)  # collapsed by default
        layout.addWidget(self._api_fields_frame)

        # ── Scroll area wrapper (dialog can be tall) ──────────────────────────
        # Initialize result containers
        self.login_url      = ""
        self.login_username = ""
        self.login_password = ""
        self.api_endpoints: list[dict] = []

        # Legal disclaimer
        disc_frame = QFrame()
        disc_frame.setStyleSheet(
            f"background: {T.c('severity_critical')}0a; border: 1px solid {T.c('severity_critical')}44; "
            f"border-radius: {T.RADIUS_MD}px;"
        )
        dl = QVBoxLayout(disc_frame)
        dl.setContentsMargins(14, 12, 14, 12)
        dl.setSpacing(8)
        disc_title = QLabel("⚠  LEGAL DISCLAIMER")
        disc_title.setStyleSheet(
            f"color: {T.c('severity_critical')}; font-size: {T.FONT_SIZE_SM}px; "
            f"font-weight: 700; letter-spacing: 1px; background: transparent;"
        )
        disc_text = QLabel(
            "By launching this scan, you confirm that you have explicit written authorization "
            "to test the target system. Unauthorized scanning is illegal and may result in "
            "criminal prosecution. This scan is logged and attributed to your account."
        )
        disc_text.setWordWrap(True)
        disc_text.setStyleSheet(f"color: {T.c('severity_high')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;")

        self.auth_checkbox = QCheckBox(
            "I confirm I am authorized to scan this target and accept full legal responsibility."
        )
        self.auth_checkbox.setStyleSheet(
            f"color: {T.c('text_primary')}; font-size: {T.FONT_SIZE_SM}px; font-weight: 600; background: transparent;"
        )
        dl.addWidget(disc_title)
        dl.addWidget(disc_text)
        dl.addWidget(self.auth_checkbox)
        layout.addWidget(disc_frame)

        # Buttons
        btn_layout = QHBoxLayout()
        cancel_btn = SecondaryButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        self.launch_btn = DangerButton("⚡  LAUNCH SCAN")
        self.launch_btn.setStyleSheet(
            f"background: {T.c('severity_critical')}22; color: {T.c('severity_critical')}; "
            f"border: 1px solid {T.c('severity_critical')}; border-radius: {T.RADIUS_MD}px; "
            f"padding: 10px 20px; font-weight: 700; font-size: {T.FONT_SIZE_SM}px; letter-spacing: 1px;"
        )
        self.launch_btn.clicked.connect(self._launch)
        btn_layout.addWidget(cancel_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.launch_btn)
        layout.addLayout(btn_layout)

        self.selected_categories = []

    def _toggle_all(self, state):
        for _, cb in self._cat_checkboxes:
            cb.blockSignals(True)
            cb.setChecked(state == Qt.CheckState.Checked.value)
            cb.blockSignals(False)

    def _update_select_all(self):
        all_checked = all(cb.isChecked() for _, cb in self._cat_checkboxes)
        self.select_all_cb.blockSignals(True)
        self.select_all_cb.setChecked(all_checked)
        self.select_all_cb.blockSignals(False)

    # ── Auth section helpers ───────────────────────────────────────────────────

    def _toggle_auth_section(self, state: int):
        """Show/hide the authentication fields based on checkbox state."""
        visible = state == Qt.CheckState.Checked.value
        self._auth_fields_frame.setVisible(visible)

    # ── API endpoints section helpers ─────────────────────────────────────────

    def _toggle_api_section(self, state: int):
        """Show/hide the API endpoints table based on checkbox state."""
        visible = state == Qt.CheckState.Checked.value
        self._api_fields_frame.setVisible(visible)

    def _add_endpoint_row(self):
        """Append a new empty row to the API endpoints table."""
        row = self._api_table.rowCount()
        self._api_table.insertRow(row)

        # URL cell
        url_item = QTableWidgetItem("http://")
        self._api_table.setItem(row, 0, url_item)

        # Method combobox
        method_cb = QComboBox()
        method_cb.addItems(["POST", "GET", "PUT", "DELETE"])
        method_cb.setStyleSheet(
            f"background: {T.c('bg_elevated')}; color: {T.c('text_primary')}; "
            f"border: 1px solid {T.c('border')}; border-radius: 4px; padding: 2px 6px;"
        )
        self._api_table.setCellWidget(row, 1, method_cb)

        # Params cell — JSON
        params_item = QTableWidgetItem("{}")
        self._api_table.setItem(row, 2, params_item)

    def _remove_endpoint_row(self):
        """Remove the currently selected row from the API endpoints table."""
        row = self._api_table.currentRow()
        if row >= 0:
            self._api_table.removeRow(row)

    def _launch(self):
        if not self.auth_checkbox.isChecked():
            QMessageBox.warning(self, "Authorization Required",
                "You must confirm authorization before launching a scan.")
            return

        self.selected_categories = [code for code, cb in self._cat_checkboxes if cb.isChecked()]
        if not self.selected_categories:
            QMessageBox.warning(self, "No Categories", "Select at least one OWASP category.")
            return

        # Collect auth credentials
        if self._enable_auth_cb.isChecked():
            self.login_url      = self._login_url_input.text().strip()
            self.login_username = self._login_user_input.text().strip()
            self.login_password = self._login_pass_input.text().strip()
        else:
            self.login_url = self.login_username = self.login_password = ""

        # Collect API endpoints
        self.api_endpoints = []
        if self._enable_api_cb.isChecked():
            for row in range(self._api_table.rowCount()):
                url_item   = self._api_table.item(row, 0)
                method_cb  = self._api_table.cellWidget(row, 1)
                params_item = self._api_table.item(row, 2)

                url = url_item.text().strip() if url_item else ""
                method = method_cb.currentText() if method_cb else "GET"
                params_text = params_item.text().strip() if params_item else "{}"

                if not url or url == "http://":
                    continue

                try:
                    params = json.loads(params_text) if params_text else {}
                except json.JSONDecodeError:
                    QMessageBox.warning(
                        self, "Invalid JSON",
                        f"Row {row + 1}: Parameters must be valid JSON (e.g. {{\"key\": \"value\"}})."
                    )
                    return

                self.api_endpoints.append({"url": url, "method": method, "params": params})

        self.accept()


# ─── Finding Row Widget ───────────────────────────────────────────────────────

class FindingRow(QFrame):
    """A single vulnerability finding displayed in the results area."""

    def __init__(self, finding: Finding, parent=None):
        super().__init__(parent)
        self.setProperty("class", "card")
        self.setStyleSheet(
            f"QFrame {{ background: {T.c('bg_card')}; border: 1px solid {T.c('border')}; "
            f"border-radius: {T.RADIUS_MD}px; margin: 2px 0; }}"
            f"QFrame:hover {{ border-color: {T.c('border_focus')}; }}"
        )

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(12)

        # Severity badge
        badge = SeverityBadge(finding.severity.value)
        badge.setFixedWidth(68)
        layout.addWidget(badge, alignment=Qt.AlignmentFlag.AlignVCenter)

        # Info
        info_layout = QVBoxLayout()
        info_layout.setSpacing(3)
        title_lbl = QLabel(finding.title)
        title_lbl.setFont(QFont(T.FONT_UI, T.FONT_SIZE_SM, QFont.Weight.Bold))
        title_lbl.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")

        meta_lbl = QLabel(
            f"{finding.owasp_category} — {finding.owasp_name}  ·  "
            f"{finding.found_at.strftime('%H:%M:%S') if finding.found_at else ''}"
        )
        meta_lbl.setStyleSheet(f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; background: transparent;")

        if finding.url_affected:
            url_lbl = QLabel(finding.url_affected[:80] + ("…" if len(finding.url_affected) > 80 else ""))
            url_lbl.setStyleSheet(
                f"color: {T.c('text_secondary')}; font-size: {T.FONT_SIZE_XS}px; "
                f"font-family: {T.FONT_MONO}; background: transparent;"
            )
            info_layout.addWidget(url_lbl)

        info_layout.addWidget(title_lbl)
        info_layout.addWidget(meta_lbl)
        layout.addLayout(info_layout, 1)


# ─── Operations Page ─────────────────────────────────────────────────────────

class OperationsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_scan_id = None
        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._refresh_live_findings)
        self._setup_ui()

    def _setup_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ── Top bar ────────────────────────────────────────────────────────
        topbar = QFrame()
        topbar.setFixedHeight(56)
        topbar.setStyleSheet(
            f"background: {T.c('bg_secondary')}; border-bottom: 1px solid {T.c('border')};"
        )
        tb_layout = QHBoxLayout(topbar)
        tb_layout.setContentsMargins(24, 0, 24, 0)
        tb_layout.setSpacing(12)

        title_lbl = QLabel("Operations")
        title_lbl.setFont(QFont(T.FONT_UI, T.FONT_SIZE_LG, QFont.Weight.Bold))
        title_lbl.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;"
        )

        self.add_target_btn = SecondaryButton("+ Add Target")
        self.new_scan_btn = PrimaryButton("⚡ New Scan")
        self.new_scan_btn.setEnabled(False)
        self.report_btn = SecondaryButton("📄 Generate Report")
        self.report_btn.setEnabled(False)

        self.add_target_btn.clicked.connect(self._add_target)
        self.new_scan_btn.clicked.connect(self._new_scan)
        self.report_btn.clicked.connect(self._generate_report)

        tb_layout.addWidget(title_lbl)
        tb_layout.addWidget(self.status_label)
        tb_layout.addStretch()
        tb_layout.addWidget(self.report_btn)
        tb_layout.addWidget(self.add_target_btn)
        tb_layout.addWidget(self.new_scan_btn)

        root_layout.addWidget(topbar)

        # ── Main content splitter ──────────────────────────────────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet(f"QSplitter::handle {{ background: {T.c('border')}; width: 1px; }}")

        # Left: targets list
        left_panel = QWidget()
        left_panel.setMinimumWidth(280)
        left_panel.setMaximumWidth(380)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(16, 16, 8, 16)
        left_layout.setSpacing(8)

        targets_header = QHBoxLayout()
        targets_header.setSpacing(8)
        targets_header.addWidget(SectionLabel("Approved Targets"))
        targets_header.addStretch()
        self.refresh_btn = GhostButton("⟳ Refresh")
        self.refresh_btn.setFixedHeight(26)
        self.refresh_btn.setToolTip("Reload the target list from the database")
        self.refresh_btn.clicked.connect(self._load_targets)
        targets_header.addWidget(self.refresh_btn)
        left_layout.addLayout(targets_header)

        self.targets_list = QTableWidget()
        self.targets_list.setColumnCount(2)
        self.targets_list.setHorizontalHeaderLabels(["Target", "Status"])
        self.targets_list.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.targets_list.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.targets_list.horizontalHeader().resizeSection(1, 80)
        self.targets_list.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.targets_list.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.targets_list.verticalHeader().setVisible(False)
        self.targets_list.setAlternatingRowColors(True)
        self.targets_list.itemSelectionChanged.connect(self._on_target_selected)
        left_layout.addWidget(self.targets_list)

        # Right: findings + scan info
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(8, 16, 24, 16)
        right_layout.setSpacing(12)

        # Scan status bar
        self.scan_status_frame = QFrame()
        self.scan_status_frame.setProperty("class", "card-elevated")
        self.scan_status_frame.setFixedHeight(60)
        self.scan_status_frame.setVisible(False)
        sf_layout = QHBoxLayout(self.scan_status_frame)
        sf_layout.setContentsMargins(16, 0, 16, 0)
        self.scan_status_dot = StatusDot("idle")
        self.scan_status_text = QLabel("No active scan")
        self.scan_status_text.setStyleSheet(f"color: {T.c('text_primary')}; font-weight: 600; background: transparent;")
        self.scan_progress_text = QLabel("")
        self.scan_progress_text.setStyleSheet(f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;")
        sf_layout.addWidget(self.scan_status_dot)
        sf_layout.addWidget(self.scan_status_text)
        sf_layout.addStretch()
        sf_layout.addWidget(self.scan_progress_text)
        right_layout.addWidget(self.scan_status_frame)

        # Findings section
        right_layout.addWidget(SectionLabel("Findings"))

        self.alert = AlertBanner("info")
        right_layout.addWidget(self.alert)

        # Findings scroll area
        findings_scroll = QScrollArea()
        findings_scroll.setWidgetResizable(True)
        findings_scroll.setFrameShape(QFrame.Shape.NoFrame)
        findings_scroll.setStyleSheet(f"background: transparent; border: none;")

        self.findings_container = QWidget()
        self.findings_container.setStyleSheet(f"background: transparent;")
        self.findings_layout = QVBoxLayout(self.findings_container)
        self.findings_layout.setContentsMargins(0, 0, 0, 0)
        self.findings_layout.setSpacing(6)
        self.findings_layout.addStretch()

        findings_scroll.setWidget(self.findings_container)
        right_layout.addWidget(findings_scroll, 1)

        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([300, 900])
        root_layout.addWidget(splitter, 1)

    def on_enter(self):
        self._load_targets()

    def _load_targets(self):
        logger.info("--- _load_targets() called ---")
        logger.info("Session: user_id=%s, role=%s, is_admin=%s",
                    session.user_id, session.role, session.is_admin_user())
        db = get_db()
        try:
            q = db.query(Target).filter(Target.created_by == session.user_id)
            logger.info("Filtering targets by created_by=%s", session.user_id)
            targets = q.order_by(Target.created_at.desc()).all()
            logger.info("DB query returned %d target(s)", len(targets))
            for t in targets:
                logger.info("  -> id=%s url=%s status=%s created_by=%s",
                            t.id, t.url, t.status.value, t.created_by)

            self.targets_list.clearContents()
            self.targets_list.setRowCount(len(targets))
            self._target_ids = []
            for i, t in enumerate(targets):
                url_item = QTableWidgetItem(t.label or t.url[:50])
                url_item.setToolTip(t.url)
                status_item = QTableWidgetItem(t.status.value.upper())
                color = {
                    "approved": T.c("severity_low"),
                    "pending": T.c("severity_medium"),
                    "rejected": T.c("severity_critical"),
                }.get(t.status.value, T.c("text_muted"))
                status_item.setForeground(QColor(color))
                self.targets_list.setItem(i, 0, url_item)
                self.targets_list.setItem(i, 1, status_item)
                self._target_ids.append(t.id)
            self.targets_list.viewport().update()
            logger.info("Table updated: %d rows displayed", self.targets_list.rowCount())
        except Exception as e:
            import traceback
            logger.error("EXCEPTION in _load_targets(): %s", e)
            logger.error("Full traceback:\n%s", traceback.format_exc())
        finally:
            db.close()

    def _on_target_selected(self):
        rows = self.targets_list.selectedItems()
        if not rows:
            self.new_scan_btn.setEnabled(False)
            return

        row = self.targets_list.currentRow()
        if row < 0 or row >= len(self._target_ids):
            return

        db = get_db()
        try:
            target = db.query(Target).filter(
                Target.id == self._target_ids[row]
            ).first()
            approved = target and target.status == TargetStatus.APPROVED
            self.new_scan_btn.setEnabled(approved)
            if not approved:
                self.status_label.setText("Target pending approval — cannot scan")
            else:
                self.status_label.setText(f"Selected: {target.url[:60]}")
                latest_scan = (
                    db.query(Scan)
                    .filter(Scan.target_id == target.id, Scan.status == ScanStatus.COMPLETED)
                    .order_by(Scan.finished_at.desc())
                    .first()
                )
                if latest_scan:
                    self._current_scan_id = latest_scan.id
                    self.report_btn.setEnabled(True)
        finally:
            db.close()

    def _add_target(self):
        logger.info("--- _add_target() called (user clicked + Add Target) ---")
        dlg = AddTargetDialog(self)
        result = dlg.exec()
        logger.info("AddTargetDialog closed — result code: %s (Accepted=%s)",
                    result, result == QDialog.DialogCode.Accepted)
        if result == QDialog.DialogCode.Accepted:
            logger.info("Dialog accepted — result_target: %s",
                        getattr(dlg.result_target, 'id', None))
            msg = "Target added and approved."
            self._load_targets()
            QTimer.singleShot(50, self._load_targets)
            logger.info("Showing alert: %s", msg)
            self.alert.show_message(msg, auto_hide_ms=4000)
        else:
            logger.info("Dialog was cancelled or rejected — no target saved")

    def _new_scan(self):
        row = self.targets_list.currentRow()
        if row < 0:
            return

        db = get_db()
        try:
            target = db.query(Target).filter(
                Target.id == self._target_ids[row]
            ).first()
            if not target:
                return

            dlg = LaunchScanDialog(target, self)
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return

            # Create scan record
            scan = Scan(
                target_id=target.id,
                created_by=session.user_id,
                status=ScanStatus.QUEUED,
                config_json=json.dumps({
                    "categories": dlg.selected_categories,
                    "login_url": dlg.login_url or None,
                    "login_username": dlg.login_username or None,
                    "api_endpoints": dlg.api_endpoints or [],
                }),
                started_at=datetime.now(timezone.utc),
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)
            self._current_scan_id = scan.id

            # Log the start
            log = ScanLog(
                scan_id=scan.id,
                level=LogLevel.INFO,
                message=f"[OBSERVER] Scan started on {target.url}",
                module="engine",
            )
            db.add(log)
            db.commit()
            target_url = target.url
        finally:
            db.close()

        # Show status
        self.scan_status_frame.setVisible(True)
        self.scan_status_dot.set_status("active")
        self.scan_status_text.setText("Scan in Progress")
        self.scan_progress_text.setText("Initializing engine…")
        self.report_btn.setEnabled(False)
        self.new_scan_btn.setEnabled(False)

        # Clear previous findings
        self._clear_findings()
        self.alert.show_message("Scan started — running crawler & OWASP detectors…", auto_hide_ms=4000)

        # Launch real background ScanEngineWorker (Phase 4)
        # IMPORTANT: never use `scan` object after db.close() — use self._current_scan_id instead
        try:
            logger.info("--- Launching ScanEngineWorker for Scan #%d on %s ---", self._current_scan_id, target_url)
            logger.info("OWASP categories selected: %s", dlg.selected_categories)
            from scanner.engine import ScanEngineWorker
            self._scan_worker = ScanEngineWorker(
                scan_id=self._current_scan_id,
                target_url=target_url,
                categories=dlg.selected_categories,
                max_depth=3,
                max_pages=25,
                timeout=8,
                login_url=dlg.login_url or None,
                login_username=dlg.login_username or None,
                login_password=dlg.login_password or None,
                api_endpoints=dlg.api_endpoints or None,
            )
            self._scan_worker.log_signal.connect(self._on_engine_log)
            self._scan_worker.progress_signal.connect(self._on_scan_progress)
            self._scan_worker.finding_signal.connect(self._on_live_finding_discovered)
            self._scan_worker.finished_signal.connect(self._on_scan_worker_finished)
            self._scan_worker.start()
            logger.info("ScanEngineWorker thread started successfully.")
        except Exception as e:
            import traceback
            err_trace = traceback.format_exc()
            logger.error("FAILED to launch ScanEngineWorker: %s\n%s", e, err_trace)
            self.scan_status_dot.set_status("error")
            self.scan_status_text.setText("Scan Failed to Start")
            self.scan_progress_text.setText(str(e))
            self.alert.show_message(f"Scan launch error: {e}", auto_hide_ms=8000)
            self.new_scan_btn.setEnabled(True)

    def _on_engine_log(self, ts: str, level: str, msg: str, module: str):
        short_msg = msg[:80] + "…" if len(msg) > 80 else msg
        self.scan_progress_text.setText(f"[{module}] {short_msg}")

    def _on_scan_progress(self, pct: int, status_text: str):
        self.scan_progress_text.setText(f"[{pct}%] {status_text}")

    def _on_live_finding_discovered(self, f_data: dict):
        """Immediately display finding in the UI list."""
        class MockFinding:
            def __init__(self, d):
                self.title = d["title"]
                self.severity = Severity(d["severity"])
                self.owasp_category = d["owasp_category"]
                self.owasp_name = d["owasp_name"]
                self.url_affected = d["url_affected"]
                self.found_at = datetime.now()

        row = FindingRow(MockFinding(f_data))
        self.findings_layout.insertWidget(0, row)

    def _on_scan_worker_finished(self, scan_id: int, success: bool, message: str):
        logger.info("ScanEngineWorker finished — scan_id=%s, success=%s, msg=%s",
                    scan_id, success, message)
        self._on_target_selected()  # re-evaluate buttons
        if success:
            self.scan_status_dot.set_status("success")
            self.scan_status_text.setText("Scan Completed")
            self.scan_progress_text.setText(f"Finished at {datetime.now().strftime('%H:%M:%S')}")
            self.report_btn.setEnabled(True)
            self.alert.show_message("✓ Scan finished! Click 'Generate Report' to create PDF audit documentation.", auto_hide_ms=0)
        else:
            self.scan_status_dot.set_status("error")
            self.scan_status_text.setText("Scan Failed / Cancelled")
            self.scan_progress_text.setText(message)
            self.alert.show_message(f"Scan ended with error: {message}", auto_hide_ms=6000)

    def _refresh_live_findings(self):
        if not self._current_scan_id:
            return
        db = get_db()
        try:
            scan = db.query(Scan).filter(Scan.id == self._current_scan_id).first()
            if not scan:
                return

            findings = db.query(Finding).filter(
                Finding.scan_id == self._current_scan_id
            ).order_by(Finding.found_at.desc()).all()

            self._clear_findings()
            for f in findings:
                row = FindingRow(f)
                self.findings_layout.insertWidget(0, row)

            counts = len(findings)
            if counts:
                self.scan_progress_text.setText(f"{counts} finding(s) detected")
        finally:
            db.close()

    def _clear_findings(self):
        while self.findings_layout.count() > 1:  # keep stretch
            item = self.findings_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _generate_report(self):
        logger.info("--- _generate_report() called in OperationsPage (current_scan_id=%s) ---",
                    self._current_scan_id)
        if not self._current_scan_id:
            logger.warning("Cannot generate report: _current_scan_id is None")
            self.alert.show_message("No scan completed yet to generate a report.", auto_hide_ms=4000)
            return
        from ui.pages.reports_page import generate_pdf_report
        success, msg = generate_pdf_report(self._current_scan_id)
        if success:
            logger.info("Report generation succeeded: %s", msg)
            self.alert.show_message(f"✓ {msg}", auto_hide_ms=5000)
        else:
            logger.error("Report generation failed: %s", msg)
            self.alert.show_message(f"✕ {msg}", auto_hide_ms=8000)
