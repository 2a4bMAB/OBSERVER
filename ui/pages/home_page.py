"""
OBSERVER — Home Dashboard (Enhanced HUD Design)
Welcome dashboard with system telemetry, quick-start workflow, and OWASP coverage.
"""
from datetime import datetime, timezone
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QFrame, QGridLayout, QScrollArea, QSizePolicy
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor

from core.rbac import session
from core.database import get_db, Scan, ScanStatus, Finding, Severity, Report
from ui.design import theme as T
from ui.design.widgets import Card, SectionLabel, HudFrame, StatusDot


# ─── Metric Card ──────────────────────────────────────────────────────────────

class DashboardMetricCard(QFrame):
    """Sleek HUD Metric Card with top accent bar and micro-labels."""

    def __init__(self, value: str, label: str, icon: str, accent_color: str | None = None, parent=None):
        super().__init__(parent)
        self.accent_color = accent_color or T.c("border_focus")
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {T.c('bg_card')};
                border: 1px solid {T.c('border')};
                border-top: 2px solid {self.accent_color};
                border-radius: {T.RADIUS_MD}px;
            }}
            QFrame:hover {{
                background-color: {T.c('bg_hover')};
                border-color: {T.c('border_focus')};
            }}
        """)
        self.setFixedHeight(115)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(4)

        # Top row: Icon + Label
        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet(f"font-size: 16px; color: {self.accent_color}; background: transparent;")
        
        name_lbl = QLabel(label.upper())
        name_lbl.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; "
            f"font-weight: 700; letter-spacing: 1.5px; background: transparent;"
        )

        top_row.addWidget(icon_lbl)
        top_row.addWidget(name_lbl)
        top_row.addStretch()
        layout.addLayout(top_row)

        # Big Value
        self.val_label = QLabel(value)
        self.val_label.setFont(QFont(T.FONT_MONO, T.FONT_SIZE_3XL, QFont.Weight.Bold))
        self.val_label.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent; padding-top: 2px;")
        layout.addWidget(self.val_label)

    def set_value(self, val: str):
        self.val_label.setText(val)


# ─── Workflow Step Card ───────────────────────────────────────────────────────

class WorkflowStepCard(QFrame):
    """Step card representing the pentest lifecycle."""

    def __init__(self, step_num: str, title: str, desc: str, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {T.c('bg_card')};
                border: 1px solid {T.c('border')};
                border-radius: {T.RADIUS_MD}px;
            }}
            QFrame:hover {{
                border-color: {T.c('border_focus')};
                background-color: {T.c('bg_elevated')};
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(16)

        # Step Number Badge
        num_frame = QFrame()
        num_frame.setFixedSize(38, 38)
        num_frame.setStyleSheet(f"""
            background-color: {T.c('bg_elevated')};
            border: 1px solid {T.c('border_focus')};
            border-radius: 19px;
        """)
        nf_layout = QVBoxLayout(num_frame)
        nf_layout.setContentsMargins(0, 0, 0, 0)
        nf_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        num_lbl = QLabel(step_num)
        num_lbl.setFont(QFont(T.FONT_MONO, T.FONT_SIZE_SM, QFont.Weight.Bold))
        num_lbl.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")
        nf_layout.addWidget(num_lbl)
        layout.addWidget(num_frame, alignment=Qt.AlignmentFlag.AlignTop)

        # Content
        text_col = QVBoxLayout()
        text_col.setSpacing(4)

        t_lbl = QLabel(title)
        t_lbl.setFont(QFont(T.FONT_UI, T.FONT_SIZE_MD, QFont.Weight.Bold))
        t_lbl.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")

        d_lbl = QLabel(desc)
        d_lbl.setWordWrap(True)
        d_lbl.setStyleSheet(
            f"color: {T.c('text_secondary')}; font-size: {T.FONT_SIZE_SM}px; "
            f"line-height: 1.5; background: transparent;"
        )

        text_col.addWidget(t_lbl)
        text_col.addWidget(d_lbl)
        layout.addLayout(text_col, 1)


# ─── Home Page ────────────────────────────────────────────────────────────────

class HomePage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        # Scroll Area for responsiveness
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("background: transparent; border: none;")

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addWidget(scroll)

        content = QWidget()
        content.setStyleSheet(f"background-color: {T.c('bg_primary')};")
        scroll.setWidget(content)

        layout = QVBoxLayout(content)
        layout.setContentsMargins(36, 32, 36, 40)
        layout.setSpacing(28)

        # ── 1. Hero HUD Header ──────────────────────────────────────────────
        hero = HudFrame()
        hero.setStyleSheet(f"""
            HudFrame {{
                background-color: {T.c('bg_secondary')};
                border: 1px solid {T.c('border')};
                border-radius: {T.RADIUS_LG}px;
            }}
        """)
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(28, 24, 28, 24)
        hero_layout.setSpacing(12)

        # Beacon & Status Bar
        top_hero = QHBoxLayout()
        beacon = QLabel("●  SYSTEM ONLINE  ·  KERNEL V1.0")
        beacon.setStyleSheet(
            f"color: {T.c('severity_low')}; font-size: {T.FONT_SIZE_XS}px; "
            f"font-weight: 700; font-family: {T.FONT_MONO}; letter-spacing: 2px; background: transparent;"
        )
        self.role_badge = QLabel("ROLE: PENTESTER")
        self.role_badge.setStyleSheet(
            f"color: {T.c('text_primary')}; font-size: {T.FONT_SIZE_XS}px; "
            f"font-family: {T.FONT_MONO}; font-weight: 700; background: {T.c('bg_elevated')}; "
            f"border: 1px solid {T.c('border_focus')}; border-radius: {T.RADIUS_SM}px; "
            f"padding: 4px 12px; letter-spacing: 1.5px;"
        )
        top_hero.addWidget(beacon)
        top_hero.addStretch()
        top_hero.addWidget(self.role_badge)
        hero_layout.addLayout(top_hero)

        # Welcome Text
        self.greeting_label = QLabel("Welcome to OBSERVER")
        self.greeting_label.setFont(QFont(T.FONT_UI, T.FONT_SIZE_2XL + 2, QFont.Weight.Bold))
        self.greeting_label.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")
        hero_layout.addWidget(self.greeting_label)

        sub_desc = QLabel(
            "Automated Web Vulnerability Audit Platform  ·  OWASP Top 10 Detection & Analysis Engine"
        )
        sub_desc.setStyleSheet(
            f"color: {T.c('text_secondary')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;"
        )
        hero_layout.addWidget(sub_desc)

        layout.addWidget(hero)

        # ── 2. Telemetry & Metrics Row ──────────────────────────────────────
        layout.addWidget(SectionLabel("Telemetry & System Overview"))
        
        metrics_grid = QGridLayout()
        metrics_grid.setSpacing(14)

        self.stat_total = DashboardMetricCard("0", "Total Audits", "🛡️", accent_color=T.c("text_primary"))
        self.stat_running = DashboardMetricCard("0", "Active Scans", "⚡", accent_color=T.c("severity_info"))
        self.stat_critical = DashboardMetricCard("0", "Critical Vulnerabilities", "🔴", accent_color=T.c("severity_critical"))
        self.stat_reports = DashboardMetricCard("0", "PDF Reports Generated", "📄", accent_color=T.c("severity_low"))

        metrics_grid.addWidget(self.stat_total, 0, 0)
        metrics_grid.addWidget(self.stat_running, 0, 1)
        metrics_grid.addWidget(self.stat_critical, 0, 2)
        metrics_grid.addWidget(self.stat_reports, 0, 3)
        layout.addLayout(metrics_grid)

        # ── 3. Quick Start Operational Lifecycle ────────────────────────────
        layout.addWidget(SectionLabel("Operational Workflow"))

        workflow_grid = QGridLayout()
        workflow_grid.setSpacing(12)

        step1 = WorkflowStepCard(
            "01",
            "Target Definition & Authorization",
            "Define targets in Operations. Every target undergoes authorization checks to ensure compliance."
        )
        step2 = WorkflowStepCard(
            "02",
            "Modular OWASP Scan Execution",
            "Select from 10 distinct OWASP detection modules and execute multi-threaded crawler & audit pipelines."
        )
        step3 = WorkflowStepCard(
            "03",
            "Real-Time Telemetry & Logs",
            "Monitor live finding streams and pop out the CLI terminal view for multi-monitor surveillance."
        )
        step4 = WorkflowStepCard(
            "04",
            "Executive Audit Documentation",
            "Generate structured PDF reports with technical proofs, severity breakdowns, and remediation plans."
        )

        workflow_grid.addWidget(step1, 0, 0)
        workflow_grid.addWidget(step2, 0, 1)
        workflow_grid.addWidget(step3, 1, 0)
        workflow_grid.addWidget(step4, 1, 1)
        layout.addLayout(workflow_grid)

        # ── 4. OWASP Coverage Matrix ────────────────────────────────────────
        layout.addWidget(SectionLabel("OWASP Top 10 (2021) — Active Engine Coverage"))

        coverage_card = QFrame()
        coverage_card.setStyleSheet(f"""
            QFrame {{
                background-color: {T.c('bg_card')};
                border: 1px solid {T.c('border')};
                border-radius: {T.RADIUS_MD}px;
            }}
        """)
        cov_layout = QVBoxLayout(coverage_card)
        cov_layout.setContentsMargins(20, 18, 20, 18)
        cov_layout.setSpacing(10)

        categories = [
            ("A01", "Broken Access Control", "IDOR, Unauthorized paths, Permissive CORS, robots.txt"),
            ("A02", "Cryptographic Failures", "HTTPS enforcement, HSTS max-age, Insecure cookie flags"),
            ("A03", "Injection", "SQL syntax error triggers, Reflected unencoded XSS"),
            ("A04", "Insecure Design", "Missing anti-CSRF tokens, Missing rate-limiting headers"),
            ("A05", "Security Misconfiguration", "Missing CSP/X-Frame-Options, Exposed .env/.git, Stack traces"),
            ("A06", "Vulnerable & Outdated Components", "Server version disclosure, Outdated JS libraries (CVEs)"),
            ("A07", "Identification & Authentication Failures", "Plaintext password transmission, URL session tokens"),
            ("A08", "Software & Data Integrity Failures", "Missing Subresource Integrity (SRI) on external assets"),
            ("A09", "Security Logging & Monitoring Failures", "Soft 404 detections, Default server error banners"),
            ("A10", "Server-Side Request Forgery (SSRF)", "Candidate URL parameters & open redirect heuristics"),
        ]

        cov_grid = QGridLayout()
        cov_grid.setHorizontalSpacing(24)
        cov_grid.setVerticalSpacing(10)

        for i, (code, name, detail) in enumerate(categories):
            row_frame = QFrame()
            row_frame.setStyleSheet("background: transparent; border: none;")
            rf_layout = QHBoxLayout(row_frame)
            rf_layout.setContentsMargins(0, 0, 0, 0)
            rf_layout.setSpacing(10)

            code_badge = QLabel(code)
            code_badge.setFixedSize(36, 22)
            code_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            code_badge.setStyleSheet(f"""
                color: {T.c('text_primary')};
                background: {T.c('bg_elevated')};
                border: 1px solid {T.c('border')};
                border-radius: {T.RADIUS_SM}px;
                font-family: {T.FONT_MONO};
                font-size: {T.FONT_SIZE_XS}px;
                font-weight: 700;
            """)

            text_box = QVBoxLayout()
            text_box.setSpacing(1)
            name_lbl = QLabel(name)
            name_lbl.setFont(QFont(T.FONT_UI, T.FONT_SIZE_SM, QFont.Weight.Bold))
            name_lbl.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")

            sub_lbl = QLabel(detail)
            sub_lbl.setStyleSheet(f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; background: transparent;")

            text_box.addWidget(name_lbl)
            text_box.addWidget(sub_lbl)

            status_lbl = QLabel("● ACTIVE")
            status_lbl.setStyleSheet(
                f"color: {T.c('severity_low')}; font-size: {T.FONT_SIZE_XS}px; "
                f"font-weight: 700; font-family: {T.FONT_MONO}; background: transparent;"
            )

            rf_layout.addWidget(code_badge)
            rf_layout.addLayout(text_box, 1)
            rf_layout.addWidget(status_lbl)

            cov_grid.addWidget(row_frame, i % 5, i // 5)

        cov_layout.addLayout(cov_grid)
        layout.addWidget(coverage_card)

        # ── 5. System Infrastructure Status Strip ───────────────────────────
        diag_frame = QFrame()
        diag_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {T.c('bg_secondary')};
                border: 1px solid {T.c('border_subtle')};
                border-radius: {T.RADIUS_SM}px;
            }}
        """)
        diag_layout = QHBoxLayout(diag_frame)
        diag_layout.setContentsMargins(16, 10, 16, 10)
        diag_layout.setSpacing(24)

        diag_db = QLabel("DATABASE: SQLite (WAL)")
        diag_smtp = QLabel("DISPATCHER: SMTP TLS")
        diag_engine = QLabel("SCANNER: Multi-threaded QThread")
        for lbl in [diag_db, diag_smtp, diag_engine]:
            lbl.setStyleSheet(
                f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; "
                f"font-family: {T.FONT_MONO}; background: transparent;"
            )
            diag_layout.addWidget(lbl)

        diag_layout.addStretch()
        diag_state = QLabel("KERNEL STATE: READY")
        diag_state.setStyleSheet(
            f"color: {T.c('accent_dim')}; font-size: {T.FONT_SIZE_XS}px; "
            f"font-weight: 700; font-family: {T.FONT_MONO}; background: transparent;"
        )
        diag_layout.addWidget(diag_state)

        layout.addWidget(diag_frame)

    def on_enter(self):
        """Refresh dashboard telemetry when navigating to Home."""
        if not session.is_authenticated:
            return

        name_first = session.user_name.split()[0] if session.user_name else "Operator"
        self.greeting_label.setText(f"Welcome back, {name_first}")
        self.role_badge.setText(f"ROLE: {session.role.upper()}")

        db = get_db()
        try:
            if session.is_admin_user():
                total = db.query(Scan).count()
                running = db.query(Scan).filter(Scan.status == ScanStatus.RUNNING).count()
                critical = db.query(Finding).filter(Finding.severity == Severity.CRITICAL).count()
                reports = db.query(Report).count()
            else:
                total = db.query(Scan).filter(Scan.created_by == session.user_id).count()
                running = db.query(Scan).filter(
                    Scan.created_by == session.user_id, Scan.status == ScanStatus.RUNNING
                ).count()
                critical = (
                    db.query(Finding)
                    .join(Scan)
                    .filter(Scan.created_by == session.user_id, Finding.severity == Severity.CRITICAL)
                    .count()
                )
                reports = db.query(Report).filter(Report.created_by == session.user_id).count()

            self.stat_total.set_value(str(total))
            self.stat_running.set_value(str(running))
            self.stat_critical.set_value(str(critical))
            self.stat_reports.set_value(str(reports))
        finally:
            db.close()
