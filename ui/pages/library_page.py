"""
OBSERVER — Library Page (Phase 3)
Full OWASP Top 10 reference with detection methods.
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QSplitter, QListWidget, QListWidgetItem, QTextEdit
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor

from ui.design import theme as T
from ui.design.widgets import SeverityBadge, Card, SectionLabel


OWASP_DATA = [
    {
        "id": "A01",
        "name": "Broken Access Control",
        "severity": "critical",
        "description": (
            "Access control enforces policy such that users cannot act outside of their intended permissions. "
            "Failures typically lead to unauthorized information disclosure, modification, or destruction of all data, "
            "or performing a business function outside the user's limits."
        ),
        "examples": [
            "Violation of the principle of least privilege",
            "Bypassing access control checks by modifying the URL or HTML page",
            "Insecure direct object references (IDOR)",
            "CORS misconfiguration allowing unauthorized API access",
            "Force browsing to authenticated pages as an unauthenticated user",
        ],
        "detection": (
            "OBSERVER tests for IDOR by modifying resource identifiers in requests, "
            "attempts forced browsing to admin/authenticated paths, and checks CORS headers "
            "for overly permissive configurations."
        ),
        "ref": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    },
    {
        "id": "A02",
        "name": "Cryptographic Failures",
        "severity": "high",
        "description": (
            "Previously known as 'Sensitive Data Exposure', this category focuses on failures related to "
            "cryptography which often lead to exposure of sensitive data such as passwords, credit card numbers, "
            "health records, personal information, and business secrets."
        ),
        "examples": [
            "Data transmitted in cleartext (HTTP instead of HTTPS)",
            "Weak cryptographic algorithms (MD5, SHA1, DES)",
            "Default crypto keys in use or missing key rotation",
            "Sensitive data stored without encryption",
            "Missing HSTS header allowing downgrade attacks",
        ],
        "detection": (
            "OBSERVER checks HTTP vs HTTPS, inspects response headers (HSTS, Content-Security-Policy), "
            "detects cookies without Secure/HttpOnly flags, and scans for sensitive data patterns "
            "in HTTP responses."
        ),
        "ref": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    },
    {
        "id": "A03",
        "name": "Injection",
        "severity": "critical",
        "description": (
            "Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is "
            "sent to an interpreter as part of a command or query. The attacker's hostile data can trick "
            "the interpreter into executing unintended commands or accessing data without proper authorization."
        ),
        "examples": [
            "SQL Injection via user-supplied input in query parameters",
            "Reflected and Stored Cross-Site Scripting (XSS)",
            "Command injection through OS calls",
            "LDAP injection in authentication",
            "XML/XPath injection",
        ],
        "detection": (
            "OBSERVER sends SQLi payloads (error-based, boolean-blind, time-based) to input fields and URL params. "
            "XSS tests inject script payloads into forms and URL parameters. "
            "Command injection tests use OS-specific payloads on relevant endpoints."
        ),
        "ref": "https://owasp.org/Top10/A03_2021-Injection/",
    },
    {
        "id": "A04",
        "name": "Insecure Design",
        "severity": "high",
        "description": (
            "Insecure design is a broad category representing different weaknesses, expressed as 'missing or "
            "ineffective control design'. A secure design can still have implementation defects leading to "
            "vulnerabilities, but an insecure design cannot be fixed by a perfect implementation."
        ),
        "examples": [
            "Business logic flaws allowing unauthorized actions",
            "Missing rate limiting on sensitive operations",
            "Insecure password recovery flows",
            "Missing account lockout mechanisms",
            "Predictable resource identifiers",
        ],
        "detection": (
            "OBSERVER tests for missing rate limiting on authentication endpoints, "
            "checks for predictable token/session patterns, and validates business logic "
            "flows by attempting to bypass multi-step processes."
        ),
        "ref": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    },
    {
        "id": "A05",
        "name": "Security Misconfiguration",
        "severity": "medium",
        "description": (
            "Security misconfiguration is the most commonly seen issue. This is commonly a result of insecure "
            "default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured "
            "HTTP headers, and verbose error messages containing sensitive information."
        ),
        "examples": [
            "Missing security headers (CSP, X-Frame-Options, etc.)",
            "Verbose error messages exposing stack traces",
            "Default credentials on admin panels",
            "Directory listing enabled",
            "Unnecessary services, ports, or features enabled",
        ],
        "detection": (
            "OBSERVER checks for 15+ security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, "
            "Referrer-Policy, etc.), tests for verbose error responses, detects directory listing, "
            "and identifies common admin panels with default paths."
        ),
        "ref": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },
    {
        "id": "A06",
        "name": "Vulnerable & Outdated Components",
        "severity": "medium",
        "description": (
            "Components, such as libraries, frameworks, and other software modules, run with the same privileges "
            "as the application. If a vulnerable component is exploited, such an attack can facilitate serious "
            "data loss or server takeover."
        ),
        "examples": [
            "Outdated jQuery, Bootstrap, or other JavaScript libraries with known CVEs",
            "CMS software without latest security patches",
            "Server software version disclosure in headers",
            "Dependencies with publicly known vulnerabilities",
        ],
        "detection": (
            "OBSERVER extracts JavaScript library versions from HTML source and script tags, "
            "checks them against a known-vulnerable versions database, "
            "and inspects Server/X-Powered-By headers for version disclosure."
        ),
        "ref": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    },
    {
        "id": "A07",
        "name": "Identification & Authentication Failures",
        "severity": "high",
        "description": (
            "Confirmation of the user's identity, authentication, and session management is critical to "
            "protect against authentication-related attacks. There may be authentication weaknesses if the "
            "application permits automated attacks such as credential stuffing or brute force."
        ),
        "examples": [
            "Permits brute force or automated credential stuffing attacks",
            "Permits weak or well-known passwords",
            "Uses weak credential recovery processes",
            "Uses plain text, encrypted, or weakly hashed passwords",
            "Missing or ineffective multi-factor authentication",
            "Session tokens not invalidated after logout",
        ],
        "detection": (
            "OBSERVER checks for account lockout mechanisms, tests cookie security flags (Secure, HttpOnly, SameSite), "
            "validates session token entropy and expiration, and checks if session tokens persist after logout."
        ),
        "ref": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    },
    {
        "id": "A08",
        "name": "Software & Data Integrity Failures",
        "severity": "high",
        "description": (
            "Software and data integrity failures relate to code and infrastructure that does not protect against "
            "integrity violations. An example is where an application relies upon plugins, libraries, or modules "
            "from untrusted sources, repositories, and content delivery networks (CDNs)."
        ),
        "examples": [
            "External scripts/stylesheets loaded without Subresource Integrity (SRI) checks",
            "Insecure deserialization of user-supplied data",
            "Auto-update functionality without integrity verification",
            "Critical data processed without integrity checks",
        ],
        "detection": (
            "OBSERVER checks for missing Subresource Integrity (SRI) attributes on external scripts and stylesheets, "
            "attempts deserialization payloads on JSON/XML endpoints, and verifies Content-Security-Policy "
            "restricts external resource loading."
        ),
        "ref": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    },
    {
        "id": "A09",
        "name": "Security Logging & Monitoring Failures",
        "severity": "medium",
        "description": (
            "This category helps detect, escalate, and respond to active breaches. Without logging and monitoring, "
            "breaches cannot be detected. Insufficient logging, detection, monitoring, and active response occurs "
            "any time an auditable event is not logged."
        ),
        "examples": [
            "Auditable events such as logins and failed logins not logged",
            "Warnings and errors generate no or inadequate log messages",
            "Logs not monitored for suspicious activity",
            "Application unable to detect, escalate, or alert for active attacks",
        ],
        "detection": (
            "OBSERVER attempts failed logins and verifies if error responses reveal debugging information. "
            "It checks if application error responses are generic (good) or verbose (bad), "
            "and tests if the app responds differently to automated vs manual requests."
        ),
        "ref": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    },
    {
        "id": "A10",
        "name": "Server-Side Request Forgery (SSRF)",
        "severity": "high",
        "description": (
            "SSRF flaws occur whenever a web application is fetching a remote resource without validating the "
            "user-supplied URL. It allows an attacker to coerce the application to send a crafted request to "
            "an unexpected destination, even when protected by a firewall, VPN, or another type of network ACL."
        ),
        "examples": [
            "URL parameters used directly in server-side HTTP requests",
            "Webhooks that can be redirected to internal services",
            "File imports from remote URLs without validation",
            "PDF generators that fetch external content",
        ],
        "detection": (
            "OBSERVER injects SSRF payloads (pointing to internal IP ranges, localhost, cloud metadata endpoints) "
            "into URL parameters, file import fields, and webhook endpoints, then analyzes responses "
            "for signs of successful internal resource access."
        ),
        "ref": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    },
]


class OWASPDetailPanel(QWidget):
    """Right panel showing full details of a selected OWASP category."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        self.scroll = QScrollArea(self)
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setStyleSheet("background: transparent; border: none;")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self.scroll)

        self.content = QWidget()
        self.content.setStyleSheet(f"background: {T.c('bg_primary')};")
        self.scroll.setWidget(self.content)

        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(24, 24, 24, 24)
        self.content_layout.setSpacing(16)

        self.placeholder = QLabel("← Select a category from the list")
        self.placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.placeholder.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_MD}px; background: transparent;"
        )
        self.content_layout.addWidget(self.placeholder)
        self.content_layout.addStretch()

    def load(self, data: dict):
        """Populate panel with OWASP category data."""
        # Replace the entire content widget in the scroll area.
        # This completely eliminates any visual overlap or lingering layouts/widgets.
        self.content = QWidget()
        self.content.setStyleSheet(f"background: {T.c('bg_primary')};")
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(24, 24, 24, 24)
        self.content_layout.setSpacing(16)
        self.scroll.setWidget(self.content)

        # Header
        header = QHBoxLayout()
        id_badge = QLabel(data["id"])
        id_badge.setStyleSheet(
            f"color: {T.c('accent')}; font-size: {T.FONT_SIZE_2XL}px; "
            f"font-weight: 700; font-family: {T.FONT_MONO}; background: transparent;"
        )
        name_lbl = QLabel(data["name"])
        name_lbl.setFont(QFont(T.FONT_UI, T.FONT_SIZE_XL, QFont.Weight.Bold))
        name_lbl.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")
        name_lbl.setWordWrap(True)
        sev = SeverityBadge(data["severity"])
        header.addWidget(id_badge)
        header.addWidget(name_lbl, 1)
        header.addWidget(sev, alignment=Qt.AlignmentFlag.AlignTop)
        self.content_layout.addLayout(header)

        # Separator
        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background: {T.c('border')}; border: none;")
        self.content_layout.addWidget(sep)

        # Description
        self.content_layout.addWidget(SectionLabel("Description"))
        desc = QLabel(data["description"])
        desc.setWordWrap(True)
        desc.setStyleSheet(
            f"color: {T.c('text_secondary')}; font-size: {T.FONT_SIZE_SM}px; "
            f"line-height: 1.6; background: transparent;"
        )
        self.content_layout.addWidget(desc)

        # Examples
        self.content_layout.addWidget(SectionLabel("Common Examples"))
        examples_frame = QFrame()
        examples_frame.setProperty("class", "card")
        ef_layout = QVBoxLayout(examples_frame)
        ef_layout.setContentsMargins(16, 12, 16, 12)
        ef_layout.setSpacing(8)
        for ex in data["examples"]:
            row = QHBoxLayout()
            row.setSpacing(10)
            dot = QLabel("▸")
            dot.setFixedWidth(14)
            dot.setStyleSheet(f"color: {T.c('accent_dim')}; background: transparent;")
            ex_lbl = QLabel(ex)
            ex_lbl.setWordWrap(True)
            ex_lbl.setStyleSheet(f"color: {T.c('text_secondary')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;")
            row.addWidget(dot, alignment=Qt.AlignmentFlag.AlignTop)
            row.addWidget(ex_lbl, 1)
            ef_layout.addLayout(row)
        self.content_layout.addWidget(examples_frame)

        # Detection method
        self.content_layout.addWidget(SectionLabel("How OBSERVER Detects This"))
        det_frame = QFrame()
        det_frame.setStyleSheet(
            f"background: {T.c('severity_info')}0a; border: 1px solid {T.c('severity_info')}33; "
            f"border-radius: {T.RADIUS_MD}px;"
        )
        df_layout = QHBoxLayout(det_frame)
        df_layout.setContentsMargins(14, 12, 14, 12)
        df_layout.setSpacing(12)
        icon = QLabel("◉")
        icon.setStyleSheet(f"color: {T.c('severity_info')}; font-size: 18px; background: transparent;")
        det_lbl = QLabel(data["detection"])
        det_lbl.setWordWrap(True)
        det_lbl.setStyleSheet(
            f"color: {T.c('text_secondary')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;"
        )
        df_layout.addWidget(icon, alignment=Qt.AlignmentFlag.AlignTop)
        df_layout.addWidget(det_lbl, 1)
        self.content_layout.addWidget(det_frame)

        # Reference link
        ref_lbl = QLabel(f'<a href="{data["ref"]}" style="color: {T.c("accent")};">{data["ref"]}</a>')
        ref_lbl.setOpenExternalLinks(True)
        ref_lbl.setStyleSheet(
            f"color: {T.c('accent')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;"
        )
        self.content_layout.addWidget(SectionLabel("OWASP Reference"))
        self.content_layout.addWidget(ref_lbl)
        self.content_layout.addStretch()


class LibraryPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Topbar
        topbar = QFrame()
        topbar.setFixedHeight(56)
        topbar.setStyleSheet(
            f"background: {T.c('bg_secondary')}; border-bottom: 1px solid {T.c('border')};"
        )
        tb = QHBoxLayout(topbar)
        tb.setContentsMargins(24, 0, 24, 0)
        title_lbl = QLabel("OWASP Top 10 Library")
        title_lbl.setFont(QFont(T.FONT_UI, T.FONT_SIZE_LG, QFont.Weight.Bold))
        title_lbl.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")
        year_lbl = QLabel("Edition 2021")
        year_lbl.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;"
        )
        tb.addWidget(title_lbl)
        tb.addWidget(year_lbl)
        tb.addStretch()
        layout.addWidget(topbar)

        # Splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet(f"QSplitter::handle {{ background: {T.c('border')}; width: 1px; }}")

        # ── Left: category list ──────────────────────────────────────────────
        left = QWidget()
        left.setMaximumWidth(300)
        left.setMinimumWidth(220)
        left.setStyleSheet(f"background: {T.c('bg_secondary')};")
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 16, 0, 0)
        ll.setSpacing(0)

        cat_label = QLabel("  CATEGORIES")
        cat_label.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; "
            f"letter-spacing: 2px; background: transparent; padding: 0 16px 8px 16px;"
        )
        ll.addWidget(cat_label)

        self.cat_list = QListWidget()
        self.cat_list.setStyleSheet(
            f"QListWidget {{ background: transparent; border: none; outline: none; }}"
            f"QListWidget::item {{ padding: 12px 20px; border-bottom: 1px solid {T.c('border_subtle')}; }}"
            f"QListWidget::item:selected {{ background: {T.c('bg_elevated')}; border-left: 2px solid {T.c('accent')}; }}"
            f"QListWidget::item:hover {{ background: {T.c('bg_hover')}; }}"
        )
        for item_data in OWASP_DATA:
            item = QListWidgetItem(f"  {item_data['id']}  {item_data['name']}")
            item.setForeground(QColor(T.c("text_secondary")))
            self.cat_list.addItem(item)

        self.cat_list.currentRowChanged.connect(self._on_category_selected)
        ll.addWidget(self.cat_list, 1)
        splitter.addWidget(left)

        # ── Right: detail panel ──────────────────────────────────────────────
        self.detail_panel = OWASPDetailPanel()
        splitter.addWidget(self.detail_panel)
        splitter.setSizes([260, 900])

        layout.addWidget(splitter, 1)

    def _on_category_selected(self, row: int):
        if 0 <= row < len(OWASP_DATA):
            self.detail_panel.load(OWASP_DATA[row])

    def on_enter(self):
        if self.cat_list.currentRow() < 0:
            self.cat_list.setCurrentRow(0)
