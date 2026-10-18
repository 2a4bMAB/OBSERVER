"""
OBSERVER — Admin Page (Phase 3)
User management (roles, activation/deactivation, account creation, edit, delete)
and Target management (approval / rejection / edit / delete of scan targets).
"""
import logging
import os
import subprocess
from datetime import datetime, timezone

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QTabWidget, QDialog, QComboBox, QMessageBox,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor

from core import auth
from core.database import (
    get_db, User, UserRole, Target, TargetStatus, Scan, Finding, Report, ScanLog, OtpCode
)
from core.rbac import session
from ui.design import theme as T
from ui.design.widgets import (
    PrimaryButton, SecondaryButton, DangerButton, Card,
    SectionLabel, AlertBanner, LabeledInput, StatusDot
)

logger = logging.getLogger("observer.admin")


# ─── Create User Dialog ────────────────────────────────────────────────────────

class CreateUserDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create New User Account")
        self.setMinimumWidth(460)
        self.setStyleSheet(f"background: {T.c('bg_primary')};")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        title = QLabel("Create User Account")
        title.setFont(QFont(T.FONT_UI, T.FONT_SIZE_LG, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")
        layout.addWidget(title)

        self.alert = AlertBanner("error")
        layout.addWidget(self.alert)

        self.name_input = LabeledInput("Full Name", "Alice Smith")
        self.email_input = LabeledInput("Email Address", "alice@company.com")
        self.password_input = LabeledInput("Initial Password", "••••••••", password=True)
        self.confirm_input = LabeledInput("Confirm Password", "••••••••", password=True)

        layout.addWidget(self.name_input)
        layout.addWidget(self.email_input)
        layout.addWidget(self.password_input)
        layout.addWidget(self.confirm_input)

        # Role Selector — only PENTESTER and ADMIN
        role_container = QWidget()
        role_container.setStyleSheet("background: transparent;")
        rc_layout = QVBoxLayout(role_container)
        rc_layout.setContentsMargins(0, 0, 0, 0)
        rc_layout.setSpacing(6)
        role_label = QLabel("Role Assignment")
        role_label.setStyleSheet(
            f"color: {T.c('text_secondary')}; font-size: {T.FONT_SIZE_XS}px; "
            f"font-weight: 600; background: transparent;"
        )
        self.role_combo = QComboBox()
        self.role_combo.addItem("Pentester (Standard Operator)", UserRole.PENTESTER.value)
        self.role_combo.addItem("Administrator (Full Access)", UserRole.ADMIN.value)
        self.role_combo.setStyleSheet(
            f"QComboBox {{ background: {T.c('bg_elevated')}; color: {T.c('text_primary')}; "
            f"border: 1px solid {T.c('border')}; border-radius: {T.RADIUS_SM}px; "
            f"padding: 8px 12px; font-size: {T.FONT_SIZE_SM}px; }}"
        )
        rc_layout.addWidget(role_label)
        rc_layout.addWidget(self.role_combo)
        layout.addWidget(role_container)

        btn_layout = QHBoxLayout()
        cancel_btn = SecondaryButton("Cancel")
        cancel_btn.setAutoDefault(False)
        cancel_btn.clicked.connect(self.reject)
        self.submit_btn = PrimaryButton("Create Account")
        self.submit_btn.setDefault(True)
        self.submit_btn.setAutoDefault(True)
        self.submit_btn.clicked.connect(self._create_user)

        self.name_input.input.returnPressed.connect(self._create_user)
        self.email_input.input.returnPressed.connect(self._create_user)
        self.password_input.input.returnPressed.connect(self._create_user)
        self.confirm_input.input.returnPressed.connect(self._create_user)

        btn_layout.addWidget(cancel_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.submit_btn)
        layout.addLayout(btn_layout)

    def _create_user(self):
        self.alert.hide_message()
        name = self.name_input.text().strip()
        email = self.email_input.text().strip()
        pwd = self.password_input.text()
        cpwd = self.confirm_input.text()
        role_val = self.role_combo.currentData()

        if not name or not email:
            self.alert.show_message("Name and email are required.")
            return
        if "@" not in email or "." not in email:
            self.alert.show_message("Valid email address is required.")
            return
        valid, msg = auth.validate_password_strength(pwd)
        if not valid:
            self.alert.show_message(msg)
            return
        if pwd != cpwd:
            self.alert.show_message("Passwords do not match.")
            return

        role = UserRole(role_val)
        user, err = auth.register_user(email, pwd, name, role)
        if not user:
            self.alert.show_message(f"Error: {err}")
            return

        db = get_db()
        try:
            u = db.query(User).filter(User.id == user.id).first()
            if u:
                u.is_verified = True
                db.commit()
                logger.info("Admin created and auto-verified user #%s (%s)", u.id, u.email)
        finally:
            db.close()
        self.accept()


# ─── Edit User Dialog ──────────────────────────────────────────────────────────

class EditUserDialog(QDialog):
    def __init__(self, user_id: int, parent=None):
        super().__init__(parent)
        self.user_id = user_id
        self.setWindowTitle("Edit User Account")
        self.setMinimumWidth(460)
        self.setStyleSheet(f"background: {T.c('bg_primary')};")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        title = QLabel("Edit User Account")
        title.setFont(QFont(T.FONT_UI, T.FONT_SIZE_LG, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")
        layout.addWidget(title)

        self.alert = AlertBanner("error")
        layout.addWidget(self.alert)

        db = get_db()
        try:
            u = db.query(User).filter(User.id == user_id).first()
            current_name   = u.full_name if u else ""
            current_email  = u.email if u else ""
            current_role   = u.role if u else UserRole.PENTESTER
            current_active = u.is_active if u else True
            logger.info("EditUserDialog loaded for user_id=%s: name=%r, email=%r, role=%s, active=%s",
                        user_id, current_name, current_email, current_role.value, current_active)
        finally:
            db.close()

        self.name_input = LabeledInput("Full Name", "")
        self.name_input.input.setText(current_name)
        self.email_input = LabeledInput("Email Address", "")
        self.email_input.input.setText(current_email)
        layout.addWidget(self.name_input)
        layout.addWidget(self.email_input)

        rc = QWidget(); rc.setStyleSheet("background: transparent;")
        rcl = QVBoxLayout(rc); rcl.setContentsMargins(0,0,0,0); rcl.setSpacing(6)
        rl = QLabel("Role")
        rl.setStyleSheet(f"color: {T.c('text_secondary')}; font-size: {T.FONT_SIZE_XS}px; font-weight: 600; background: transparent;")
        self.role_combo = QComboBox()
        self.role_combo.addItem("Pentester", UserRole.PENTESTER.value)
        self.role_combo.addItem("Administrator", UserRole.ADMIN.value)
        self.role_combo.setStyleSheet(
            f"QComboBox {{ background: {T.c('bg_elevated')}; color: {T.c('text_primary')}; "
            f"border: 1px solid {T.c('border')}; border-radius: {T.RADIUS_SM}px; "
            f"padding: 8px 12px; font-size: {T.FONT_SIZE_SM}px; }}"
        )
        idx = self.role_combo.findData(current_role.value)
        if idx >= 0:
            self.role_combo.setCurrentIndex(idx)
        rcl.addWidget(rl); rcl.addWidget(self.role_combo)
        layout.addWidget(rc)

        sc = QWidget(); sc.setStyleSheet("background: transparent;")
        scl = QVBoxLayout(sc); scl.setContentsMargins(0,0,0,0); scl.setSpacing(6)
        sl = QLabel("Account Status")
        sl.setStyleSheet(f"color: {T.c('text_secondary')}; font-size: {T.FONT_SIZE_XS}px; font-weight: 600; background: transparent;")
        self.status_combo = QComboBox()
        self.status_combo.addItem("Active", True)
        self.status_combo.addItem("Disabled", False)
        self.status_combo.setStyleSheet(
            f"QComboBox {{ background: {T.c('bg_elevated')}; color: {T.c('text_primary')}; "
            f"border: 1px solid {T.c('border')}; border-radius: {T.RADIUS_SM}px; "
            f"padding: 8px 12px; font-size: {T.FONT_SIZE_SM}px; }}"
        )
        self.status_combo.setCurrentIndex(0 if current_active else 1)
        scl.addWidget(sl); scl.addWidget(self.status_combo)
        layout.addWidget(sc)

        btn_layout = QHBoxLayout()
        cancel_btn = SecondaryButton("Cancel")
        cancel_btn.setAutoDefault(False)
        cancel_btn.clicked.connect(self.reject)

        self.save_btn = PrimaryButton("Save Changes")
        self.save_btn.setDefault(True)
        self.save_btn.setAutoDefault(True)
        self.save_btn.clicked.connect(self._save)

        # Enter key triggers Save
        self.name_input.input.returnPressed.connect(self._save)
        self.email_input.input.returnPressed.connect(self._save)

        btn_layout.addWidget(cancel_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.save_btn)
        layout.addLayout(btn_layout)

    def _save(self):
        self.alert.hide_message()
        name      = self.name_input.text().strip()
        email     = self.email_input.text().strip()
        role_val  = self.role_combo.currentData()
        is_active = self.status_combo.currentData()

        logger.info("EditUserDialog._save() triggered for user_id=%s: new_name=%r, new_email=%r, new_role=%s, active=%s",
                    self.user_id, name, email, role_val, is_active)

        if not name or not email:
            self.alert.show_message("Name and email are required.")
            return
        if "@" not in email or "." not in email:
            self.alert.show_message("Valid email address is required.")
            return

        db = get_db()
        try:
            existing = db.query(User).filter(
                User.email == email, User.id != self.user_id
            ).first()
            if existing:
                self.alert.show_message("Email already in use by another account.")
                return
            u = db.query(User).filter(User.id == self.user_id).first()
            if u:
                u.full_name = name
                u.email     = email
                u.role      = UserRole(role_val)
                u.is_active = is_active
                db.commit()
                logger.info("SUCCESS: User #%s updated in DB: name=%s role=%s active=%s",
                            self.user_id, name, role_val, is_active)
        except Exception as e:
            import traceback
            logger.error("Error saving user #%s: %s\n%s", self.user_id, e, traceback.format_exc())
            self.alert.show_message(f"Error: {e}")
            return
        finally:
            db.close()
        self.accept()


# ─── Edit Target Dialog ────────────────────────────────────────────────────────

class EditTargetDialog(QDialog):
    """Edit a target label and notes only. URL is read-only to preserve scan history."""
    def __init__(self, target_id: int, parent=None):
        super().__init__(parent)
        self.target_id = target_id
        self.setWindowTitle("Edit Target")
        self.setMinimumWidth(500)
        self.setStyleSheet(f"background: {T.c('bg_primary')};")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        title = QLabel("Edit Target")
        title.setFont(QFont(T.FONT_UI, T.FONT_SIZE_LG, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")
        layout.addWidget(title)

        self.alert = AlertBanner("error")
        layout.addWidget(self.alert)

        db = get_db()
        try:
            t = db.query(Target).filter(Target.id == target_id).first()
            current_url   = t.url if t else ""
            current_label = (t.label or "") if t else ""
            current_notes = (t.notes or "") if t else ""
            logger.info("EditTargetDialog loaded for target_id=%s: url=%r, label=%r",
                        target_id, current_url, current_label)
        finally:
            db.close()

        url_box = QWidget(); url_box.setStyleSheet("background: transparent;")
        ubl = QVBoxLayout(url_box); ubl.setContentsMargins(0,0,0,0); ubl.setSpacing(4)
        ul = QLabel("URL (read-only — preserves scan history)")
        ul.setStyleSheet(f"color: {T.c('text_secondary')}; font-size: {T.FONT_SIZE_XS}px; font-weight: 600; background: transparent;")
        uv = QLabel(current_url)
        uv.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_SM}px; "
            f"background: {T.c('bg_elevated')}; border: 1px solid {T.c('border')}; "
            f"border-radius: {T.RADIUS_SM}px; padding: 8px 12px;"
        )
        uv.setWordWrap(True)
        ubl.addWidget(ul); ubl.addWidget(uv)
        layout.addWidget(url_box)

        self.label_input = LabeledInput("Label (optional display name)", "")
        self.label_input.input.setText(current_label)
        self.notes_input = LabeledInput("Notes (optional)", "")
        self.notes_input.input.setText(current_notes)
        layout.addWidget(self.label_input)
        layout.addWidget(self.notes_input)

        btn_layout = QHBoxLayout()
        cancel_btn = SecondaryButton("Cancel")
        cancel_btn.setAutoDefault(False)
        cancel_btn.clicked.connect(self.reject)

        self.save_btn = PrimaryButton("Save Changes")
        self.save_btn.setDefault(True)
        self.save_btn.setAutoDefault(True)
        self.save_btn.clicked.connect(self._save)

        # Enter key triggers Save
        self.label_input.input.returnPressed.connect(self._save)
        self.notes_input.input.returnPressed.connect(self._save)

        btn_layout.addWidget(cancel_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.save_btn)
        layout.addLayout(btn_layout)

    def _save(self):
        label = self.label_input.text().strip() or None
        notes = self.notes_input.text().strip() or None
        logger.info("EditTargetDialog._save() for target_id=%s: new_label=%r", self.target_id, label)
        db = get_db()
        try:
            t = db.query(Target).filter(Target.id == self.target_id).first()
            if t:
                t.label = label
                t.notes = notes
                db.commit()
                logger.info("SUCCESS: Target #%s updated: label=%r notes=%r", self.target_id, label, notes)
        except Exception as e:
            import traceback
            logger.error("Error saving target #%s: %s\n%s", self.target_id, e, traceback.format_exc())
            self.alert.show_message(f"Error: {e}")
            return
        finally:
            db.close()
        self.accept()


# ─── Target Reports Dialog ─────────────────────────────────────────────────────

class TargetReportsDialog(QDialog):
    """Show all reports generated for a specific target."""
    def __init__(self, target_id: int, target_url: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Reports — {target_url[:60]}")
        self.setMinimumWidth(620)
        self.setMinimumHeight(280)
        self.setStyleSheet(f"background: {T.c('bg_primary')};")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        header = QLabel(f"Reports for: {target_url}")
        header.setFont(QFont(T.FONT_UI, T.FONT_SIZE_SM, QFont.Weight.Bold))
        header.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")
        header.setWordWrap(True)
        layout.addWidget(header)

        db = get_db()
        try:
            rows = (
                db.query(Report)
                .join(Scan, Report.scan_id == Scan.id)
                .filter(Scan.target_id == target_id)
                .order_by(Report.created_at.desc())
                .all()
            )
            report_data = [
                (r.title,
                 r.created_at.strftime("%Y-%m-%d %H:%M") if r.created_at else "—",
                 r.file_path)
                for r in rows
            ]
        finally:
            db.close()

        if not report_data:
            empty = QLabel("No reports generated for this target yet.")
            empty.setStyleSheet(f"color: {T.c('text_muted')}; background: transparent;")
            layout.addWidget(empty)
        else:
            tbl = QTableWidget()
            tbl.setColumnCount(3)
            tbl.setHorizontalHeaderLabels(["Report Title", "Generated At", "File"])
            tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            tbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
            tbl.horizontalHeader().resizeSection(1, 140)
            tbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
            tbl.horizontalHeader().resizeSection(2, 90)
            tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            tbl.verticalHeader().setVisible(False)
            tbl.setRowCount(len(report_data))
            tbl.setAlternatingRowColors(True)
            for i, (rtitle, rdate, rpath) in enumerate(report_data):
                tbl.setItem(i, 0, QTableWidgetItem(rtitle))
                tbl.setItem(i, 1, QTableWidgetItem(rdate))
                exists = bool(rpath and os.path.exists(rpath))
                fi = QTableWidgetItem("OK" if exists else "Missing")
                fi.setForeground(QColor(
                    T.c("severity_low") if exists else T.c("severity_critical")
                ))
                tbl.setItem(i, 2, fi)
            layout.addWidget(tbl)

        btn_row = QHBoxLayout()
        from core.config import config
        open_btn = SecondaryButton("Open Reports Folder")
        open_btn.setAutoDefault(False)
        open_btn.clicked.connect(lambda: subprocess.Popen(["explorer", str(config.REPORTS_DIR)]))
        close_btn = PrimaryButton("Close")
        close_btn.setDefault(True)
        close_btn.clicked.connect(self.accept)
        btn_row.addWidget(open_btn)
        btn_row.addStretch()
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)


# ─── Admin Page ───────────────────────────────────────────────────────────────

class AdminPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        topbar = QFrame()
        topbar.setFixedHeight(56)
        topbar.setStyleSheet(
            f"background: {T.c('bg_secondary')}; border-bottom: 1px solid {T.c('border')};"
        )
        tb = QHBoxLayout(topbar)
        tb.setContentsMargins(24, 0, 24, 0)
        title_lbl = QLabel("Administration")
        title_lbl.setFont(QFont(T.FONT_UI, T.FONT_SIZE_LG, QFont.Weight.Bold))
        title_lbl.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")
        self.create_user_btn = PrimaryButton("+ New User")
        self.create_user_btn.clicked.connect(self._open_create_user_dialog)
        tb.addWidget(title_lbl)
        tb.addStretch()
        tb.addWidget(self.create_user_btn)
        layout.addWidget(topbar)

        content = QWidget()
        cl = QVBoxLayout(content)
        cl.setContentsMargins(24, 20, 24, 24)
        cl.setSpacing(14)

        self.alert = AlertBanner("info")
        cl.addWidget(self.alert)

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: 1px solid {T.c('border')};
                background: {T.c('bg_card')};
                border-radius: {T.RADIUS_MD}px;
            }}
            QTabBar::tab {{
                background: {T.c('bg_secondary')};
                color: {T.c('text_secondary')};
                padding: 10px 24px;
                font-weight: 600;
                font-size: {T.FONT_SIZE_SM}px;
                border: 1px solid {T.c('border')};
                border-bottom: none;
                margin-right: 4px;
                border-top-left-radius: {T.RADIUS_SM}px;
                border-top-right-radius: {T.RADIUS_SM}px;
            }}
            QTabBar::tab:selected {{
                background: {T.c('bg_card')};
                color: {T.c('text_primary')};
                border-color: {T.c('border')};
            }}
        """)

        # Tab 1: User Accounts
        users_tab = QWidget()
        ut_layout = QVBoxLayout(users_tab)
        ut_layout.setContentsMargins(16, 16, 16, 16)
        ut_layout.setSpacing(12)

        self.users_table = QTableWidget()
        self.users_table.setColumnCount(5)
        self.users_table.setHorizontalHeaderLabels(
            ["Name / Email", "Role", "Status", "Last Login", "Actions"]
        )
        hh = self.users_table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        hh.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        hh.resizeSection(1, 110)
        hh.resizeSection(2, 90)
        hh.resizeSection(3, 150)
        hh.resizeSection(4, 220)
        self.users_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.users_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.users_table.verticalHeader().setVisible(False)
        self.users_table.setAlternatingRowColors(True)
        ut_layout.addWidget(self.users_table)
        self.tabs.addTab(users_tab, "User Accounts")

        # Tab 2: Target Management
        targets_tab = QWidget()
        tt_layout = QVBoxLayout(targets_tab)
        tt_layout.setContentsMargins(16, 16, 16, 16)
        tt_layout.setSpacing(12)

        self.targets_table = QTableWidget()
        self.targets_table.setColumnCount(6)
        self.targets_table.setHorizontalHeaderLabels(
            ["Target URL / Label", "Submitted By", "Date", "Status", "Reports", "Actions"]
        )
        th = self.targets_table.horizontalHeader()
        th.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        th.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        th.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        th.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        th.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        th.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        th.resizeSection(1, 130)
        th.resizeSection(2, 130)
        th.resizeSection(3, 100)
        th.resizeSection(4, 90)
        th.resizeSection(5, 220)
        self.targets_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.targets_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.targets_table.verticalHeader().setVisible(False)
        self.targets_table.setAlternatingRowColors(True)
        tt_layout.addWidget(self.targets_table)
        self.tabs.addTab(targets_tab, "Target Management")

        cl.addWidget(self.tabs)
        layout.addWidget(content, 1)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def on_enter(self):
        logger.info("AdminPage.on_enter() — is_admin=%s", session.is_admin_user())
        if not session.is_admin_user():
            self.alert.show_message("Access denied: Administrative privileges required.")
            return
        self._load_users()
        self._load_targets()

    # ── User Management ───────────────────────────────────────────────────────

    def _load_users(self):
        logger.info("_load_users() called")
        db = get_db()
        try:
            users = db.query(User).order_by(User.created_at.desc()).all()
            logger.info("_load_users(): %d user(s) found in DB", len(users))
            self.users_table.clearContents()
            self.users_table.setRowCount(len(users))

            for i, u in enumerate(users):
                logger.info("  row %d: id=%s role=%s email=%s", i, u.id, u.role.value, u.email)
                name_item = QTableWidgetItem(f"{u.full_name}\n{u.email}")
                role_item = QTableWidgetItem(u.role.value.upper())
                role_color = T.c("accent") if u.role == UserRole.ADMIN else T.c("text_secondary")
                role_item.setForeground(QColor(role_color))

                status_str   = "ACTIVE" if u.is_active else "DISABLED"
                status_item  = QTableWidgetItem(status_str)
                status_color = T.c("severity_low") if u.is_active else T.c("severity_critical")
                status_item.setForeground(QColor(status_color))

                ll_str  = u.last_login.strftime("%Y-%m-%d %H:%M") if u.last_login else "Never"
                ll_item = QTableWidgetItem(ll_str)

                aw = QWidget()
                al = QHBoxLayout(aw)
                al.setContentsMargins(4, 2, 4, 2)
                al.setSpacing(6)

                if u.id != session.user_id:
                    edit_btn = SecondaryButton("Edit")
                    edit_btn.setFixedHeight(28)
                    edit_btn.clicked.connect(
                        lambda checked=False, uid=u.id: self._open_edit_user_dialog(uid)
                    )
                    del_btn = DangerButton("Delete")
                    del_btn.setFixedHeight(28)
                    del_btn.clicked.connect(
                        lambda checked=False, uid=u.id, uname=u.full_name: self._confirm_delete_user(uid, uname)
                    )
                    al.addWidget(edit_btn)
                    al.addWidget(del_btn)
                else:
                    self_lbl = QLabel("(Current User)")
                    self_lbl.setStyleSheet(
                        f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; background: transparent;"
                    )
                    al.addWidget(self_lbl)

                self.users_table.setItem(i, 0, name_item)
                self.users_table.setItem(i, 1, role_item)
                self.users_table.setItem(i, 2, status_item)
                self.users_table.setItem(i, 3, ll_item)
                self.users_table.setCellWidget(i, 4, aw)
                self.users_table.setRowHeight(i, 52)

            self.users_table.viewport().update()
            logger.info("_load_users(): table shows %d rows", self.users_table.rowCount())
        except Exception as e:
            import traceback
            logger.error("EXCEPTION in _load_users(): %s\n%s", e, traceback.format_exc())
        finally:
            db.close()

    def _open_create_user_dialog(self):
        if not session.is_admin_user():
            return
        dlg = CreateUserDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._load_users()
            self.alert.show_message("New user account created successfully.", auto_hide_ms=4000)

    def _open_edit_user_dialog(self, user_id: int):
        logger.info("AdminPage._open_edit_user_dialog() called for user_id=%s", user_id)
        if not session.is_admin_user():
            logger.warning("Access denied: session is not admin user")
            return
        dlg = EditUserDialog(user_id, self)
        result = dlg.exec()
        logger.info("EditUserDialog closed with result=%s (Accepted=%s)",
                    result, result == QDialog.DialogCode.Accepted)
        if result == QDialog.DialogCode.Accepted:
            self._load_users()
            self.alert.show_message("User account updated.", auto_hide_ms=3000)

    def _confirm_delete_user(self, user_id: int, user_name: str):
        logger.info("AdminPage._confirm_delete_user() called for user_id=%s (%s)", user_id, user_name)
        if not session.is_admin_user():
            logger.warning("Access denied: session is not admin user")
            return

        box = QMessageBox(self)
        box.setWindowTitle("Confirm User Deletion")
        box.setText(
            f"Are you sure you want to permanently delete the account for:\n\n"
            f"  {user_name}\n\n"
            f"All scans, targets and reports linked to this user will also be removed.\n"
            f"PDF files on disk will be PRESERVED.\n\n"
            f"This action CANNOT be undone."
        )
        box.setIcon(QMessageBox.Icon.Warning)
        delete_btn = box.addButton("Delete", QMessageBox.ButtonRole.YesRole)
        cancel_btn = box.addButton("Cancel", QMessageBox.ButtonRole.NoRole)
        box.setDefaultButton(delete_btn)

        box.exec()
        clicked = box.clickedButton()
        logger.info("User deletion confirm dialog result: clicked %s", "Delete" if clicked == delete_btn else "Cancel")
        if clicked == delete_btn:
            self._delete_user(user_id)

    def _delete_user(self, user_id: int):
        logger.info("AdminPage._delete_user() executing for user_id=%s", user_id)
        if not session.is_admin_user():
            return
        db = get_db()
        try:
            u = db.query(User).filter(User.id == user_id).first()
            if not u:
                logger.warning("User #%s not found in DB", user_id)
                return

            # Clean up OTP codes
            db.query(OtpCode).filter(OtpCode.user_id == user_id).delete(synchronize_session=False)

            # Find all targets created by this user
            user_targets = db.query(Target).filter(Target.created_by == user_id).all()
            user_target_ids = [t.id for t in user_targets]

            # Find all scans created by this user or belonging to user targets
            user_scans = db.query(Scan).filter(
                (Scan.created_by == user_id) | (Scan.target_id.in_(user_target_ids))
            ).all()
            user_scan_ids = [s.id for s in user_scans]

            # Cascade delete scans dependencies
            if user_scan_ids:
                db.query(Report).filter(Report.scan_id.in_(user_scan_ids)).delete(synchronize_session=False)
                db.query(Finding).filter(Finding.scan_id.in_(user_scan_ids)).delete(synchronize_session=False)
                db.query(ScanLog).filter(ScanLog.scan_id.in_(user_scan_ids)).delete(synchronize_session=False)
                db.query(Scan).filter(Scan.id.in_(user_scan_ids)).delete(synchronize_session=False)

            # Delete remaining reports created by user
            db.query(Report).filter(Report.created_by == user_id).delete(synchronize_session=False)

            # Delete targets created by user
            if user_target_ids:
                db.query(Target).filter(Target.id.in_(user_target_ids)).delete(synchronize_session=False)

            # Delete the user record
            db.delete(u)
            db.commit()
            logger.info("SUCCESS: User #%s permanently deleted by admin #%s", user_id, session.user_id)
        except Exception as e:
            import traceback
            logger.error("Error deleting user #%s: %s\n%s", user_id, e, traceback.format_exc())
            db.rollback()
            self.alert.show_message(f"Error deleting user: {e}")
            return
        finally:
            db.close()
        self._load_users()
        self.alert.show_message("User account deleted.", auto_hide_ms=4000)

    # ── Target Management ─────────────────────────────────────────────────────

    def _load_targets(self):
        logger.info("_load_targets() called")
        db = get_db()
        try:
            targets = db.query(Target).order_by(Target.created_at.desc()).all()
            logger.info("_load_targets(): %d target(s) found", len(targets))
            self.targets_table.clearContents()
            self.targets_table.setRowCount(len(targets))

            for i, t in enumerate(targets):
                label_text   = f"{t.label}\n{t.url}" if t.label else t.url
                target_item  = QTableWidgetItem(label_text)
                creator      = db.query(User).filter(User.id == t.created_by).first()
                creator_str  = creator.full_name if creator else "System"
                creator_item = QTableWidgetItem(creator_str)
                date_str     = t.created_at.strftime("%Y-%m-%d %H:%M") if t.created_at else "—"
                date_item    = QTableWidgetItem(date_str)
                status_item  = QTableWidgetItem(t.status.value.upper())
                scolor = {
                    "approved": T.c("severity_low"),
                    "pending":  T.c("severity_medium"),
                    "rejected": T.c("severity_critical"),
                }.get(t.status.value, T.c("text_muted"))
                status_item.setForeground(QColor(scolor))

                report_count = (
                    db.query(Report)
                    .join(Scan, Report.scan_id == Scan.id)
                    .filter(Scan.target_id == t.id)
                    .count()
                )
                rw = QWidget()
                rl = QHBoxLayout(rw)
                rl.setContentsMargins(4, 2, 4, 2)
                rl.setSpacing(4)
                cnt = QLabel(str(report_count))
                cnt.setStyleSheet(
                    f"color: {T.c('text_primary') if report_count > 0 else T.c('text_muted')}; "
                    f"font-weight: {'700' if report_count > 0 else '400'}; background: transparent;"
                )
                rl.addWidget(cnt)
                if report_count > 0:
                    vb = SecondaryButton("View")
                    vb.setFixedHeight(24)
                    vb.clicked.connect(
                        lambda checked=False, tid=t.id, turl=t.url: self._show_target_reports(tid, turl)
                    )
                    rl.addWidget(vb)
                rl.addStretch()

                aw = QWidget()
                al = QHBoxLayout(aw)
                al.setContentsMargins(4, 2, 4, 2)
                al.setSpacing(4)

                if t.status == TargetStatus.PENDING:
                    ab = PrimaryButton("Approve")
                    ab.setFixedHeight(26)
                    ab.clicked.connect(
                        lambda checked=False, tid=t.id: self._set_target_status(tid, TargetStatus.APPROVED)
                    )
                    rb = DangerButton("Reject")
                    rb.setFixedHeight(26)
                    rb.clicked.connect(
                        lambda checked=False, tid=t.id: self._set_target_status(tid, TargetStatus.REJECTED)
                    )
                    al.addWidget(ab)
                    al.addWidget(rb)

                eb = SecondaryButton("Edit")
                eb.setFixedHeight(26)
                eb.setToolTip("Edit label / notes")
                eb.clicked.connect(
                    lambda checked=False, tid=t.id: self._open_edit_target_dialog(tid)
                )
                db2 = DangerButton("Delete")
                db2.setFixedHeight(26)
                db2.setToolTip("Delete target")
                db2.clicked.connect(
                    lambda checked=False, tid=t.id, turl=t.url: self._confirm_delete_target(tid, turl)
                )
                al.addWidget(eb)
                al.addWidget(db2)

                self.targets_table.setItem(i, 0, target_item)
                self.targets_table.setItem(i, 1, creator_item)
                self.targets_table.setItem(i, 2, date_item)
                self.targets_table.setItem(i, 3, status_item)
                self.targets_table.setCellWidget(i, 4, rw)
                self.targets_table.setCellWidget(i, 5, aw)
                self.targets_table.setRowHeight(i, 52)

            self.targets_table.viewport().update()
        except Exception as e:
            import traceback
            logger.error("EXCEPTION in _load_targets(): %s\n%s", e, traceback.format_exc())
        finally:
            db.close()

    def _show_target_reports(self, target_id: int, target_url: str):
        TargetReportsDialog(target_id, target_url, self).exec()

    def _open_edit_target_dialog(self, target_id: int):
        logger.info("AdminPage._open_edit_target_dialog() called for target_id=%s", target_id)
        if not session.is_admin_user():
            return
        dlg = EditTargetDialog(target_id, self)
        result = dlg.exec()
        logger.info("EditTargetDialog closed with result=%s (Accepted=%s)",
                    result, result == QDialog.DialogCode.Accepted)
        if result == QDialog.DialogCode.Accepted:
            self._load_targets()
            self.alert.show_message("Target updated.", auto_hide_ms=3000)

    def _confirm_delete_target(self, target_id: int, target_url: str):
        logger.info("AdminPage._confirm_delete_target() called for target_id=%s (%s)", target_id, target_url)
        if not session.is_admin_user():
            return

        box = QMessageBox(self)
        box.setWindowTitle("Confirm Target Deletion")
        box.setText(
            f"Are you sure you want to permanently delete:\n\n"
            f"  {target_url}\n\n"
            f"All scan records and report entries will be removed.\n"
            f"PDF files on disk will be PRESERVED.\n\n"
            f"This action CANNOT be undone."
        )
        box.setIcon(QMessageBox.Icon.Warning)
        delete_btn = box.addButton("Delete", QMessageBox.ButtonRole.YesRole)
        cancel_btn = box.addButton("Cancel", QMessageBox.ButtonRole.NoRole)
        box.setDefaultButton(delete_btn)

        box.exec()
        clicked = box.clickedButton()
        logger.info("Target deletion confirm dialog result: clicked %s", "Delete" if clicked == delete_btn else "Cancel")
        if clicked == delete_btn:
            self._delete_target(target_id)

    def _delete_target(self, target_id: int):
        logger.info("AdminPage._delete_target() executing for target_id=%s", target_id)
        if not session.is_admin_user():
            return
        db = get_db()
        try:
            t = db.query(Target).filter(Target.id == target_id).first()
            if not t:
                logger.warning("Target #%s not found in DB", target_id)
                return

            # Explicit cascade deletion of all scans and their children
            scans = db.query(Scan).filter(Scan.target_id == target_id).all()
            scan_ids = [s.id for s in scans]
            logger.info("Deleting %d scan(s) linked to target #%s: %s", len(scan_ids), target_id, scan_ids)
            if scan_ids:
                db.query(Report).filter(Report.scan_id.in_(scan_ids)).delete(synchronize_session=False)
                db.query(Finding).filter(Finding.scan_id.in_(scan_ids)).delete(synchronize_session=False)
                db.query(ScanLog).filter(ScanLog.scan_id.in_(scan_ids)).delete(synchronize_session=False)
                db.query(Scan).filter(Scan.id.in_(scan_ids)).delete(synchronize_session=False)

            # Delete the target
            db.delete(t)
            db.commit()
            logger.info("SUCCESS: Target #%s deleted by admin #%s", target_id, session.user_id)
        except Exception as e:
            import traceback
            logger.error("Error deleting target #%s: %s\n%s", target_id, e, traceback.format_exc())
            db.rollback()
            self.alert.show_message(f"Error deleting target: {e}")
            return
        finally:
            db.close()
        self._load_targets()
        self.alert.show_message(
            "Target deleted. PDF files on disk have been preserved.", auto_hide_ms=5000
        )

    def _set_target_status(self, target_id: int, status: TargetStatus):
        if not session.is_admin_user():
            return
        db = get_db()
        try:
            t = db.query(Target).filter(Target.id == target_id).first()
            if t:
                t.status      = status
                t.approved_by = session.user_id
                t.approved_at = datetime.now(timezone.utc)
                db.commit()
                logger.info("Target #%s status updated to %s", target_id, status.value)
        finally:
            db.close()
        self._load_targets()
        self.alert.show_message(f"Target marked as {status.value.upper()}.", auto_hide_ms=3000)
