"""
OBSERVER — Profile Page (Phase 3)
User profile view with secure modification (password/2FA revalidation).
"""
from datetime import datetime, timezone
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QDialog, QSizePolicy
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont

from core import auth
from core.database import get_db, User, OtpPurpose
from core.rbac import session
from core.mailer import send_profile_change_otp
from ui.design import theme as T
from ui.design.widgets import (
    LabeledInput, PrimaryButton, SecondaryButton, DangerButton,
    Card, SectionLabel, AlertBanner, LoadingSpinner, HudFrame
)


# ─── Change Password Dialog ────────────────────────────────────────────────────

class ChangePasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Change Password")
        self.setMinimumWidth(440)
        self.setStyleSheet(f"background: {T.c('bg_primary')};")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        title = QLabel("Change Password")
        title.setFont(QFont(T.FONT_UI, T.FONT_SIZE_LG, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")
        layout.addWidget(title)

        desc = QLabel(
            "Enter your current password to authorize the change. "
            "A 2FA code will be sent to your email."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;")
        layout.addWidget(desc)

        self.alert = AlertBanner("error")
        layout.addWidget(self.alert)

        self.current_pwd = LabeledInput("Current Password", "••••••••", password=True)
        self.new_pwd = LabeledInput("New Password", "••••••••", password=True)
        self.confirm_pwd = LabeledInput("Confirm New Password", "••••••••", password=True)
        for w in [self.current_pwd, self.new_pwd, self.confirm_pwd]:
            layout.addWidget(w)

        hint = QLabel("Min. 8 chars — uppercase, lowercase, digit & special character")
        hint.setStyleSheet(f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; background: transparent;")
        layout.addWidget(hint)

        btn_layout = QHBoxLayout()
        cancel_btn = SecondaryButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        self.save_btn = PrimaryButton("Change Password")
        self.save_btn.clicked.connect(self._on_save)
        btn_layout.addWidget(cancel_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.save_btn)
        layout.addLayout(btn_layout)

    def _on_save(self):
        self.alert.hide_message()
        for w in [self.current_pwd, self.new_pwd, self.confirm_pwd]:
            w.clear_error()

        # Validate current password
        user, err = auth.authenticate_user(session.user_email, self.current_pwd.text())
        if not user:
            self.current_pwd.set_error("Current password is incorrect.")
            return

        # Validate new password strength
        valid, msg = auth.validate_password_strength(self.new_pwd.text())
        if not valid:
            self.new_pwd.set_error(msg)
            return

        if self.new_pwd.text() != self.confirm_pwd.text():
            self.confirm_pwd.set_error("Passwords do not match.")
            return

        # Update
        ok, err = auth.update_user_password(session.user_id, self.new_pwd.text())
        if ok:
            self.accept()
        else:
            self.alert.show_message(err)


# ─── Profile Page ─────────────────────────────────────────────────────────────

class ProfilePage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("background: transparent; border: none;")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        content = QWidget()
        content.setStyleSheet(f"background: {T.c('bg_primary')};")
        scroll.setWidget(content)

        layout = QVBoxLayout(content)
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
        title_lbl = QLabel("Profile")
        title_lbl.setFont(QFont(T.FONT_UI, T.FONT_SIZE_LG, QFont.Weight.Bold))
        title_lbl.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")
        tb.addWidget(title_lbl)
        layout.addWidget(topbar)

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(36, 28, 36, 36)
        inner_layout.setSpacing(24)

        self.alert = AlertBanner("success")
        inner_layout.addWidget(self.alert)

        # ── Identity Card ────────────────────────────────────────────────────
        id_card = QFrame()
        id_card.setProperty("class", "card")
        id_layout = QVBoxLayout(id_card)
        id_layout.setContentsMargins(24, 20, 24, 20)
        id_layout.setSpacing(16)
        id_layout.addWidget(SectionLabel("Account Information"))

        # Avatar / initials
        avatar_row = QHBoxLayout()
        avatar_row.setSpacing(16)
        self.avatar_label = QLabel("AB")
        self.avatar_label.setFixedSize(56, 56)
        self.avatar_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.avatar_label.setStyleSheet(
            f"background: {T.c('bg_elevated')}; color: {T.c('accent')}; "
            f"border: 1px solid {T.c('border')}; border-radius: 28px; "
            f"font-size: {T.FONT_SIZE_XL}px; font-weight: 700;"
        )
        self.name_big = QLabel("—")
        self.name_big.setFont(QFont(T.FONT_UI, T.FONT_SIZE_XL, QFont.Weight.Bold))
        self.name_big.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")

        name_col = QVBoxLayout()
        name_col.setSpacing(4)
        self.email_big = QLabel("—")
        self.email_big.setStyleSheet(f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;")
        self.role_big = QLabel("—")
        self.role_big.setStyleSheet(
            f"color: {T.c('accent_dim')}; font-size: {T.FONT_SIZE_XS}px; "
            f"letter-spacing: 2px; background: transparent;"
        )
        name_col.addWidget(self.name_big)
        name_col.addWidget(self.email_big)
        name_col.addWidget(self.role_big)

        avatar_row.addWidget(self.avatar_label)
        avatar_row.addLayout(name_col, 1)

        logout_btn = SecondaryButton("⎋ Log Out")
        logout_btn.setFixedHeight(32)
        logout_btn.clicked.connect(self._on_logout)
        avatar_row.addWidget(logout_btn, alignment=Qt.AlignmentFlag.AlignVCenter)

        id_layout.addLayout(avatar_row)

        # Info rows
        self.last_login_lbl = QLabel("Last login: —")
        self.last_login_lbl.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;"
        )
        id_layout.addWidget(self.last_login_lbl)

        inner_layout.addWidget(id_card)

        # ── Edit Profile ────────────────────────────────────────────────────
        edit_card = QFrame()
        edit_card.setProperty("class", "card")
        edit_layout = QVBoxLayout(edit_card)
        edit_layout.setContentsMargins(24, 20, 24, 20)
        edit_layout.setSpacing(14)
        edit_layout.addWidget(SectionLabel("Edit Profile"))

        self.name_input = LabeledInput("Full Name", "")
        self.email_input = LabeledInput("Email Address", "")
        edit_layout.addWidget(self.name_input)
        edit_layout.addWidget(self.email_input)

        # Warning
        warn = QFrame()
        warn.setStyleSheet(
            f"background: {T.c('severity_medium')}0f; border: 1px solid {T.c('severity_medium')}44; "
            f"border-radius: {T.RADIUS_MD}px;"
        )
        wl = QHBoxLayout(warn)
        wl.setContentsMargins(12, 8, 12, 8)
        wi = QLabel("⚠")
        wi.setStyleSheet(f"color: {T.c('severity_medium')}; background: transparent; font-size: 13px;")
        wt = QLabel(
            "Changing your email or name will require a 2FA verification code "
            "sent to your current email address."
        )
        wt.setWordWrap(True)
        wt.setStyleSheet(f"color: {T.c('severity_medium')}; font-size: {T.FONT_SIZE_XS}px; background: transparent;")
        wl.addWidget(wi)
        wl.addWidget(wt, 1)
        edit_layout.addWidget(warn)

        save_btn = PrimaryButton("Save Changes")
        save_btn.clicked.connect(self._on_save_profile)
        edit_layout.addWidget(save_btn)
        inner_layout.addWidget(edit_card)

        # ── Security ────────────────────────────────────────────────────────
        sec_card = QFrame()
        sec_card.setProperty("class", "card")
        sec_layout = QVBoxLayout(sec_card)
        sec_layout.setContentsMargins(24, 20, 24, 20)
        sec_layout.setSpacing(14)
        sec_layout.addWidget(SectionLabel("Security"))

        sec_row = QHBoxLayout()
        sec_info = QVBoxLayout()
        sec_title = QLabel("Password")
        sec_title.setFont(QFont(T.FONT_UI, T.FONT_SIZE_MD, QFont.Weight.Bold))
        sec_title.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")
        sec_desc = QLabel("Change your account password. Your current password will be required.")
        sec_desc.setStyleSheet(f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;")
        sec_desc.setWordWrap(True)
        sec_info.addWidget(sec_title)
        sec_info.addWidget(sec_desc)

        pwd_btn = SecondaryButton("Change Password")
        pwd_btn.setFixedWidth(160)
        pwd_btn.clicked.connect(self._on_change_password)
        sec_row.addLayout(sec_info, 1)
        sec_row.addWidget(pwd_btn, alignment=Qt.AlignmentFlag.AlignVCenter)
        sec_layout.addLayout(sec_row)

        inner_layout.addWidget(sec_card)
        inner_layout.addStretch()
        layout.addWidget(inner)

    def on_enter(self):
        if not session.is_authenticated:
            return
        db = get_db()
        try:
            user = db.query(User).filter(User.id == session.user_id).first()
            if not user:
                return
            initials = "".join(p[0].upper() for p in user.full_name.split()[:2]) if user.full_name else "?"
            self.avatar_label.setText(initials)
            self.name_big.setText(user.full_name)
            self.email_big.setText(user.email)
            self.role_big.setText(user.role.value.upper())
            self.name_input.setText(user.full_name)
            self.email_input.setText(user.email)
            if user.last_login:
                self.last_login_lbl.setText(
                    f"Last login: {user.last_login.strftime('%Y-%m-%d %H:%M UTC')}"
                )
        finally:
            db.close()

    def _on_save_profile(self):
        """Initiate profile change with 2FA verification."""
        new_name = self.name_input.text().strip()
        new_email = self.email_input.text().strip()

        if not new_name or not new_email:
            self.alert.show_message("Name and email are required.")
            return

        # Send OTP for authorization
        db = get_db()
        try:
            user = db.query(User).filter(User.id == session.user_id).first()
            code = auth.create_otp_for_user(session.user_id, OtpPurpose.PROFILE_CHANGE)
            from core.mailer import send_profile_change_otp
            ok, err = send_profile_change_otp(user.email, user.full_name, code)
            if not ok:
                self.alert.show_message(f"Failed to send verification code: {err}")
                return
        finally:
            db.close()

        # Show OTP verification inline
        from ui.auth.verify_view import VerifyView
        from PyQt6.QtWidgets import QDialog, QVBoxLayout

        dlg = QDialog(self)
        dlg.setWindowTitle("Authorize Profile Change")
        dlg.setMinimumWidth(700)
        dlg.setMinimumHeight(500)
        dlg.setStyleSheet(f"background: {T.c('bg_primary')};")
        dlg_layout = QVBoxLayout(dlg)
        dlg_layout.setContentsMargins(0, 0, 0, 0)

        verify = VerifyView(OtpPurpose.PROFILE_CHANGE)
        verify.configure(session.user_id, OtpPurpose.PROFILE_CHANGE)
        dlg_layout.addWidget(verify)

        def on_verified():
            ok, err = auth.update_user_profile(session.user_id, new_name, new_email)
            dlg.accept()
            if ok:
                # Update session
                session.user_name = new_name
                session.user_email = new_email
                self.alert.show_message("Profile updated successfully.", auto_hide_ms=4000)
                self.on_enter()
            else:
                self.alert.show_message(f"Update failed: {err}")

        verify.verify_success.connect(on_verified)
        verify.go_back.connect(dlg.reject)
        dlg.exec()

    def _on_change_password(self):
        dlg = ChangePasswordDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.alert.show_message("Password changed successfully.", auto_hide_ms=4000)

    def _on_logout(self):
        w = self.window()
        if hasattr(w, "logout"):
            w.logout()
