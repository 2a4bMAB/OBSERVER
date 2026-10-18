"""
OBSERVER — OTP Verification View
Used for both:
  - Email verification after registration (purpose=REGISTER)
  - 2FA after login (purpose=LOGIN_2FA)
  - Profile change authorization (purpose=PROFILE_CHANGE)
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QSizePolicy
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont

from core import auth
from core.database import OtpPurpose
from ui.design import theme as T
from ui.design.widgets import (
    OtpInput, PrimaryButton, GhostButton, AlertBanner,
    LoadingSpinner, HudFrame, LogoWidget
)


# ─── Worker ────────────────────────────────────────────────────────────────────

class VerifyOtpWorker(QThread):
    success = pyqtSignal()
    failure = pyqtSignal(str)

    def __init__(self, user_id: int, code: str, purpose: OtpPurpose):
        super().__init__()
        self.user_id = user_id
        self.code = code
        self.purpose = purpose

    def run(self):
        ok, error = auth.validate_otp(self.user_id, self.code, self.purpose)
        if ok:
            self.success.emit()
        else:
            self.failure.emit(error)


class ResendOtpWorker(QThread):
    success = pyqtSignal()
    failure = pyqtSignal(str)

    def __init__(self, user_id: int, purpose: OtpPurpose):
        super().__init__()
        self.user_id = user_id
        self.purpose = purpose

    def run(self):
        from core.database import get_db, User
        from core.mailer import send_registration_otp, send_2fa_otp, send_profile_change_otp

        db = get_db()
        try:
            user = db.query(User).filter(User.id == self.user_id).first()
            if not user:
                self.failure.emit("User not found.")
                return
            code = auth.create_otp_for_user(self.user_id, self.purpose)

            if self.purpose == OtpPurpose.REGISTER:
                ok, err = send_registration_otp(user.email, user.full_name, code)
            elif self.purpose == OtpPurpose.LOGIN_2FA:
                ok, err = send_2fa_otp(user.email, user.full_name, code)
            else:
                ok, err = send_profile_change_otp(user.email, user.full_name, code)

            if ok:
                self.success.emit()
            else:
                self.failure.emit(err)
        finally:
            db.close()


# ─── Verify View ───────────────────────────────────────────────────────────────

class VerifyView(QWidget):
    """
    OTP code entry screen.
    Signals:
    - verify_success()   → parent handles what to do next
    - go_back()          → return to previous view
    """
    verify_success = pyqtSignal()
    go_back = pyqtSignal()

    # Resend cooldown in seconds
    RESEND_COOLDOWN = 60

    def __init__(
        self,
        purpose: OtpPurpose = OtpPurpose.LOGIN_2FA,
        parent=None
    ):
        super().__init__(parent)
        self.purpose = purpose
        self._user_id: int | None = None
        self._resend_countdown = 0
        self._resend_timer = QTimer(self)
        self._resend_timer.timeout.connect(self._tick_resend)
        self._setup_ui()

    def configure(self, user_id: int, purpose: OtpPurpose):
        """Call before showing this view to set context."""
        self._user_id = user_id
        self.purpose = purpose
        self.otp_input.clear()
        self.alert.hide_message()
        self._update_copy()
        self._start_resend_cooldown()

    def _update_copy(self):
        """Update UI labels based on the current purpose."""
        copy = {
            OtpPurpose.REGISTER: {
                "title": "Verify Your Email",
                "desc": (
                    "A 6-digit verification code has been sent to your email address. "
                    "Enter it below to activate your account."
                ),
                "purpose_tag": "ACCOUNT VERIFICATION",
            },
            OtpPurpose.LOGIN_2FA: {
                "title": "Two-Factor Authentication",
                "desc": (
                    "A 6-digit authentication code has been sent to your email address. "
                    "Enter it below to complete your login."
                ),
                "purpose_tag": "2FA — EMAIL VERIFICATION",
            },
            OtpPurpose.PROFILE_CHANGE: {
                "title": "Authorize Profile Change",
                "desc": (
                    "For your security, a 6-digit authorization code has been sent to your "
                    "registered email. Enter it to confirm this change."
                ),
                "purpose_tag": "PROFILE CHANGE AUTHORIZATION",
            },
        }
        c = copy.get(self.purpose, copy[OtpPurpose.LOGIN_2FA])
        self.title_label.setText(c["title"])
        self.desc_label.setText(c["desc"])
        self.purpose_tag.setText(c["purpose_tag"])

    def _setup_ui(self):
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Left branding ──────────────────────────────────────────────────
        left_panel = QFrame()
        left_panel.setStyleSheet(
            f"background-color: {T.c('bg_secondary')}; "
            f"border-right: 1px solid {T.c('border')};"
        )
        left_panel.setMinimumWidth(420)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        hud = HudFrame()
        hud.setFixedSize(320, 280)
        hud_layout = QVBoxLayout(hud)
        hud_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hud_layout.setContentsMargins(32, 32, 32, 32)
        hud_layout.setSpacing(16)
        hud_layout.addWidget(LogoWidget(size="large"))

        left_layout.addStretch()
        left_layout.addWidget(hud, alignment=Qt.AlignmentFlag.AlignCenter)
        left_layout.addStretch()

        # ── Right form ─────────────────────────────────────────────────────
        right_panel = QFrame()
        right_panel.setStyleSheet(f"background-color: {T.c('bg_primary')};")
        right_layout = QVBoxLayout(right_panel)
        right_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        right_layout.setContentsMargins(64, 48, 64, 48)

        form_container = QWidget()
        form_container.setMaximumWidth(380)
        form_layout = QVBoxLayout(form_container)
        form_layout.setContentsMargins(0, 0, 0, 0)
        form_layout.setSpacing(0)

        # Purpose tag
        self.purpose_tag = QLabel("2FA — EMAIL VERIFICATION")
        self.purpose_tag.setStyleSheet(
            f"color: {T.c('accent_dim')}; font-size: {T.FONT_SIZE_XS}px; "
            f"letter-spacing: 3px; background: transparent;"
        )

        # Title
        self.title_label = QLabel("Two-Factor Authentication")
        self.title_label.setFont(QFont(T.FONT_UI, T.FONT_SIZE_2XL, QFont.Weight.Bold))
        self.title_label.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")
        self.title_label.setWordWrap(True)

        # Description
        self.desc_label = QLabel("")
        self.desc_label.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;"
        )
        self.desc_label.setWordWrap(True)

        form_layout.addWidget(self.purpose_tag)
        form_layout.addSpacing(6)
        form_layout.addWidget(self.title_label)
        form_layout.addSpacing(10)
        form_layout.addWidget(self.desc_label)
        form_layout.addSpacing(32)

        # Alert
        self.alert = AlertBanner("error")
        form_layout.addWidget(self.alert)
        self.success_alert = AlertBanner("success")
        form_layout.addWidget(self.success_alert)
        form_layout.addSpacing(8)

        # OTP Label
        otp_label = QLabel("VERIFICATION CODE")
        otp_label.setStyleSheet(
            f"color: {T.c('text_secondary')}; font-size: {T.FONT_SIZE_SM}px; "
            f"font-weight: 600; letter-spacing: 1px; background: transparent;"
        )
        form_layout.addWidget(otp_label)
        form_layout.addSpacing(8)

        # OTP Input (large, centered)
        self.otp_input = OtpInput()
        self.otp_input.returnPressed.connect(self._on_verify)
        form_layout.addWidget(self.otp_input)
        form_layout.addSpacing(8)

        # Expiry notice
        expire_notice = QLabel(f"Code expires in {T.FONT_SIZE_BASE} minutes")
        from core.config import config
        expire_notice.setText(f"Code expires in {config.OTP_EXPIRE_MINUTES} minutes")
        expire_notice.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; "
            f"letter-spacing: 0.5px; background: transparent;"
        )
        form_layout.addWidget(expire_notice, alignment=Qt.AlignmentFlag.AlignRight)
        form_layout.addSpacing(24)

        # Verify button
        self.verify_btn = PrimaryButton("VERIFY")
        self.verify_btn.setMinimumHeight(46)
        self.verify_btn.clicked.connect(self._on_verify)
        form_layout.addWidget(self.verify_btn)
        form_layout.addSpacing(16)

        # Resend + back row
        action_layout = QHBoxLayout()
        self.back_btn = GhostButton("← Go Back")
        self.back_btn.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_SM}px; "
            f"background: transparent; border: none; padding: 0;"
        )
        self.back_btn.clicked.connect(self.go_back.emit)

        self.resend_btn = GhostButton("Resend Code")
        self.resend_btn.setStyleSheet(
            f"color: {T.c('accent')}; font-size: {T.FONT_SIZE_SM}px; "
            f"background: transparent; border: none; padding: 0; font-weight: 600;"
        )
        self.resend_btn.clicked.connect(self._on_resend)
        self.resend_btn.setEnabled(False)

        action_layout.addWidget(self.back_btn)
        action_layout.addStretch()
        action_layout.addWidget(self.resend_btn)
        form_layout.addLayout(action_layout)
        form_layout.addSpacing(8)

        # Spinner
        spinner_layout = QHBoxLayout()
        spinner_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.spinner = LoadingSpinner()
        self.spinner.setVisible(False)
        spinner_layout.addWidget(self.spinner)
        form_layout.addLayout(spinner_layout)

        right_layout.addWidget(form_container, alignment=Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(left_panel)
        main_layout.addWidget(right_panel, 1)

    def _start_resend_cooldown(self):
        """Start the resend button cooldown timer."""
        self._resend_countdown = self.RESEND_COOLDOWN
        self.resend_btn.setEnabled(False)
        self.resend_btn.setText(f"Resend Code ({self._resend_countdown}s)")
        self._resend_timer.start(1000)

    def _tick_resend(self):
        self._resend_countdown -= 1
        if self._resend_countdown <= 0:
            self._resend_timer.stop()
            self.resend_btn.setEnabled(True)
            self.resend_btn.setText("Resend Code")
        else:
            self.resend_btn.setText(f"Resend Code ({self._resend_countdown}s)")

    def _set_loading(self, loading: bool):
        self.verify_btn.set_loading(loading, "VERIFYING...")
        self.spinner.start() if loading else self.spinner.stop()
        self.otp_input.setEnabled(not loading)
        self.resend_btn.setEnabled(not loading and self._resend_countdown <= 0)
        self.back_btn.setEnabled(not loading)

    def _on_verify(self):
        code = self.otp_input.text().strip()
        self.alert.hide_message()
        self.success_alert.hide_message()

        if len(code) != 6 or not code.isdigit():
            self.alert.show_message("Please enter a 6-digit code.")
            return

        if not self._user_id:
            self.alert.show_message("Session error. Please go back and try again.")
            return

        self._set_loading(True)

        self._worker = VerifyOtpWorker(self._user_id, code, self.purpose)
        self._worker.success.connect(self._on_otp_valid)
        self._worker.failure.connect(self._on_otp_invalid)
        self._worker.start()

    def _on_otp_valid(self):
        self._set_loading(False)

        if self.purpose == OtpPurpose.REGISTER:
            auth.verify_account(self._user_id)

        self.verify_success.emit()

    def _on_otp_invalid(self, error: str):
        self._set_loading(False)
        self.otp_input.clear()
        self.alert.show_message(error)

    def _on_resend(self):
        if not self._user_id:
            return
        self.alert.hide_message()
        self.resend_btn.setEnabled(False)

        self._resend_worker = ResendOtpWorker(self._user_id, self.purpose)
        self._resend_worker.success.connect(self._on_resend_success)
        self._resend_worker.failure.connect(self._on_resend_failure)
        self._resend_worker.start()

    def _on_resend_success(self):
        self.success_alert.show_message(
            "A new verification code has been sent to your email.", auto_hide_ms=5000
        )
        self._start_resend_cooldown()

    def _on_resend_failure(self, error: str):
        self.alert.show_message(f"Failed to resend code: {error}")
        self._start_resend_cooldown()
