"""
OBSERVER — Login View
Email + password authentication with rate limiting feedback.
After success → triggers 2FA OTP flow.
"""
from typing import Callable
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QSizePolicy, QSpacerItem
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont

from core import auth
from core.database import OtpPurpose
from core.mailer import send_2fa_otp
from ui.design import theme as T
from ui.design.widgets import (
    LabeledInput, PrimaryButton, GhostButton, AlertBanner,
    LoadingSpinner, HudFrame, LogoWidget
)


# ─── Worker Thread ─────────────────────────────────────────────────────────────

class LoginWorker(QThread):
    success = pyqtSignal(object)    # User object
    failure = pyqtSignal(str)       # Error message

    def __init__(self, email: str, password: str):
        super().__init__()
        self.email = email
        self.password = password

    def run(self):
        user, error = auth.authenticate_user(self.email, self.password)
        if user:
            self.success.emit(user)
        else:
            self.failure.emit(error)


class OtpSendWorker(QThread):
    success = pyqtSignal()
    failure = pyqtSignal(str)

    def __init__(self, user_id: int, email: str, full_name: str):
        super().__init__()
        self.user_id = user_id
        self.email = email
        self.full_name = full_name

    def run(self):
        from core.database import OtpPurpose
        code = auth.create_otp_for_user(self.user_id, OtpPurpose.LOGIN_2FA)
        ok, err = send_2fa_otp(self.email, self.full_name, code)
        if ok:
            self.success.emit()
        else:
            self.failure.emit(err)


# ─── Login View ────────────────────────────────────────────────────────────────

class LoginView(QWidget):
    """
    Full-screen login page. Signals:
    - login_success(user_id, role) → Main app handles session creation
    - go_to_register              → Switch to register view
    """
    login_success = pyqtSignal(int, str)   # user_id, role
    go_to_register = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._pending_user = None
        self._setup_ui()

    def _setup_ui(self):
        # Full-screen background
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Left panel (branding) ──────────────────────────────────────────
        left_panel = QFrame()
        left_panel.setStyleSheet(
            f"background-color: {T.c('bg_secondary')}; "
            f"border-right: 1px solid {T.c('border')};"
        )
        left_panel.setMinimumWidth(420)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        left_layout.setSpacing(20)

        # HUD-styled branding area
        hud = HudFrame()
        hud.setFixedSize(320, 280)
        hud_layout = QVBoxLayout(hud)
        hud_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hud_layout.setSpacing(16)
        hud_layout.setContentsMargins(32, 32, 32, 32)

        self.logo = LogoWidget(size="large")
        hud_layout.addWidget(self.logo)

        left_layout.addStretch()
        left_layout.addWidget(hud, alignment=Qt.AlignmentFlag.AlignCenter)

        # Bottom status line
        status_layout = QHBoxLayout()
        status_layout.setContentsMargins(32, 0, 32, 0)
        dot = QLabel("●")
        dot.setStyleSheet(f"color: {T.c('accent_dim')}; font-size: 8px; background: transparent;")
        status_label = QLabel("SYSTEM ACTIVE")
        status_label.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; "
            f"letter-spacing: 2px; background: transparent;"
        )
        version_label = QLabel(f"v{T.FONT_SIZE_BASE}")
        version_label.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; background: transparent;"
        )
        from core.config import config
        version_label.setText(f"v{config.APP_VERSION}")
        status_layout.addWidget(dot)
        status_layout.addWidget(status_label)
        status_layout.addStretch()
        status_layout.addWidget(version_label)

        left_layout.addStretch()
        left_layout.addLayout(status_layout)
        left_layout.setContentsMargins(0, 0, 0, 24)

        # ── Right panel (form) ─────────────────────────────────────────────
        right_panel = QFrame()
        right_panel.setStyleSheet(f"background-color: {T.c('bg_primary')};")
        right_layout = QVBoxLayout(right_panel)
        right_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        right_layout.setContentsMargins(64, 48, 64, 48)
        right_layout.setSpacing(0)

        # Form container
        form_container = QWidget()
        form_container.setMaximumWidth(380)
        form_container.setSizePolicy(
            QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed
        )
        form_layout = QVBoxLayout(form_container)
        form_layout.setContentsMargins(0, 0, 0, 0)
        form_layout.setSpacing(0)

        # Title
        title = QLabel("Sign In")
        title.setFont(QFont(T.FONT_UI, T.FONT_SIZE_2XL, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")

        subtitle = QLabel("Enter your credentials to access OBSERVER")
        subtitle.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;"
        )
        subtitle.setWordWrap(True)

        form_layout.addWidget(title)
        form_layout.addSpacing(6)
        form_layout.addWidget(subtitle)
        form_layout.addSpacing(32)

        # Alert banner
        self.alert = AlertBanner("error")
        form_layout.addWidget(self.alert)
        form_layout.addSpacing(4)

        # Email input
        self.email_input = LabeledInput("Email Address", "you@company.com")
        form_layout.addWidget(self.email_input)
        form_layout.addSpacing(16)

        # Password input
        self.password_input = LabeledInput("Password", "••••••••", password=True)
        form_layout.addWidget(self.password_input)
        form_layout.addSpacing(28)

        # Submit button
        self.login_btn = PrimaryButton("AUTHENTICATE")
        self.login_btn.setMinimumHeight(46)
        self.login_btn.clicked.connect(self._on_login)
        form_layout.addWidget(self.login_btn)
        form_layout.addSpacing(20)

        # Register link
        register_layout = QHBoxLayout()
        register_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        register_text = QLabel("New to OBSERVER?")
        register_text.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;"
        )
        self.register_btn = GhostButton("Request Access")
        self.register_btn.setStyleSheet(
            f"color: {T.c('accent')}; font-size: {T.FONT_SIZE_SM}px; "
            f"background: transparent; border: none; padding: 0; font-weight: 600;"
        )
        self.register_btn.clicked.connect(self.go_to_register.emit)
        register_layout.addWidget(register_text)
        register_layout.addWidget(self.register_btn)
        form_layout.addLayout(register_layout)

        # Spinner
        spinner_layout = QHBoxLayout()
        spinner_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.spinner = LoadingSpinner()
        self.spinner.setVisible(False)
        spinner_layout.addWidget(self.spinner)
        form_layout.addSpacing(8)
        form_layout.addLayout(spinner_layout)

        right_layout.addWidget(form_container, alignment=Qt.AlignmentFlag.AlignCenter)

        main_layout.addWidget(left_panel)
        main_layout.addWidget(right_panel, 1)

        # Enter key shortcut
        self.password_input.input.returnPressed.connect(self._on_login)
        self.email_input.input.returnPressed.connect(self.password_input.input.setFocus)

    def _set_loading(self, loading: bool):
        self.login_btn.set_loading(loading, "AUTHENTICATING...")
        self.spinner.start() if loading else self.spinner.stop()
        self.email_input.input.setEnabled(not loading)
        self.password_input.input.setEnabled(not loading)

    def _on_login(self):
        email = self.email_input.text().strip()
        password = self.password_input.text()

        self.email_input.clear_error()
        self.password_input.clear_error()
        self.alert.hide_message()

        # Basic validation
        if not email:
            self.email_input.set_error("Email address is required.")
            return
        if not password:
            self.password_input.set_error("Password is required.")
            return

        self._set_loading(True)

        self._worker = LoginWorker(email, password)
        self._worker.success.connect(self._on_credentials_valid)
        self._worker.failure.connect(self._on_credentials_invalid)
        self._worker.start()

    def _on_credentials_valid(self, user):
        """Credentials OK → send 2FA OTP."""
        self._pending_user_id = user.id
        self._otp_worker = OtpSendWorker(user.id, user.email, user.full_name)
        self._otp_worker.success.connect(self._on_otp_sent)
        self._otp_worker.failure.connect(self._on_otp_failed)
        self._otp_worker.start()

    def _on_otp_sent(self):
        self._set_loading(False)
        # Switch to 2FA view — signal parent with pending user
        self.login_success.emit(self._pending_user_id, "__awaiting_2fa__")

    def _on_otp_failed(self, error: str):
        self._set_loading(False)
        self.alert.show_message(
            f"2FA email could not be sent: {error}\n"
            f"Check SMTP configuration in .env file."
        )

    def _on_credentials_invalid(self, error: str):
        self._set_loading(False)
        self.alert.show_message(error)

    def clear(self):
        """Reset the form."""
        self.email_input.setText("")
        self.password_input.setText("")
        self.email_input.clear_error()
        self.password_input.clear_error()
        self.alert.hide_message()
