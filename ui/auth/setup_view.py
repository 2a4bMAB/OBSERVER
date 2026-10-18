"""
OBSERVER — First-Run Admin Setup View
Shown when no admin account exists (first launch).
Creates the initial admin user with email verification.
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QSizePolicy
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont

from core import auth
from core.database import UserRole
from core.mailer import send_registration_otp
from ui.design import theme as T
from ui.design.widgets import (
    LabeledInput, PrimaryButton, AlertBanner,
    LoadingSpinner, HudFrame, LogoWidget
)


# ─── Worker ────────────────────────────────────────────────────────────────────

class SetupAdminWorker(QThread):
    success = pyqtSignal(int)  # user_id
    failure = pyqtSignal(str)

    def __init__(self, email: str, password: str, full_name: str):
        super().__init__()
        self.email = email
        self.password = password
        self.full_name = full_name

    def run(self):
        user, error = auth.register_user(
            self.email, self.password, self.full_name, UserRole.ADMIN
        )
        if not user:
            self.failure.emit(error)
            return

        from core.database import OtpPurpose
        code = auth.create_otp_for_user(user.id, OtpPurpose.REGISTER)
        ok, err = send_registration_otp(user.email, user.full_name, code)

        if ok:
            self.success.emit(user.id)
        else:
            self.failure.emit(
                f"Admin account created but verification email failed.\n"
                f"Error: {err}\n"
                f"Check SMTP settings in your .env file."
            )


# ─── Setup View ────────────────────────────────────────────────────────────────

class SetupView(QWidget):
    """
    First-launch screen for creating the admin account.
    Signals:
    - setup_success(user_id) → go to OTP verification
    """
    setup_success = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Left panel ─────────────────────────────────────────────────────
        left_panel = QFrame()
        left_panel.setStyleSheet(
            f"background-color: {T.c('bg_secondary')}; "
            f"border-right: 1px solid {T.c('border')};"
        )
        left_panel.setMinimumWidth(420)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        hud = HudFrame()
        hud.setFixedSize(320, 320)
        hud_layout = QVBoxLayout(hud)
        hud_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hud_layout.setContentsMargins(32, 32, 32, 32)
        hud_layout.setSpacing(20)
        hud_layout.addWidget(LogoWidget(size="large"))

        # First run badge
        badge = QLabel("FIRST RUN — INITIAL SETUP")
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setStyleSheet(
            f"color: {T.c('severity_medium')}; font-size: {T.FONT_SIZE_XS}px; "
            f"letter-spacing: 2px; background: {T.c('severity_medium')}15; "
            f"border: 1px solid {T.c('severity_medium')}44; "
            f"border-radius: 3px; padding: 4px 10px;"
        )
        hud_layout.addWidget(badge)

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
        form_container.setMaximumWidth(400)
        form_layout = QVBoxLayout(form_container)
        form_layout.setContentsMargins(0, 0, 0, 0)
        form_layout.setSpacing(0)

        # Header tag
        tag = QLabel("SYSTEM INITIALIZATION")
        tag.setStyleSheet(
            f"color: {T.c('accent_dim')}; font-size: {T.FONT_SIZE_XS}px; "
            f"letter-spacing: 3px; background: transparent;"
        )

        title = QLabel("Create Admin Account")
        title.setFont(QFont(T.FONT_UI, T.FONT_SIZE_2XL, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")

        subtitle = QLabel(
            "No administrator account detected. Create the first admin account "
            "to initialize the OBSERVER platform. A verification code will be "
            "sent to the provided email."
        )
        subtitle.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;"
        )
        subtitle.setWordWrap(True)

        form_layout.addWidget(tag)
        form_layout.addSpacing(6)
        form_layout.addWidget(title)
        form_layout.addSpacing(8)
        form_layout.addWidget(subtitle)
        form_layout.addSpacing(28)

        # Warning box
        warning_frame = QFrame()
        warning_frame.setStyleSheet(
            f"background: {T.c('severity_medium')}0f; "
            f"border: 1px solid {T.c('severity_medium')}44; "
            f"border-radius: {T.RADIUS_MD}px;"
        )
        wf_layout = QHBoxLayout(warning_frame)
        wf_layout.setContentsMargins(14, 10, 14, 10)
        wf_layout.setSpacing(10)
        warn_icon = QLabel("⚠")
        warn_icon.setStyleSheet(f"color: {T.c('severity_medium')}; background: transparent; font-size: 14px;")
        warn_text = QLabel(
            "This account will have full administrative privileges. "
            "Use a secure password and a monitored email address."
        )
        warn_text.setStyleSheet(
            f"color: {T.c('severity_medium')}; font-size: {T.FONT_SIZE_XS}px; background: transparent;"
        )
        warn_text.setWordWrap(True)
        wf_layout.addWidget(warn_icon)
        wf_layout.addWidget(warn_text, 1)
        form_layout.addWidget(warning_frame)
        form_layout.addSpacing(20)

        # Alert
        self.alert = AlertBanner("error")
        form_layout.addWidget(self.alert)
        form_layout.addSpacing(4)

        # Fields
        self.name_input = LabeledInput("Administrator Full Name", "John Doe")
        self.email_input = LabeledInput("Email Address", "admin@company.com")
        self.password_input = LabeledInput("Password", "••••••••", password=True)
        self.confirm_input = LabeledInput("Confirm Password", "••••••••", password=True)

        for w in [self.name_input, self.email_input, self.password_input, self.confirm_input]:
            form_layout.addWidget(w)
            form_layout.addSpacing(14)

        hint = QLabel("Min. 8 chars — uppercase, lowercase, digit & special character")
        hint.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; background: transparent;"
        )
        form_layout.addWidget(hint)
        form_layout.addSpacing(24)

        self.setup_btn = PrimaryButton("INITIALIZE OBSERVER")
        self.setup_btn.setMinimumHeight(46)
        self.setup_btn.clicked.connect(self._on_setup)
        form_layout.addWidget(self.setup_btn)

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

        self.confirm_input.input.returnPressed.connect(self._on_setup)

    def _validate(self) -> bool:
        ok = True
        for w in [self.name_input, self.email_input, self.password_input, self.confirm_input]:
            w.clear_error()
        self.alert.hide_message()

        if not self.name_input.text().strip():
            self.name_input.set_error("Full name is required.")
            ok = False

        email = self.email_input.text().strip()
        if not email:
            self.email_input.set_error("Email address is required.")
            ok = False
        elif "@" not in email or "." not in email.split("@")[-1]:
            self.email_input.set_error("Please enter a valid email address.")
            ok = False

        password = self.password_input.text()
        valid, msg = auth.validate_password_strength(password)
        if not valid:
            self.password_input.set_error(msg)
            ok = False

        if self.confirm_input.text() != password:
            self.confirm_input.set_error("Passwords do not match.")
            ok = False

        return ok

    def _set_loading(self, loading: bool):
        self.setup_btn.set_loading(loading, "INITIALIZING...")
        self.spinner.start() if loading else self.spinner.stop()
        for w in [self.name_input, self.email_input, self.password_input, self.confirm_input]:
            w.input.setEnabled(not loading)

    def _on_setup(self):
        if not self._validate():
            return
        self._set_loading(True)
        self._worker = SetupAdminWorker(
            email=self.email_input.text().strip(),
            password=self.password_input.text(),
            full_name=self.name_input.text().strip(),
        )
        self._worker.success.connect(self._on_success)
        self._worker.failure.connect(self._on_failure)
        self._worker.start()

    def _on_success(self, user_id: int):
        self._set_loading(False)
        self.setup_success.emit(user_id)

    def _on_failure(self, error: str):
        self._set_loading(False)
        self.alert.show_message(error)
