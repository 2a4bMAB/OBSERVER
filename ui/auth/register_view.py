"""
OBSERVER — Register View
New account creation with email verification OTP flow.
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QFrame, QSizePolicy
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont

from core import auth
from core.database import UserRole
from core.mailer import send_registration_otp
from ui.design import theme as T
from ui.design.widgets import (
    LabeledInput, PrimaryButton, GhostButton, AlertBanner,
    LoadingSpinner, HudFrame, LogoWidget
)


# ─── Worker ────────────────────────────────────────────────────────────────────

class RegisterWorker(QThread):
    success = pyqtSignal(object)   # User
    failure = pyqtSignal(str)      # Error message

    def __init__(self, email: str, password: str, full_name: str):
        super().__init__()
        self.email = email
        self.password = password
        self.full_name = full_name

    def run(self):
        user, error = auth.register_user(
            self.email, self.password, self.full_name, UserRole.PENTESTER
        )
        if user:
            # Send verification OTP
            from core.database import OtpPurpose
            code = auth.create_otp_for_user(user.id, OtpPurpose.REGISTER)
            ok, err = send_registration_otp(user.email, user.full_name, code)
            if ok:
                self.success.emit(user)
            else:
                # Cleanup user since we can't verify
                self.failure.emit(
                    f"Account created but verification email failed: {err}. "
                    f"Check SMTP settings in .env"
                )
        else:
            self.failure.emit(error)


# ─── Register View ─────────────────────────────────────────────────────────────

class RegisterView(QWidget):
    """
    Registration form.
    Signals:
    - register_success(user_id) → Switch to email verification view
    - go_to_login               → Back to login
    """
    register_success = pyqtSignal(int)
    go_to_login = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Left branding panel ────────────────────────────────────────────
        left_panel = QFrame()
        left_panel.setStyleSheet(
            f"background-color: {T.c('bg_secondary')}; "
            f"border-right: 1px solid {T.c('border')};"
        )
        left_panel.setMinimumWidth(420)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        hud = HudFrame()
        hud.setFixedSize(320, 340)
        hud_layout = QVBoxLayout(hud)
        hud_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hud_layout.setContentsMargins(32, 32, 32, 32)
        hud_layout.setSpacing(16)

        self.logo = LogoWidget(size="large")
        hud_layout.addWidget(self.logo)

        hud_layout.addSpacing(16)

        # Info bullets
        for bullet in ["Email-based 2FA on every login", "Role-based access control", "Encrypted credentials"]:
            row = QHBoxLayout()
            row.setSpacing(8)
            dot = QLabel("—")
            dot.setStyleSheet(f"color: {T.c('accent_dim')}; background: transparent; font-size: 11px;")
            dot.setFixedWidth(16)
            lbl = QLabel(bullet)
            lbl.setStyleSheet(
                f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;"
            )
            row.addWidget(dot)
            row.addWidget(lbl)
            hud_layout.addLayout(row)

        left_layout.addStretch()
        left_layout.addWidget(hud, alignment=Qt.AlignmentFlag.AlignCenter)
        left_layout.addStretch()

        # ── Right form panel ───────────────────────────────────────────────
        right_panel = QFrame()
        right_panel.setStyleSheet(f"background-color: {T.c('bg_primary')};")
        right_layout = QVBoxLayout(right_panel)
        right_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        right_layout.setContentsMargins(64, 48, 64, 48)

        form_container = QWidget()
        form_container.setMaximumWidth(400)
        form_container.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        form_layout = QVBoxLayout(form_container)
        form_layout.setContentsMargins(0, 0, 0, 0)
        form_layout.setSpacing(0)

        title = QLabel("Create Account")
        title.setFont(QFont(T.FONT_UI, T.FONT_SIZE_2XL, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")

        subtitle = QLabel("Register for access to OBSERVER. An admin will assign your role.")
        subtitle.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;"
        )
        subtitle.setWordWrap(True)

        form_layout.addWidget(title)
        form_layout.addSpacing(6)
        form_layout.addWidget(subtitle)
        form_layout.addSpacing(28)

        # Alert
        self.alert = AlertBanner("error")
        form_layout.addWidget(self.alert)
        form_layout.addSpacing(4)

        # Fields
        self.name_input = LabeledInput("Full Name", "John Doe")
        self.email_input = LabeledInput("Email Address", "you@company.com")
        self.password_input = LabeledInput("Password", "••••••••", password=True)
        self.confirm_input = LabeledInput("Confirm Password", "••••••••", password=True)

        for w in [self.name_input, self.email_input, self.password_input, self.confirm_input]:
            form_layout.addWidget(w)
            form_layout.addSpacing(14)

        # Password strength hint
        hint = QLabel(
            "Min. 8 chars — uppercase, lowercase, digit & special character"
        )
        hint.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; background: transparent;"
        )
        hint.setWordWrap(True)
        form_layout.addWidget(hint)
        form_layout.addSpacing(24)

        # Submit
        self.register_btn = PrimaryButton("CREATE ACCOUNT")
        self.register_btn.setMinimumHeight(46)
        self.register_btn.clicked.connect(self._on_register)
        form_layout.addWidget(self.register_btn)
        form_layout.addSpacing(16)

        # Login link
        back_layout = QHBoxLayout()
        back_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        back_text = QLabel("Already have an account?")
        back_text.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;"
        )
        self.login_btn = GhostButton("Sign In")
        self.login_btn.setStyleSheet(
            f"color: {T.c('accent')}; font-size: {T.FONT_SIZE_SM}px; "
            f"background: transparent; border: none; padding: 0; font-weight: 600;"
        )
        self.login_btn.clicked.connect(self.go_to_login.emit)
        back_layout.addWidget(back_text)
        back_layout.addWidget(self.login_btn)
        form_layout.addLayout(back_layout)

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

        # Enter key
        self.confirm_input.input.returnPressed.connect(self._on_register)

    def _validate(self) -> bool:
        """Validate all fields. Returns True if valid."""
        ok = True

        self.name_input.clear_error()
        self.email_input.clear_error()
        self.password_input.clear_error()
        self.confirm_input.clear_error()
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
        self.register_btn.set_loading(loading, "CREATING ACCOUNT...")
        self.spinner.start() if loading else self.spinner.stop()
        for w in [self.name_input, self.email_input, self.password_input, self.confirm_input]:
            w.input.setEnabled(not loading)

    def _on_register(self):
        if not self._validate():
            return

        self._set_loading(True)

        self._worker = RegisterWorker(
            email=self.email_input.text().strip(),
            password=self.password_input.text(),
            full_name=self.name_input.text().strip(),
        )
        self._worker.success.connect(self._on_success)
        self._worker.failure.connect(self._on_failure)
        self._worker.start()

    def _on_success(self, user):
        self._set_loading(False)
        self.register_success.emit(user.id)

    def _on_failure(self, error: str):
        self._set_loading(False)
        self.alert.show_message(error)

    def clear(self):
        for w in [self.name_input, self.email_input, self.password_input, self.confirm_input]:
            w.setText("")
            w.clear_error()
        self.alert.hide_message()
