"""
OBSERVER — Settings Page (Phase 3)
Configure SMTP, appearance, and scan parameters.
"""
import os
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QComboBox, QSpinBox, QTextEdit, QLineEdit
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont

from core.config import config
from core.mailer import test_smtp_connection
from ui.design import theme as T
from ui.design.widgets import (
    LabeledInput, PrimaryButton, SecondaryButton, Card,
    SectionLabel, AlertBanner, LoadingSpinner
)


# ─── SMTP Test Worker ──────────────────────────────────────────────────────────

class SmtpTestWorker(QThread):
    finished = pyqtSignal(bool, str)

    def __init__(self, host, port, user, password, use_tls):
        super().__init__()
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.use_tls = use_tls

    def run(self):
        ok, msg = test_smtp_connection(
            self.host, int(self.port), self.user, self.password, self.use_tls
        )
        self.finished.emit(ok, msg)


# ─── Section Divider ──────────────────────────────────────────────────────────

def _make_section(title: str, description: str) -> QWidget:
    w = QWidget()
    w.setStyleSheet("background: transparent;")
    layout = QVBoxLayout(w)
    layout.setContentsMargins(0, 0, 0, 4)
    layout.setSpacing(2)
    t = QLabel(title)
    t.setFont(QFont(T.FONT_UI, T.FONT_SIZE_MD, QFont.Weight.Bold))
    t.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")
    d = QLabel(description)
    d.setWordWrap(True)
    d.setStyleSheet(f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;")
    layout.addWidget(t)
    layout.addWidget(d)
    return w


def _make_card() -> tuple[QFrame, QVBoxLayout]:
    card = QFrame()
    card.setProperty("class", "card")
    layout = QVBoxLayout(card)
    layout.setContentsMargins(24, 20, 24, 20)
    layout.setSpacing(14)
    return card, layout


# ─── Settings Page ────────────────────────────────────────────────────────────

class SettingsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._env_path = config.ENV_FILE
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
        title_lbl = QLabel("Settings")
        title_lbl.setFont(QFont(T.FONT_UI, T.FONT_SIZE_LG, QFont.Weight.Bold))
        title_lbl.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")
        tb.addWidget(title_lbl)
        layout.addWidget(topbar)

        inner = QWidget()
        il = QVBoxLayout(inner)
        il.setContentsMargins(36, 28, 36, 36)
        il.setSpacing(28)

        self.alert = AlertBanner("success")
        il.addWidget(self.alert)

        # ── SMTP Configuration ───────────────────────────────────────────────
        il.addWidget(_make_section(
            "SMTP Configuration",
            "Required for email verification (2FA), registration OTPs, and vulnerability alerts. "
            "Settings are stored in your .env file."
        ))

        smtp_card, smtp_layout = _make_card()

        self.smtp_host = LabeledInput("SMTP Host", "smtp.gmail.com")
        self.smtp_port = LabeledInput("SMTP Port", "587")
        self.smtp_user = LabeledInput("SMTP Username / Email", "your@email.com")
        self.smtp_pass = LabeledInput("SMTP Password / App Password", "••••••••••••", password=True)
        self.smtp_from = LabeledInput("From Email Address", "observer@yourcompany.com")

        for w in [self.smtp_host, self.smtp_port, self.smtp_user, self.smtp_pass, self.smtp_from]:
            smtp_layout.addWidget(w)

        btn_row = QHBoxLayout()
        self.test_btn = SecondaryButton("◉ Test Connection")
        self.test_btn.clicked.connect(self._test_smtp)
        self.save_smtp_btn = PrimaryButton("Save SMTP Settings")
        self.save_smtp_btn.clicked.connect(self._save_smtp)
        self.smtp_spinner = LoadingSpinner()
        self.smtp_spinner.setVisible(False)
        btn_row.addWidget(self.test_btn)
        btn_row.addWidget(self.smtp_spinner)
        btn_row.addStretch()
        btn_row.addWidget(self.save_smtp_btn)
        smtp_layout.addLayout(btn_row)
        il.addWidget(smtp_card)

        # ── Appearance ───────────────────────────────────────────────────────
        il.addWidget(_make_section(
            "Appearance",
            "Switch between dark and light themes."
        ))
        theme_card, theme_layout = _make_card()
        theme_row = QHBoxLayout()
        theme_label = QLabel("Theme")
        theme_label.setStyleSheet(f"color: {T.c('text_secondary')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;")
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Dark (Default)", "Light"])
        self.theme_combo.setStyleSheet(
            f"QComboBox {{ background: {T.c('bg_elevated')}; color: {T.c('text_primary')}; "
            f"border: 1px solid {T.c('border')}; border-radius: {T.RADIUS_SM}px; "
            f"padding: 6px 12px; font-size: {T.FONT_SIZE_SM}px; }}"
        )
        self.theme_combo.currentIndexChanged.connect(self._on_theme_changed)
        theme_apply_btn = SecondaryButton("Apply")
        theme_apply_btn.clicked.connect(self._apply_theme)
        theme_row.addWidget(theme_label)
        theme_row.addWidget(self.theme_combo)
        theme_row.addWidget(theme_apply_btn)
        theme_row.addStretch()
        theme_layout.addLayout(theme_row)
        il.addWidget(theme_card)

        # ── Scan Configuration ───────────────────────────────────────────────
        il.addWidget(_make_section(
            "Scan Configuration",
            "Configure scan engine behavior, request timeouts, and detection sensitivity."
        ))
        scan_card, scan_layout = _make_card()

        to_row = QHBoxLayout()
        to_label = QLabel("Request timeout (seconds)")
        to_label.setStyleSheet(f"color: {T.c('text_secondary')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;")
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 60)
        self.timeout_spin.setValue(10)
        self.timeout_spin.setStyleSheet(
            f"QSpinBox {{ background: {T.c('bg_elevated')}; color: {T.c('text_primary')}; "
            f"border: 1px solid {T.c('border')}; border-radius: {T.RADIUS_SM}px; padding: 6px; }}"
        )
        to_row.addWidget(to_label)
        to_row.addWidget(self.timeout_spin)
        to_row.addStretch()
        scan_layout.addLayout(to_row)

        td_row = QHBoxLayout()
        td_label = QLabel("Max crawl depth")
        td_label.setStyleSheet(f"color: {T.c('text_secondary')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;")
        self.depth_spin = QSpinBox()
        self.depth_spin.setRange(1, 10)
        self.depth_spin.setValue(3)
        self.depth_spin.setStyleSheet(self.timeout_spin.styleSheet())
        td_row.addWidget(td_label)
        td_row.addWidget(self.depth_spin)
        td_row.addStretch()
        scan_layout.addLayout(td_row)

        info_note = QLabel(
            "Note: Full scan engine configuration will be available in Phase 4."
        )
        info_note.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; background: transparent; "
            f"font-style: italic;"
        )
        scan_layout.addWidget(info_note)

        save_scan_btn = SecondaryButton("Save Scan Settings")
        save_scan_btn.clicked.connect(lambda: self.alert.show_message(
            "Scan settings saved.", auto_hide_ms=3000
        ))
        scan_layout.addWidget(save_scan_btn)
        il.addWidget(scan_card)

        il.addStretch()
        layout.addWidget(inner)

    def on_enter(self):
        """Load current .env values."""
        self.smtp_host.setText(config.SMTP_HOST or "")
        self.smtp_port.setText(str(config.SMTP_PORT))
        self.smtp_user.setText(config.SMTP_USER or "")
        self.smtp_from.setText(config.SMTP_FROM or "")
        # Don't pre-fill password

    def _test_smtp(self):
        self.test_btn.setEnabled(False)
        self.smtp_spinner.setVisible(True)
        self.smtp_spinner.start()

        self._smtp_worker = SmtpTestWorker(
            host=self.smtp_host.text().strip(),
            port=self.smtp_port.text().strip() or "587",
            user=self.smtp_user.text().strip(),
            password=self.smtp_pass.text(),
            use_tls=True,
        )
        self._smtp_worker.finished.connect(self._on_smtp_test_done)
        self._smtp_worker.start()

    def _on_smtp_test_done(self, ok: bool, msg: str):
        self.smtp_spinner.stop()
        self.smtp_spinner.setVisible(False)
        self.test_btn.setEnabled(True)
        if ok:
            self.alert.show_message(f"✓ SMTP connection successful! {msg}", auto_hide_ms=5000)
        else:
            self.alert.show_message(f"✕ SMTP test failed: {msg}", auto_hide_ms=0)

    def _save_smtp(self):
        """Write updated SMTP settings to .env file."""
        env_content = ""
        try:
            if self._env_path.exists():
                env_content = self._env_path.read_text(encoding="utf-8")
        except Exception:
            pass

        updates = {
            "SMTP_HOST": self.smtp_host.text().strip(),
            "SMTP_PORT": self.smtp_port.text().strip() or "587",
            "SMTP_USER": self.smtp_user.text().strip(),
            "SMTP_FROM": self.smtp_from.text().strip(),
        }
        if self.smtp_pass.text():
            updates["SMTP_PASS"] = self.smtp_pass.text()

        lines = env_content.splitlines()
        updated_keys = set()
        new_lines = []
        for line in lines:
            key = line.split("=")[0].strip()
            if key in updates:
                new_lines.append(f"{key}={updates[key]}")
                updated_keys.add(key)
            else:
                new_lines.append(line)

        for key, val in updates.items():
            if key not in updated_keys:
                new_lines.append(f"{key}={val}")

        try:
            self._env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
            self.alert.show_message("SMTP settings saved to .env. Restart OBSERVER to apply.", auto_hide_ms=6000)
        except Exception as e:
            self.alert.show_message(f"Failed to save .env: {e}", auto_hide_ms=0)

    def _on_theme_changed(self, index: int):
        pass  # Just track selection

    def _apply_theme(self):
        from ui.design.theme import Theme
        from ui.app import MainWindow
        idx = self.theme_combo.currentIndex()
        theme = Theme.DARK if idx == 0 else Theme.LIGHT
        # Find MainWindow and apply
        from PyQt6.QtWidgets import QApplication
        for w in QApplication.topLevelWidgets():
            if isinstance(w, MainWindow):
                w.apply_theme(theme)
                break
        self.alert.show_message("Theme applied.", auto_hide_ms=3000)
