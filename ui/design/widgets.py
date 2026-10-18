"""
OBSERVER — Reusable UI Widgets
Pre-styled components built on top of the design system.
"""
from typing import Optional, Callable
from PyQt6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QVBoxLayout, QWidget, QGraphicsOpacityEffect,
    QSizePolicy, QProgressBar
)
from PyQt6.QtCore import (
    Qt, QTimer, QPropertyAnimation, QEasingCurve, pyqtSignal, QSize
)
from PyQt6.QtGui import QFont, QColor, QPainter, QPen, QPixmap, QIcon

from ui.design import theme as T


# ─── Separator ────────────────────────────────────────────────────────────────

class HSeparator(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setProperty("class", "separator")
        self.setFrameShape(QFrame.Shape.HLine)
        self.setFixedHeight(1)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)


class VSeparator(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setProperty("class", "separator")
        self.setFrameShape(QFrame.Shape.VLine)
        self.setFixedWidth(1)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)


# ─── Card Frame ───────────────────────────────────────────────────────────────

class Card(QFrame):
    """A styled card container."""
    def __init__(self, elevated: bool = False, parent=None):
        super().__init__(parent)
        self.setProperty("class", "card-elevated" if elevated else "card")


# ─── Section Label ────────────────────────────────────────────────────────────

class SectionLabel(QLabel):
    """Small uppercase section/group title."""
    def __init__(self, text: str, parent=None):
        super().__init__(text.upper(), parent)
        self.setProperty("class", "section-title")


# ─── Labeled Input ────────────────────────────────────────────────────────────

class LabeledInput(QWidget):
    """A label + QLineEdit pair with error state support."""

    textChanged = pyqtSignal(str)

    def __init__(
        self,
        label: str,
        placeholder: str = "",
        password: bool = False,
        parent=None
    ):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self.label = QLabel(label)
        self.label.setStyleSheet(
            f"color: {T.c('text_secondary')}; font-size: {T.FONT_SIZE_SM}px; font-weight: 600; letter-spacing: 0.5px;"
        )

        self.input = QLineEdit()
        self.input.setPlaceholderText(placeholder)
        if password:
            self.input.setEchoMode(QLineEdit.EchoMode.Password)
        self.input.textChanged.connect(self.textChanged.emit)

        self.error_label = QLabel("")
        self.error_label.setStyleSheet(
            f"color: {T.c('severity_critical')}; font-size: {T.FONT_SIZE_XS}px;"
        )
        self.error_label.setVisible(False)

        layout.addWidget(self.label)
        layout.addWidget(self.input)
        layout.addWidget(self.error_label)

    def text(self) -> str:
        return self.input.text()

    def setText(self, text: str):
        self.input.setText(text)

    def set_error(self, message: str):
        self.input.setProperty("class", "error")
        self.input.style().unpolish(self.input)
        self.input.style().polish(self.input)
        self.error_label.setText(message)
        self.error_label.setVisible(True)

    def clear_error(self):
        self.input.setProperty("class", "")
        self.input.style().unpolish(self.input)
        self.input.style().polish(self.input)
        self.error_label.setText("")
        self.error_label.setVisible(False)


# ─── OTP Input ────────────────────────────────────────────────────────────────

class OtpInput(QLineEdit):
    """Large centered OTP code input field."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setProperty("class", "otp-input")
        self.setMaxLength(6)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setPlaceholderText("• • • • • •")


# ─── Primary Button ───────────────────────────────────────────────────────────

class PrimaryButton(QPushButton):
    def __init__(self, text: str, parent=None):
        super().__init__(text, parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(42)

    def set_loading(self, loading: bool, text: str = "Processing..."):
        self.setEnabled(not loading)
        if loading:
            self._original_text = self.text()
            self.setText(text)
        else:
            self.setText(getattr(self, "_original_text", self.text()))


class SecondaryButton(QPushButton):
    def __init__(self, text: str, parent=None):
        super().__init__(text, parent)
        self.setProperty("class", "secondary")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(42)


class GhostButton(QPushButton):
    def __init__(self, text: str, parent=None):
        super().__init__(text, parent)
        self.setProperty("class", "ghost")
        self.setCursor(Qt.CursorShape.PointingHandCursor)


class DangerButton(QPushButton):
    def __init__(self, text: str, parent=None):
        super().__init__(text, parent)
        self.setProperty("class", "danger")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(38)


# ─── Alert / Notification Banner ──────────────────────────────────────────────

class AlertBanner(QFrame):
    """Inline alert banner (error, success, warning, info)."""

    STYLES = {
        "error":   ("#ff2d2d", "#ff2d2d15", "#ff2d2d44"),
        "success": ("#4caf82", "#4caf8215", "#4caf8244"),
        "warning": ("#f0b429", "#f0b42915", "#f0b42944"),
        "info":    ("#5b9bd5", "#5b9bd515", "#5b9bd544"),
    }

    ICONS = {
        "error":   "✕",
        "success": "✓",
        "warning": "⚠",
        "info":    "ℹ",
    }

    def __init__(self, kind: str = "info", parent=None):
        super().__init__(parent)
        self.kind = kind
        fg, bg, border = self.STYLES.get(kind, self.STYLES["info"])

        self.setStyleSheet(
            f"background-color: {bg}; border: 1px solid {border}; "
            f"border-radius: {T.RADIUS_MD}px; padding: 0px;"
        )

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(10)

        icon_label = QLabel(self.ICONS.get(kind, "ℹ"))
        icon_label.setStyleSheet(f"color: {fg}; font-size: 14px; background: transparent; border: none;")
        icon_label.setFixedWidth(20)

        self.message_label = QLabel("")
        self.message_label.setStyleSheet(
            f"color: {fg}; font-size: {T.FONT_SIZE_SM}px; background: transparent; border: none;"
        )
        self.message_label.setWordWrap(True)

        layout.addWidget(icon_label)
        layout.addWidget(self.message_label, 1)

        self.setVisible(False)

    def show_message(self, text: str, auto_hide_ms: int = 0):
        self.message_label.setText(text)
        self.setVisible(True)
        if auto_hide_ms > 0:
            QTimer.singleShot(auto_hide_ms, self.hide)

    def hide_message(self):
        self.setVisible(False)
        self.message_label.setText("")


# ─── Loading Spinner ──────────────────────────────────────────────────────────

class LoadingSpinner(QLabel):
    """Simple text-based spinner for async operations."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._frames = ["◐", "◓", "◑", "◒"]
        self._index = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(
            f"color: {T.c('accent')}; font-size: 20px; background: transparent;"
        )
        self.setFixedSize(QSize(32, 32))

    def start(self):
        self._timer.start(120)
        self.setVisible(True)

    def stop(self):
        self._timer.stop()
        self.setVisible(False)

    def _tick(self):
        self.setText(self._frames[self._index % len(self._frames)])
        self._index += 1


# ─── Status Dot ───────────────────────────────────────────────────────────────

class StatusDot(QLabel):
    """A small colored dot indicating status."""

    COLORS = {
        "active":  "#b8b8b8",
        "success": "#4caf82",
        "warning": "#f0b429",
        "error":   "#ff2d2d",
        "idle":    "#404040",
    }

    def __init__(self, status: str = "idle", parent=None):
        super().__init__(parent)
        self.setFixedSize(QSize(8, 8))
        self.set_status(status)

    def set_status(self, status: str):
        color = self.COLORS.get(status, "#404040")
        self.setStyleSheet(
            f"background-color: {color}; border-radius: 4px; border: none;"
        )


# ─── Severity Badge ───────────────────────────────────────────────────────────

class SeverityBadge(QLabel):
    """Colored severity badge for findings."""
    def __init__(self, severity: str, parent=None):
        super().__init__(severity.upper(), parent)
        self.setStyleSheet(T.severity_badge_style(severity))
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFixedHeight(20)


# ─── HUD Frame (corner brackets) ─────────────────────────────────────────────

class HudFrame(QFrame):
    """
    A frame with corner bracket decorations — inspired by the OBSERVER logo HUD.
    Used for prominent cards and the login screen.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self._corner_size = 16
        self._corner_thickness = 1
        self._corner_color = QColor(T.c("accent_dim"))

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        pen = QPen(self._corner_color, self._corner_thickness)
        painter.setPen(pen)

        w, h = self.width(), self.height()
        s = self._corner_size

        # Top-left
        painter.drawLine(0, s, 0, 0)
        painter.drawLine(0, 0, s, 0)
        # Top-right
        painter.drawLine(w - s, 0, w, 0)
        painter.drawLine(w, 0, w, s)
        # Bottom-left
        painter.drawLine(0, h - s, 0, h)
        painter.drawLine(0, h, s, h)
        # Bottom-right
        painter.drawLine(w - s, h, w, h)
        painter.drawLine(w, h - s, w, h)

        painter.end()

    def update_corner_color(self, color: str):
        self._corner_color = QColor(color)
        self.update()


# ─── Logo Widget ──────────────────────────────────────────────────────────────

class LogoWidget(QWidget):
    """Renders the OBSERVER wordmark with the eye icon from assets."""

    def __init__(self, size: str = "large", parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Eye icon (from assets)
        self.icon_label = QLabel()
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Robust multi-path resolution for assets
        import os
        import sys
        from pathlib import Path

        possible_paths = [
            Path(__file__).resolve().parent / "assets" / "logo.png",
            Path(getattr(sys, "_MEIPASS", "")) / "ui" / "design" / "assets" / "logo.png",
            Path(sys.executable).parent / "ui" / "design" / "assets" / "logo.png",
            Path(sys.executable).parent / "_internal" / "ui" / "design" / "assets" / "logo.png",
            Path.cwd() / "ui" / "design" / "assets" / "logo.png",
        ]

        logo_file = None
        for p in possible_paths:
            if p and p.exists() and p.is_file() and p.stat().st_size > 0:
                logo_file = p
                break

        icon_size = 80 if size == "large" else 32
        loaded = False

        if logo_file:
            pixmap = QPixmap(str(logo_file))
            if not pixmap.isNull():
                scaled_pixmap = pixmap.scaled(
                    icon_size, icon_size,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
                self.icon_label.setPixmap(scaled_pixmap)
                loaded = True

        if not loaded:
            # Fallback: stylized HUD eye symbol
            self.icon_label.setText("◉")
            eye_size = T.FONT_SIZE_3XL if size == "large" else T.FONT_SIZE_XL
            self.icon_label.setStyleSheet(
                f"color: {T.c('accent')}; font-size: {eye_size}px; background: transparent; font-weight: bold;"
            )

        # Wordmark
        self.wordmark = QLabel("O B S E R V E R")
        word_size = T.FONT_SIZE_XL if size == "large" else T.FONT_SIZE_SM
        self.wordmark.setFont(QFont(T.FONT_UI, word_size, QFont.Weight.Bold))
        self.wordmark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.wordmark.setStyleSheet(
            f"color: {T.c('text_primary')}; letter-spacing: 8px; background: transparent;"
        )

        if size == "large":
            self.tagline = QLabel("SEE EVERYTHING. KNOW EVERYTHING.")
            self.tagline.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.tagline.setStyleSheet(
                f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; "
                f"letter-spacing: 3px; background: transparent;"
            )
            layout.addWidget(self.icon_label)
            layout.addWidget(self.wordmark)
            layout.addWidget(self.tagline)
        else:
            h_layout = QHBoxLayout()
            h_layout.setSpacing(8)
            h_layout.addWidget(self.icon_label)
            h_layout.addWidget(self.wordmark)
            layout.addLayout(h_layout)
