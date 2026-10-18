"""
OBSERVER — Placeholder pages for Phase 2
Full implementations come in Phase 3.
"""
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QHBoxLayout
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from ui.design import theme as T


def _placeholder_page(icon: str, title: str, description: str) -> QWidget:
    widget = QWidget()
    widget.setStyleSheet(f"background: {T.c('bg_primary')};")
    layout = QVBoxLayout(widget)
    layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
    layout.setSpacing(12)

    icon_lbl = QLabel(icon)
    icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    icon_lbl.setStyleSheet(f"color: {T.c('text_muted')}; font-size: 48px; background: transparent;")

    title_lbl = QLabel(title)
    title_lbl.setFont(QFont(T.FONT_UI, T.FONT_SIZE_XL, QFont.Weight.Bold))
    title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    title_lbl.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")

    desc_lbl = QLabel(description)
    desc_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    desc_lbl.setStyleSheet(f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;")
    desc_lbl.setWordWrap(True)

    phase_lbl = QLabel("— Coming in Phase 3 —")
    phase_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    phase_lbl.setStyleSheet(
        f"color: {T.c('accent_dim')}; font-size: {T.FONT_SIZE_XS}px; "
        f"letter-spacing: 2px; background: transparent;"
    )

    layout.addWidget(icon_lbl)
    layout.addWidget(title_lbl)
    layout.addWidget(desc_lbl)
    layout.addSpacing(16)
    layout.addWidget(phase_lbl)

    return widget


class OperationsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        w = _placeholder_page(
            "⚡", "Operations",
            "Launch vulnerability scans, monitor progress in real time,\n"
            "and generate reports from scan results."
        )
        QVBoxLayout(self).addWidget(w)

    def on_enter(self): pass


class ReportsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        w = _placeholder_page(
            "📄", "Reports",
            "View, download, and manage all generated PDF audit reports."
        )
        QVBoxLayout(self).addWidget(w)

    def on_enter(self): pass


class LogsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        w = _placeholder_page(
            "▤", "Logs",
            "Real-time CLI-style log viewer. Can be detached as a floating window."
        )
        QVBoxLayout(self).addWidget(w)

    def on_enter(self): pass


class LibraryPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        w = _placeholder_page(
            "📚", "Library",
            "Reference documentation for all 10 OWASP Top 10 categories\n"
            "with detection methods used by OBSERVER."
        )
        QVBoxLayout(self).addWidget(w)

    def on_enter(self): pass


class AdminPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        w = _placeholder_page(
            "👤", "User Management",
            "Create, manage, and deactivate user accounts.\n"
            "Approve or reject scan targets."
        )
        QVBoxLayout(self).addWidget(w)

    def on_enter(self): pass
