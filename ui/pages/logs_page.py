"""
OBSERVER — Logs Page (Phase 3)
CLI-style log viewer that can be detached as a floating window.
Shows real-time scan logs from the database.
"""
from datetime import datetime, timezone
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QTextEdit, QComboBox, QSizePolicy, QMainWindow, QApplication
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QTextCharFormat, QTextCursor

from core.database import get_db, ScanLog, LogLevel, Scan
from core.rbac import session
from ui.design import theme as T
from ui.design.widgets import PrimaryButton, SecondaryButton, GhostButton, SectionLabel


# ─── Log Text Widget ──────────────────────────────────────────────────────────

class LogTextWidget(QTextEdit):
    """
    Read-only terminal-style log output widget.
    Supports colored log levels.
    """

    LEVEL_COLORS = {
        LogLevel.DEBUG.value:   "#606060",
        LogLevel.INFO.value:    "#b8b8b8",
        LogLevel.WARNING.value: "#f0b429",
        LogLevel.ERROR.value:   "#ff2d2d",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont(T.FONT_MONO, T.FONT_SIZE_SM))
        self.setStyleSheet(
            f"background-color: #030303; color: {T.c('text_secondary')}; "
            f"border: none; padding: 8px;"
        )
        self._max_lines = 2000

    def append_log(self, timestamp: str, level: str, message: str, module: str = ""):
        """Append a colored log line."""
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        # Timestamp
        ts_fmt = QTextCharFormat()
        ts_fmt.setForeground(QColor("#404040"))
        cursor.insertText(timestamp + "  ", ts_fmt)

        # Level
        level_fmt = QTextCharFormat()
        level_fmt.setForeground(QColor(self.LEVEL_COLORS.get(level, "#b8b8b8")))
        level_fmt.setFontWeight(700)
        cursor.insertText(f"[{level.upper():<7}]", level_fmt)

        # Module
        if module:
            mod_fmt = QTextCharFormat()
            mod_fmt.setForeground(QColor("#505050"))
            cursor.insertText(f"  {module:<12}", mod_fmt)

        # Message
        msg_fmt = QTextCharFormat()
        msg_color = self.LEVEL_COLORS.get(level, "#b8b8b8")
        msg_fmt.setForeground(QColor(msg_color))
        cursor.insertText(f"  {message}\n", msg_fmt)

        # Auto-scroll
        scrollbar = self.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

        # Trim if too many lines
        doc = self.document()
        while doc.blockCount() > self._max_lines:
            cursor2 = QTextCursor(doc.firstBlock())
            cursor2.select(QTextCursor.SelectionType.BlockUnderCursor)
            cursor2.deleteChar()

    def add_system_line(self, text: str):
        """Add a dim system separator/info line."""
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = QTextCharFormat()
        fmt.setForeground(QColor("#282828"))
        cursor.insertText(f"{'─' * 80}\n{text}\n{'─' * 80}\n", fmt)
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())


# ─── Detached Log Window ──────────────────────────────────────────────────────

class DetachedLogWindow(QMainWindow):
    """A floating window showing the same log stream."""

    closed = pyqtSignal()

    def __init__(self, log_widget: LogTextWidget, parent=None):
        super().__init__(parent)
        self.setWindowTitle("OBSERVER — Logs (Detached)")
        self.resize(900, 600)
        self.setStyleSheet(f"background: #030303;")

        # Header
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QFrame()
        header.setFixedHeight(40)
        header.setStyleSheet(
            f"background: {T.c('bg_secondary')}; border-bottom: 1px solid {T.c('border')};"
        )
        hl = QHBoxLayout(header)
        hl.setContentsMargins(16, 0, 16, 0)
        title = QLabel("◉  OBSERVER LOGS — DETACHED")
        title.setStyleSheet(
            f"color: {T.c('accent')}; font-size: {T.FONT_SIZE_XS}px; "
            f"letter-spacing: 2px; font-weight: 700; background: transparent;"
        )
        hl.addWidget(title)
        hl.addStretch()

        layout.addWidget(header)
        layout.addWidget(log_widget, 1)
        self.setCentralWidget(container)

    def closeEvent(self, event):
        self.closed.emit()
        super().closeEvent(event)


# ─── Logs Page ────────────────────────────────────────────────────────────────

class LogsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._last_log_id = 0
        self._current_scan_id = None
        self._detached_window = None
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(1500)
        self._poll_timer.timeout.connect(self._poll_logs)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Topbar ──────────────────────────────────────────────────────────
        topbar = QFrame()
        topbar.setFixedHeight(56)
        topbar.setStyleSheet(
            f"background: {T.c('bg_secondary')}; border-bottom: 1px solid {T.c('border')};"
        )
        tb = QHBoxLayout(topbar)
        tb.setContentsMargins(24, 0, 24, 0)
        tb.setSpacing(12)

        title_lbl = QLabel("Logs")
        title_lbl.setFont(QFont(T.FONT_UI, T.FONT_SIZE_LG, QFont.Weight.Bold))
        title_lbl.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")

        # Scan selector
        self.scan_selector = QComboBox()
        self.scan_selector.setMinimumWidth(280)
        self.scan_selector.currentIndexChanged.connect(self._on_scan_changed)

        self.clear_btn = SecondaryButton("Clear")
        self.clear_btn.setFixedHeight(32)
        self.clear_btn.clicked.connect(self._clear_display)

        self.popout_btn = PrimaryButton("⤢ Pop Out")
        self.popout_btn.setFixedHeight(32)
        self.popout_btn.clicked.connect(self._toggle_popout)

        tb.addWidget(title_lbl)
        tb.addStretch()
        tb.addWidget(QLabel("Scan:").findChild(QLabel) or QLabel("Scan:"))
        tb.addWidget(self.scan_selector)
        tb.addWidget(self.clear_btn)
        tb.addWidget(self.popout_btn)
        layout.addWidget(topbar)

        # ── Log display ──────────────────────────────────────────────────────
        self.log_widget = LogTextWidget()
        self.log_widget.add_system_line(
            f"  OBSERVER Log Viewer — Ready  |  Select a scan above to view its logs"
        )
        layout.addWidget(self.log_widget, 1)

        # ── Status bar ───────────────────────────────────────────────────────
        statusbar = QFrame()
        statusbar.setFixedHeight(28)
        statusbar.setStyleSheet(
            f"background: #020202; border-top: 1px solid #1a1a1a;"
        )
        sb = QHBoxLayout(statusbar)
        sb.setContentsMargins(16, 0, 16, 0)
        self.status_text = QLabel("● IDLE")
        self.status_text.setStyleSheet(
            f"color: #303030; font-size: {T.FONT_SIZE_XS}px; "
            f"font-family: {T.FONT_MONO}; letter-spacing: 1px; background: transparent;"
        )
        self.log_count_text = QLabel("0 entries")
        self.log_count_text.setStyleSheet(
            f"color: #303030; font-size: {T.FONT_SIZE_XS}px; background: transparent;"
        )
        sb.addWidget(self.status_text)
        sb.addStretch()
        sb.addWidget(self.log_count_text)
        layout.addWidget(statusbar)

    def on_enter(self):
        self._load_scan_list()
        self._poll_timer.start()

    def _load_scan_list(self):
        """Populate the scan dropdown."""
        db = get_db()
        try:
            q = db.query(Scan)
            if not session.is_admin_user():
                q = q.filter(Scan.created_by == session.user_id)
            scans = q.order_by(Scan.created_at.desc()).limit(50).all()

            self.scan_selector.blockSignals(True)
            self.scan_selector.clear()
            self.scan_selector.addItem("— Select Scan —", None)
            self._scan_id_map = {}
            for s in scans:
                label = f"#{s.id}  [{s.status.value.upper()}]  {s.created_at.strftime('%Y-%m-%d %H:%M')}"
                self.scan_selector.addItem(label, s.id)
                self._scan_id_map[s.id] = s
            self.scan_selector.blockSignals(False)
        finally:
            db.close()

    def _on_scan_changed(self, index: int):
        scan_id = self.scan_selector.currentData()
        if not scan_id:
            self._current_scan_id = None
            return
        self._current_scan_id = scan_id
        self._last_log_id = 0
        self.log_widget.clear()
        self.log_widget.add_system_line(f"  Loading logs for Scan #{scan_id}…")
        self._load_full_logs()

    def _load_full_logs(self):
        if not self._current_scan_id:
            return
        db = get_db()
        try:
            logs = (
                db.query(ScanLog)
                .filter(ScanLog.scan_id == self._current_scan_id)
                .order_by(ScanLog.timestamp.asc())
                .all()
            )
            self.log_widget.clear()
            for log in logs:
                self._append_log_entry(log)
            if logs:
                self._last_log_id = logs[-1].id
            self._update_count()
        finally:
            db.close()

    def _poll_logs(self):
        """Poll for new log entries from the current scan."""
        if not self._current_scan_id:
            return
        db = get_db()
        try:
            new_logs = (
                db.query(ScanLog)
                .filter(
                    ScanLog.scan_id == self._current_scan_id,
                    ScanLog.id > self._last_log_id,
                )
                .order_by(ScanLog.timestamp.asc())
                .all()
            )
            for log in new_logs:
                self._append_log_entry(log)
            if new_logs:
                self._last_log_id = new_logs[-1].id
                self._update_count()

                # Mirror to detached window if open
                if self._detached_window and self._detached_window.isVisible():
                    # Already using same widget if not detached; skip
                    pass
        finally:
            db.close()

    def _append_log_entry(self, log: ScanLog):
        ts = log.timestamp.strftime("%H:%M:%S.%f")[:12] if log.timestamp else "??:??:??"
        self.log_widget.append_log(ts, log.level.value, log.message, log.module or "")

    def _update_count(self):
        count = self.log_widget.document().blockCount()
        self.log_count_text.setText(f"{count} entries")

    def _clear_display(self):
        self.log_widget.clear()
        self.log_widget.add_system_line("  Display cleared — logs preserved in database")
        self._update_count()

    def _toggle_popout(self):
        if self._detached_window and self._detached_window.isVisible():
            self._detached_window.close()
            self._detached_window = None
            self.popout_btn.setText("⤢ Pop Out")
            self.layout().addWidget(self.log_widget)
            return

        # Detach: reparent log widget to floating window
        self._detached_window = DetachedLogWindow(self.log_widget)
        self._detached_window.closed.connect(self._on_window_closed)
        self._detached_window.show()
        self.popout_btn.setText("↩ Re-attach")

    def _on_window_closed(self):
        """When the detached window is closed, re-attach the log widget."""
        if self._detached_window:
            self.layout().addWidget(self.log_widget)
        self._detached_window = None
        self.popout_btn.setText("⤢ Pop Out")

    def closeEvent(self, event):
        self._poll_timer.stop()
        if self._detached_window:
            self._detached_window.close()
        super().closeEvent(event)

# Fix missing label
_lbl = QLabel  # forward ref
