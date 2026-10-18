"""
OBSERVER — Design System / Theme
Central design tokens, color palettes, fonts, and Qt StyleSheets.
Based on the OBSERVER logo: black, silver/grey, white.
Supports Dark (default) and Light themes.
"""
from enum import Enum
from PyQt6.QtGui import QColor, QFont, QPalette
from PyQt6.QtCore import Qt


# ─── Theme Enum ───────────────────────────────────────────────────────────────

class Theme(str, Enum):
    DARK = "dark"
    LIGHT = "light"


# ─── Color Tokens ─────────────────────────────────────────────────────────────

DARK_PALETTE = {
    # Backgrounds
    "bg_primary":       "#080808",
    "bg_secondary":     "#101010",
    "bg_card":          "#161616",
    "bg_elevated":      "#1e1e1e",
    "bg_hover":         "#252525",
    "bg_input":         "#0d0d0d",

    # Borders
    "border":           "#242424",
    "border_focus":     "#484848",
    "border_subtle":    "#1a1a1a",

    # Accent — silver/metallic
    "accent":           "#b8b8b8",
    "accent_dim":       "#787878",
    "accent_bright":    "#e8e8e8",
    "accent_glow":      "#ffffff22",

    # Text
    "text_primary":     "#f0f0f0",
    "text_secondary":   "#909090",
    "text_muted":       "#505050",
    "text_disabled":    "#383838",
    "text_inverse":     "#080808",

    # Severity colors
    "severity_critical":"#ff2d2d",
    "severity_high":    "#ff6b35",
    "severity_medium":  "#f0b429",
    "severity_low":     "#4caf82",
    "severity_info":    "#5b9bd5",

    # Status
    "status_active":    "#b8b8b8",
    "status_success":   "#4caf82",
    "status_warning":   "#f0b429",
    "status_error":     "#ff2d2d",

    # Scrollbar
    "scrollbar_bg":     "#101010",
    "scrollbar_handle": "#2e2e2e",

    # Sidebar
    "sidebar_bg":       "#050505",
    "sidebar_border":   "#1a1a1a",
    "sidebar_active":   "#161616",
    "sidebar_hover":    "#111111",
}

LIGHT_PALETTE = {
    # Backgrounds
    "bg_primary":       "#f4f4f4",
    "bg_secondary":     "#ebebeb",
    "bg_card":          "#ffffff",
    "bg_elevated":      "#f9f9f9",
    "bg_hover":         "#e5e5e5",
    "bg_input":         "#ffffff",

    # Borders
    "border":           "#d4d4d4",
    "border_focus":     "#888888",
    "border_subtle":    "#e0e0e0",

    # Accent
    "accent":           "#2e2e2e",
    "accent_dim":       "#666666",
    "accent_bright":    "#000000",
    "accent_glow":      "#00000011",

    # Text
    "text_primary":     "#0a0a0a",
    "text_secondary":   "#5a5a5a",
    "text_muted":       "#999999",
    "text_disabled":    "#c0c0c0",
    "text_inverse":     "#f4f4f4",

    # Severity
    "severity_critical":"#cc0000",
    "severity_high":    "#cc4400",
    "severity_medium":  "#aa7700",
    "severity_low":     "#2e7d32",
    "severity_info":    "#1565c0",

    # Status
    "status_active":    "#2e2e2e",
    "status_success":   "#2e7d32",
    "status_warning":   "#aa7700",
    "status_error":     "#cc0000",

    # Scrollbar
    "scrollbar_bg":     "#ebebeb",
    "scrollbar_handle": "#c0c0c0",

    # Sidebar
    "sidebar_bg":       "#ffffff",
    "sidebar_border":   "#e0e0e0",
    "sidebar_active":   "#f0f0f0",
    "sidebar_hover":    "#f7f7f7",
}


# ─── Active Theme State ───────────────────────────────────────────────────────

_current_theme: Theme = Theme.DARK
_current_palette: dict = DARK_PALETTE


def set_theme(theme: Theme):
    global _current_theme, _current_palette
    _current_theme = theme
    _current_palette = DARK_PALETTE if theme == Theme.DARK else LIGHT_PALETTE


def get_theme() -> Theme:
    return _current_theme


def c(token: str) -> str:
    """Get a color value by token name."""
    return _current_palette.get(token, "#ff00ff")  # Magenta = missing token


def is_dark() -> bool:
    return _current_theme == Theme.DARK


# ─── Typography ───────────────────────────────────────────────────────────────

FONT_UI = "Segoe UI"           # Windows native, clean and professional
FONT_MONO = "Consolas"         # Monospace for logs and code
FONT_TITLE = "Segoe UI"        # Titles / headings

FONT_SIZE_XS = 9
FONT_SIZE_SM = 11
FONT_SIZE_BASE = 12
FONT_SIZE_MD = 13
FONT_SIZE_LG = 15
FONT_SIZE_XL = 18
FONT_SIZE_2XL = 24
FONT_SIZE_3XL = 32


def font(size: int = FONT_SIZE_BASE, bold: bool = False, mono: bool = False) -> QFont:
    f = QFont(FONT_MONO if mono else FONT_UI, size)
    f.setBold(bold)
    return f


def font_title(size: int = FONT_SIZE_LG) -> QFont:
    f = QFont(FONT_TITLE, size)
    f.setBold(True)
    f.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 1.5)
    return f


# ─── Spacing & Sizing ─────────────────────────────────────────────────────────

RADIUS_SM = 3
RADIUS_MD = 4
RADIUS_LG = 6

SIDEBAR_WIDTH = 220
SIDEBAR_COLLAPSED_WIDTH = 60
TOPBAR_HEIGHT = 48
STATUSBAR_HEIGHT = 28


# ─── Master Stylesheet ────────────────────────────────────────────────────────

def get_stylesheet() -> str:
    p = _current_palette
    is_d = is_dark()

    return f"""
    /* ── Global ────────────────────────────────────────────────────────── */
    QWidget {{
        background-color: {p['bg_primary']};
        color: {p['text_primary']};
        font-family: '{FONT_UI}';
        font-size: {FONT_SIZE_BASE}px;
        selection-background-color: {p['accent_dim']};
        selection-color: {p['text_primary']};
    }}

    /* ── Main Window ────────────────────────────────────────────────────── */
    QMainWindow {{
        background-color: {p['bg_primary']};
    }}
    QMainWindow::separator {{
        background: {p['border']};
        width: 1px;
        height: 1px;
    }}

    /* ── Scroll Bars ────────────────────────────────────────────────────── */
    QScrollBar:vertical {{
        background: {p['scrollbar_bg']};
        width: 6px;
        margin: 0;
        border: none;
    }}
    QScrollBar::handle:vertical {{
        background: {p['scrollbar_handle']};
        border-radius: 3px;
        min-height: 24px;
    }}
    QScrollBar::handle:vertical:hover {{
        background: {p['accent_dim']};
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0;
    }}
    QScrollBar:horizontal {{
        background: {p['scrollbar_bg']};
        height: 6px;
        margin: 0;
        border: none;
    }}
    QScrollBar::handle:horizontal {{
        background: {p['scrollbar_handle']};
        border-radius: 3px;
        min-width: 24px;
    }}
    QScrollBar::handle:horizontal:hover {{
        background: {p['accent_dim']};
    }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
        width: 0;
    }}

    /* ── Labels ─────────────────────────────────────────────────────────── */
    QLabel {{
        background: transparent;
        color: {p['text_primary']};
    }}
    QLabel[class="muted"] {{
        color: {p['text_muted']};
        font-size: {FONT_SIZE_SM}px;
    }}
    QLabel[class="secondary"] {{
        color: {p['text_secondary']};
    }}
    QLabel[class="title"] {{
        color: {p['text_primary']};
        font-size: {FONT_SIZE_XL}px;
        font-weight: 600;
    }}
    QLabel[class="section-title"] {{
        color: {p['text_secondary']};
        font-size: {FONT_SIZE_SM}px;
        font-weight: 600;
        letter-spacing: 2px;
    }}
    QLabel[class="status-badge"] {{
        font-size: {FONT_SIZE_XS}px;
        font-weight: 600;
        letter-spacing: 1.5px;
        padding: 2px 8px;
        border-radius: {RADIUS_SM}px;
    }}

    /* ── Line Edits / Inputs ─────────────────────────────────────────────── */
    QLineEdit {{
        background-color: {p['bg_input']};
        color: {p['text_primary']};
        border: 1px solid {p['border']};
        border-radius: {RADIUS_MD}px;
        padding: 9px 12px;
        font-size: {FONT_SIZE_BASE}px;
        selection-background-color: {p['accent_dim']};
    }}
    QLineEdit:focus {{
        border-color: {p['border_focus']};
        outline: none;
    }}
    QLineEdit:disabled {{
        color: {p['text_disabled']};
        background-color: {p['bg_secondary']};
    }}
    QLineEdit[class="error"] {{
        border-color: {p['severity_critical']};
    }}
    QLineEdit[class="otp-input"] {{
        font-size: {FONT_SIZE_2XL}px;
        font-family: '{FONT_MONO}';
        letter-spacing: 8px;
        text-align: center;
        padding: 12px 16px;
        font-weight: 700;
    }}

    /* ── Push Buttons ────────────────────────────────────────────────────── */
    QPushButton {{
        background-color: {p['accent']};
        color: {p['text_inverse']};
        border: none;
        border-radius: {RADIUS_MD}px;
        padding: 10px 20px;
        font-size: {FONT_SIZE_BASE}px;
        font-weight: 600;
        letter-spacing: 0.5px;
    }}
    QPushButton:hover {{
        background-color: {p['accent_bright']};
    }}
    QPushButton:pressed {{
        background-color: {p['accent_dim']};
    }}
    QPushButton:disabled {{
        background-color: {p['bg_elevated']};
        color: {p['text_disabled']};
    }}
    QPushButton[class="secondary"] {{
        background-color: transparent;
        color: {p['text_secondary']};
        border: 1px solid {p['border']};
    }}
    QPushButton[class="secondary"]:hover {{
        background-color: {p['bg_hover']};
        color: {p['text_primary']};
        border-color: {p['border_focus']};
    }}
    QPushButton[class="ghost"] {{
        background-color: transparent;
        color: {p['text_secondary']};
        border: none;
        padding: 6px 10px;
    }}
    QPushButton[class="ghost"]:hover {{
        color: {p['text_primary']};
        background-color: {p['bg_hover']};
    }}
    QPushButton[class="danger"] {{
        background-color: transparent;
        color: {p['severity_critical']};
        border: 1px solid {p['severity_critical']}55;
    }}
    QPushButton[class="danger"]:hover {{
        background-color: {p['severity_critical']}22;
        border-color: {p['severity_critical']};
    }}

    /* ── Tool Buttons ────────────────────────────────────────────────────── */
    QToolButton {{
        background-color: transparent;
        color: {p['text_secondary']};
        border: none;
        border-radius: {RADIUS_MD}px;
        padding: 6px;
    }}
    QToolButton:hover {{
        background-color: {p['bg_hover']};
        color: {p['text_primary']};
    }}
    QToolButton:checked {{
        background-color: {p['bg_elevated']};
        color: {p['accent']};
    }}

    /* ── Frames / Cards ──────────────────────────────────────────────────── */
    QFrame[class="card"] {{
        background-color: {p['bg_card']};
        border: 1px solid {p['border']};
        border-radius: {RADIUS_LG}px;
    }}
    QFrame[class="card-elevated"] {{
        background-color: {p['bg_elevated']};
        border: 1px solid {p['border']};
        border-radius: {RADIUS_LG}px;
    }}
    QFrame[class="separator"] {{
        background-color: {p['border']};
        border: none;
        max-height: 1px;
    }}

    /* ── Combo Boxes ─────────────────────────────────────────────────────── */
    QComboBox {{
        background-color: {p['bg_input']};
        color: {p['text_primary']};
        border: 1px solid {p['border']};
        border-radius: {RADIUS_MD}px;
        padding: 8px 12px;
        font-size: {FONT_SIZE_BASE}px;
    }}
    QComboBox:focus {{
        border-color: {p['border_focus']};
    }}
    QComboBox::drop-down {{
        border: none;
        width: 24px;
    }}
    QComboBox::down-arrow {{
        width: 10px;
        height: 10px;
    }}
    QComboBox QAbstractItemView {{
        background-color: {p['bg_elevated']};
        border: 1px solid {p['border']};
        color: {p['text_primary']};
        selection-background-color: {p['bg_hover']};
        outline: none;
    }}

    /* ── Check Boxes ─────────────────────────────────────────────────────── */
    QCheckBox {{
        color: {p['text_secondary']};
        font-size: {FONT_SIZE_SM}px;
        spacing: 8px;
    }}
    QCheckBox::indicator {{
        width: 16px;
        height: 16px;
        border: 1px solid {p['border']};
        border-radius: {RADIUS_SM}px;
        background: {p['bg_input']};
    }}
    QCheckBox::indicator:checked {{
        background: {p['accent']};
        border-color: {p['accent']};
    }}
    QCheckBox::indicator:hover {{
        border-color: {p['border_focus']};
    }}

    /* ── Table Views ─────────────────────────────────────────────────────── */
    QTableView, QTreeView, QListView {{
        background-color: {p['bg_secondary']};
        alternate-background-color: {p['bg_card']};
        border: 1px solid {p['border']};
        border-radius: {RADIUS_MD}px;
        gridline-color: {p['border_subtle']};
        color: {p['text_primary']};
        selection-background-color: {p['bg_hover']};
        selection-color: {p['text_primary']};
        outline: none;
    }}
    QTableView::item, QTreeView::item, QListView::item {{
        padding: 6px 10px;
        border: none;
    }}
    QHeaderView {{
        background-color: {p['bg_primary']};
    }}
    QHeaderView::section {{
        background-color: {p['bg_primary']};
        color: {p['text_muted']};
        border: none;
        border-bottom: 1px solid {p['border']};
        padding: 8px 10px;
        font-size: {FONT_SIZE_XS}px;
        font-weight: 600;
        letter-spacing: 1.5px;
        text-transform: uppercase;
    }}

    /* ── Text Edit (Logs) ────────────────────────────────────────────────── */
    QTextEdit, QPlainTextEdit {{
        background-color: {p['bg_input']};
        color: {p['text_primary']};
        border: 1px solid {p['border']};
        border-radius: {RADIUS_MD}px;
        padding: 8px;
        font-family: '{FONT_MONO}';
        font-size: {FONT_SIZE_SM}px;
        selection-background-color: {p['accent_dim']};
    }}

    /* ── Status Bar ──────────────────────────────────────────────────────── */
    QStatusBar {{
        background-color: {p['bg_secondary']};
        color: {p['text_muted']};
        font-size: {FONT_SIZE_XS}px;
        border-top: 1px solid {p['border']};
        letter-spacing: 0.5px;
    }}
    QStatusBar::item {{
        border: none;
    }}

    /* ── Menu Bar ────────────────────────────────────────────────────────── */
    QMenuBar {{
        background-color: {p['bg_secondary']};
        color: {p['text_secondary']};
        border-bottom: 1px solid {p['border']};
        padding: 2px;
    }}
    QMenuBar::item {{
        padding: 4px 10px;
        background: transparent;
    }}
    QMenuBar::item:selected {{
        background-color: {p['bg_hover']};
        color: {p['text_primary']};
    }}
    QMenu {{
        background-color: {p['bg_elevated']};
        color: {p['text_primary']};
        border: 1px solid {p['border']};
        border-radius: {RADIUS_MD}px;
        padding: 4px;
    }}
    QMenu::item {{
        padding: 7px 20px;
        border-radius: {RADIUS_SM}px;
    }}
    QMenu::item:selected {{
        background-color: {p['bg_hover']};
    }}
    QMenu::separator {{
        height: 1px;
        background: {p['border']};
        margin: 4px 8px;
    }}

    /* ── Tooltips ────────────────────────────────────────────────────────── */
    QToolTip {{
        background-color: {p['bg_elevated']};
        color: {p['text_primary']};
        border: 1px solid {p['border']};
        border-radius: {RADIUS_SM}px;
        padding: 5px 10px;
        font-size: {FONT_SIZE_SM}px;
    }}

    /* ── Progress Bar ────────────────────────────────────────────────────── */
    QProgressBar {{
        background-color: {p['bg_elevated']};
        border: 1px solid {p['border']};
        border-radius: {RADIUS_SM}px;
        height: 6px;
        text-align: center;
        color: transparent;
    }}
    QProgressBar::chunk {{
        background-color: {p['accent']};
        border-radius: {RADIUS_SM}px;
    }}

    /* ── Tab Widget ──────────────────────────────────────────────────────── */
    QTabWidget::pane {{
        border: 1px solid {p['border']};
        background-color: {p['bg_card']};
        border-radius: {RADIUS_MD}px;
    }}
    QTabBar::tab {{
        background: transparent;
        color: {p['text_muted']};
        padding: 8px 16px;
        border: none;
        border-bottom: 2px solid transparent;
        font-size: {FONT_SIZE_SM}px;
        letter-spacing: 0.5px;
    }}
    QTabBar::tab:selected {{
        color: {p['text_primary']};
        border-bottom-color: {p['accent']};
    }}
    QTabBar::tab:hover {{
        color: {p['text_secondary']};
    }}

    /* ── Spin Box ────────────────────────────────────────────────────────── */
    QSpinBox, QDoubleSpinBox {{
        background-color: {p['bg_input']};
        color: {p['text_primary']};
        border: 1px solid {p['border']};
        border-radius: {RADIUS_MD}px;
        padding: 8px 10px;
    }}
    QSpinBox:focus, QDoubleSpinBox:focus {{
        border-color: {p['border_focus']};
    }}

    /* ── Splitter ────────────────────────────────────────────────────────── */
    QSplitter::handle {{
        background-color: {p['border']};
    }}
    QSplitter::handle:horizontal {{
        width: 1px;
    }}
    QSplitter::handle:vertical {{
        height: 1px;
    }}

    /* ── Dialog ──────────────────────────────────────────────────────────── */
    QDialog {{
        background-color: {p['bg_primary']};
    }}

    /* ── Group Box ───────────────────────────────────────────────────────── */
    QGroupBox {{
        border: 1px solid {p['border']};
        border-radius: {RADIUS_MD}px;
        margin-top: 12px;
        padding-top: 12px;
        color: {p['text_secondary']};
        font-size: {FONT_SIZE_SM}px;
        font-weight: 600;
        letter-spacing: 1px;
    }}
    QGroupBox::title {{
        subcontrol-origin: margin;
        left: 12px;
        padding: 0 6px;
    }}
    """


# ─── Severity Badge Colors ─────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": ("#ff2d2d", "#ff2d2d22"),
    "high":     ("#ff6b35", "#ff6b3522"),
    "medium":   ("#f0b429", "#f0b42922"),
    "low":      ("#4caf82", "#4caf8222"),
    "info":     ("#5b9bd5", "#5b9bd522"),
}


def severity_badge_style(severity: str) -> str:
    """Return stylesheet for a severity badge label."""
    sev = severity.lower()
    fg, bg = SEVERITY_COLORS.get(sev, ("#909090", "#90909022"))
    return (
        f"color: {fg}; background-color: {bg}; "
        f"border: 1px solid {fg}44; border-radius: {RADIUS_SM}px; "
        f"padding: 2px 8px; font-size: {FONT_SIZE_XS}px; font-weight: 700; "
        f"letter-spacing: 1.5px;"
    )
