"""
OBSERVER — Main Application Window
Orchestrates the full Qt application lifecycle:
  - First-run detection → setup view
  - Auth flow: login → 2FA → main app
  - Main window with sidebar navigation
  - Theme switching (dark/light)
"""
import sys
import json
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QStackedWidget,
    QWidget, QHBoxLayout, QVBoxLayout, QLabel,
    QFrame, QStatusBar, QSizePolicy, QToolButton,
    QSpacerItem
)
from PyQt6.QtCore import Qt, QSize, pyqtSignal, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QFont, QIcon, QAction

from core.database import init_db, check_first_run, OtpPurpose, get_db, User
from core import auth
from core.rbac import session, Permission
from ui.design import theme as T
from ui.design.theme import Theme, set_theme
from ui.design.widgets import LogoWidget, VSeparator, StatusDot, PrimaryButton


# ─── Sidebar Item ─────────────────────────────────────────────────────────────

class SidebarItem(QToolButton):
    """A single navigation item in the sidebar."""

    def __init__(self, icon_text: str, label: str, page_id: str, parent=None):
        super().__init__(parent)
        self.page_id = page_id
        self._icon_text = icon_text
        self._label = label

        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.setFixedHeight(44)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        # Icon (unicode symbol) + text
        self.setText(f"  {icon_text}   {label}")
        self.setFont(QFont(T.FONT_UI, T.FONT_SIZE_SM))

        self._update_style(False)

    def _update_style(self, active: bool):
        bg = T.c("sidebar_active") if active else "transparent"
        border_left = T.c("accent") if active else "transparent"
        text_color = T.c("text_primary") if active else T.c("text_secondary")

        self.setStyleSheet(f"""
            QToolButton {{
                background-color: {bg};
                color: {text_color};
                border: none;
                border-left: 2px solid {border_left};
                border-radius: 0;
                text-align: left;
                padding: 0 16px;
                font-size: {T.FONT_SIZE_SM}px;
                font-weight: {"600" if active else "400"};
            }}
            QToolButton:hover {{
                background-color: {T.c("sidebar_hover")};
                color: {T.c("text_primary")};
            }}
        """)

    def setChecked(self, checked: bool):
        super().setChecked(checked)
        self._update_style(checked)


# ─── Sidebar ──────────────────────────────────────────────────────────────────

class Sidebar(QFrame):
    """
    Left navigation panel.
    Emits page_changed(page_id) on navigation.
    """
    page_changed = pyqtSignal(str)
    logout_requested = pyqtSignal()

    NAV_ITEMS = [
        ("⌂", "Home", "home"),
        ("⚡", "Operations", "operations"),
        ("📄", "Reports", "reports"),
        ("▤", "Logs", "logs"),
        ("📚", "Library", "library"),
    ]

    BOTTOM_ITEMS = [
        ("⚙", "Settings", "settings"),
        ("◉", "Profile", "profile"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._items: dict[str, SidebarItem] = {}
        self._active_page = "home"
        self._setup_ui()

    def _setup_ui(self):
        self.setFixedWidth(T.SIDEBAR_WIDTH)
        self.setStyleSheet(
            f"background-color: {T.c('sidebar_bg')}; "
            f"border-right: 1px solid {T.c('sidebar_border')};"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Logo area ──────────────────────────────────────────────────────
        logo_area = QFrame()
        logo_area.setFixedHeight(T.TOPBAR_HEIGHT + 16)
        logo_area.setStyleSheet(
            f"background-color: {T.c('sidebar_bg')}; "
            f"border-bottom: 1px solid {T.c('sidebar_border')};"
        )
        logo_layout = QHBoxLayout(logo_area)
        logo_layout.setContentsMargins(16, 0, 16, 0)

        self.logo_widget = LogoWidget(size="small")
        logo_layout.addWidget(self.logo_widget)
        logo_layout.addStretch()

        layout.addWidget(logo_area)
        layout.addSpacing(12)

        # ── Section label ──────────────────────────────────────────────────
        nav_label = QLabel("NAVIGATION")
        nav_label.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; "
            f"letter-spacing: 2px; padding: 0 18px; background: transparent;"
        )
        layout.addWidget(nav_label)
        layout.addSpacing(6)

        # ── Main nav items ─────────────────────────────────────────────────
        for icon, label, page_id in self.NAV_ITEMS:
            item = SidebarItem(icon, label, page_id)
            item.clicked.connect(lambda checked, pid=page_id: self._navigate(pid))
            self._items[page_id] = item
            layout.addWidget(item)

        # ── Admin section (conditionally shown) ────────────────────────────
        self.admin_separator = QFrame()
        self.admin_separator.setFixedHeight(1)
        self.admin_separator.setStyleSheet(
            f"background: {T.c('sidebar_border')}; border: none; margin: 8px 0;"
        )
        self.admin_label = QLabel("ADMINISTRATION")
        self.admin_label.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; "
            f"letter-spacing: 2px; padding: 0 18px; background: transparent;"
        )

        self.admin_item = SidebarItem("👤", "User Management", "admin")
        self.admin_item.clicked.connect(lambda: self._navigate("admin"))
        self._items["admin"] = self.admin_item

        layout.addSpacing(8)
        layout.addWidget(self.admin_separator)
        layout.addSpacing(4)
        layout.addWidget(self.admin_label)
        layout.addSpacing(4)
        layout.addWidget(self.admin_item)

        layout.addStretch()

        # ── Bottom: separator ──────────────────────────────────────────────
        bottom_sep = QFrame()
        bottom_sep.setFixedHeight(1)
        bottom_sep.setStyleSheet(
            f"background: {T.c('sidebar_border')}; border: none;"
        )
        layout.addWidget(bottom_sep)

        # ── Bottom nav ─────────────────────────────────────────────────────
        for icon, label, page_id in self.BOTTOM_ITEMS:
            item = SidebarItem(icon, label, page_id)
            item.clicked.connect(lambda checked, pid=page_id: self._navigate(pid))
            self._items[page_id] = item
            layout.addWidget(item)

        # ── User info footer ────────────────────────────────────────────────
        self.user_footer = QFrame()
        self.user_footer.setFixedHeight(60)
        self.user_footer.setStyleSheet(
            f"background-color: {T.c('bg_elevated')}; "
            f"border-top: 1px solid {T.c('sidebar_border')};"
        )
        footer_layout = QHBoxLayout(self.user_footer)
        footer_layout.setContentsMargins(14, 8, 14, 8)
        footer_layout.setSpacing(10)

        self.status_dot = StatusDot("success")
        self.user_name_label = QLabel("—")
        self.user_name_label.setStyleSheet(
            f"color: {T.c('text_primary')}; font-size: {T.FONT_SIZE_SM}px; "
            f"font-weight: 600; background: transparent;"
        )
        self.user_role_label = QLabel("—")
        self.user_role_label.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; background: transparent;"
        )

        user_text_layout = QVBoxLayout()
        user_text_layout.setSpacing(2)
        user_text_layout.addWidget(self.user_name_label)
        user_text_layout.addWidget(self.user_role_label)

        footer_layout.addWidget(self.status_dot)
        footer_layout.addLayout(user_text_layout)
        footer_layout.addStretch()

        self.logout_btn = QToolButton()
        self.logout_btn.setText("⎋")
        self.logout_btn.setToolTip("Log Out")
        self.logout_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.logout_btn.setStyleSheet(f"""
            QToolButton {{
                background: transparent;
                color: {T.c('text_muted')};
                border: 1px solid {T.c('border')};
                border-radius: 4px;
                font-size: 13px;
                padding: 4px 8px;
            }}
            QToolButton:hover {{
                background: {T.c('severity_critical')}22;
                color: {T.c('severity_critical')};
                border-color: {T.c('severity_critical')};
            }}
        """)
        self.logout_btn.clicked.connect(self.logout_requested.emit)
        footer_layout.addWidget(self.logout_btn)

        layout.addWidget(self.user_footer)

        # Default active
        self.set_active("home")

    def set_active(self, page_id: str):
        """Update visual active state without re-emitting page_changed."""
        for item in self._items.values():
            item.setChecked(False)
        if page_id in self._items:
            self._items[page_id].setChecked(True)
        self._active_page = page_id

    def _navigate(self, page_id: str):
        """User clicked a sidebar item: update visual state and emit signal."""
        self.set_active(page_id)
        self.page_changed.emit(page_id)

    def set_user_info(self, name: str, role: str):
        self.user_name_label.setText(name)
        self.user_role_label.setText(role.upper())
        self.status_dot.set_status("success")

    def show_admin_section(self, visible: bool):
        self.admin_separator.setVisible(visible)
        self.admin_label.setVisible(visible)
        self.admin_item.setVisible(visible)


# ─── Auth Stack ───────────────────────────────────────────────────────────────

class AuthStack(QWidget):
    """Manages the authentication views (setup, login, register, verify)."""
    auth_complete = pyqtSignal()   # Fired when user is fully authenticated

    def __init__(self, parent=None):
        super().__init__(parent)
        self._pending_user_id: int | None = None
        self._pending_purpose = OtpPurpose.LOGIN_2FA
        self._setup_ui()

    def _setup_ui(self):
        from ui.auth.login_view import LoginView
        from ui.auth.register_view import RegisterView
        from ui.auth.verify_view import VerifyView
        from ui.auth.setup_view import SetupView

        self.stack = QStackedWidget(self)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.stack)

        self.setup_view = SetupView()
        self.login_view = LoginView()
        self.register_view = RegisterView()
        self.verify_view = VerifyView()

        self.stack.addWidget(self.setup_view)   # 0
        self.stack.addWidget(self.login_view)   # 1
        self.stack.addWidget(self.register_view)# 2
        self.stack.addWidget(self.verify_view)  # 3

        # Connections
        self.setup_view.setup_success.connect(self._on_setup_success)
        self.login_view.login_success.connect(self._on_login_step1)
        self.login_view.go_to_register.connect(lambda: self.stack.setCurrentIndex(2))
        self.register_view.register_success.connect(self._on_register_success)
        self.register_view.go_to_login.connect(lambda: self.stack.setCurrentIndex(1))
        self.verify_view.verify_success.connect(self._on_verify_success)
        self.verify_view.go_back.connect(self._on_verify_go_back)

    def show_initial(self):
        """Show setup or login based on first-run state."""
        if check_first_run():
            self.stack.setCurrentIndex(0)
        else:
            self.stack.setCurrentIndex(1)

    def _on_setup_success(self, user_id: int):
        """Admin created → go to email verification."""
        self._pending_user_id = user_id
        self._pending_purpose = OtpPurpose.REGISTER
        self.verify_view.configure(user_id, OtpPurpose.REGISTER)
        self.stack.setCurrentIndex(3)

    def _on_login_step1(self, user_id: int, flag: str):
        """Credentials verified → go to 2FA."""
        if flag == "__awaiting_2fa__":
            self._pending_user_id = user_id
            self._pending_purpose = OtpPurpose.LOGIN_2FA
            self.verify_view.configure(user_id, OtpPurpose.LOGIN_2FA)
            self.stack.setCurrentIndex(3)
        else:
            # Fallback (should not happen)
            self._finalize_login(user_id)

    def _on_register_success(self, user_id: int):
        """Registration done → email verification."""
        self._pending_user_id = user_id
        self._pending_purpose = OtpPurpose.REGISTER
        self.verify_view.configure(user_id, OtpPurpose.REGISTER)
        self.stack.setCurrentIndex(3)

    def _on_verify_success(self):
        """OTP verified — what happens next depends on purpose."""
        if self._pending_purpose == OtpPurpose.REGISTER:
            # Registration complete → go to login
            self.stack.setCurrentIndex(1)
        elif self._pending_purpose == OtpPurpose.LOGIN_2FA:
            self._finalize_login(self._pending_user_id)

    def _on_verify_go_back(self):
        """Back from verify → go to login."""
        self.stack.setCurrentIndex(1)

    def _finalize_login(self, user_id: int):
        """Complete login: create session, persist token, signal auth_complete."""
        token = auth.complete_login(user_id)
        db = get_db()
        try:
            user = db.query(User).filter(User.id == user_id).first()
            if user:
                session.set_user(
                    user_id=user.id,
                    email=user.email,
                    name=user.full_name,
                    role=user.role.value,
                    token=token,
                )
        finally:
            db.close()
        # Save token to disk for persistent session (never stores password)
        auth.save_stored_session(token)
        self.auth_complete.emit()


# ─── Main Window ──────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    """
    The primary application window.
    Manages auth stack ↔ main layout switching.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("OBSERVER")
        self.setMinimumSize(1200, 750)
        self.resize(1400, 900)

        # Initialize DB
        init_db()

        self._setup_ui()
        self._start_auth()

    def _setup_ui(self):
        # Central widget with full layout
        self.central = QStackedWidget()
        self.setCentralWidget(self.central)

        # ── Auth stack ─────────────────────────────────────────────────────
        self.auth_stack = AuthStack()
        self.auth_stack.auth_complete.connect(self._on_auth_complete)
        self.central.addWidget(self.auth_stack)   # index 0

        # ── Main app layout ────────────────────────────────────────────────
        self.main_widget = QWidget()
        main_layout = QHBoxLayout(self.main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self.sidebar = Sidebar()
        self.sidebar.page_changed.connect(self._navigate_to)
        main_layout.addWidget(self.sidebar)

        # Content area (pages stacked)
        self.content_area = QStackedWidget()
        self.content_area.setStyleSheet(
            f"background-color: {T.c('bg_primary')};"
        )
        main_layout.addWidget(self.content_area, 1)

# ─── Page Error Widget ────────────────────────────────────────────────────────

class PageErrorWidget(QWidget):
    """Resilient fallback displayed when a specific page fails to load."""

    def __init__(self, page_id: str, error_msg: str, on_retry=None, parent=None):
        super().__init__(parent)
        self.page_id = page_id
        self.error_msg = error_msg
        self.on_retry = on_retry
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setContentsMargins(40, 40, 40, 40)

        card = QFrame()
        card.setProperty("class", "card")
        card.setMaximumWidth(560)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(28, 24, 28, 24)
        card_layout.setSpacing(14)

        title = QLabel(f"⚠  Unable to load {self.page_id.capitalize()} Page")
        title.setFont(QFont(T.FONT_UI, T.FONT_SIZE_LG, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {T.c('severity_critical')}; background: transparent;")
        card_layout.addWidget(title)

        desc = QLabel(
            "An error occurred while initializing this module. "
            "The rest of OBSERVER remains fully functional."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color: {T.c('text_secondary')}; font-size: {T.FONT_SIZE_SM}px; background: transparent;")
        card_layout.addWidget(desc)

        err_box = QLabel(self.error_msg)
        err_box.setWordWrap(True)
        err_box.setFont(QFont(T.FONT_MONO, T.FONT_SIZE_XS))
        err_box.setStyleSheet(
            f"background: {T.c('bg_elevated')}; color: {T.c('severity_high')}; "
            f"border: 1px solid {T.c('border')}; border-radius: {T.RADIUS_SM}px; padding: 10px;"
        )
        card_layout.addWidget(err_box)

        if self.on_retry:
            btn_row = QHBoxLayout()
            btn_row.addStretch()
            retry_btn = PrimaryButton("↻ Retry Loading")
            retry_btn.clicked.connect(self.on_retry)
            btn_row.addWidget(retry_btn)
            card_layout.addLayout(btn_row)

        layout.addWidget(card)


# ─── Main Window ──────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    """
    The primary application window.
    Manages auth stack ↔ main layout switching with on-demand lazy loading.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("OBSERVER")
        self.setMinimumSize(1200, 750)
        self.resize(1400, 900)

        # Page instances cache for lazy loading
        self._page_map: dict[str, QWidget] = {}

        # Initialize DB
        init_db()

        self._setup_ui()
        self._start_auth()

    def _setup_ui(self):
        # Central widget with full layout
        self.central = QStackedWidget()
        self.setCentralWidget(self.central)

        # ── Auth stack ─────────────────────────────────────────────────────
        self.auth_stack = AuthStack()
        self.auth_stack.auth_complete.connect(self._on_auth_complete)
        self.central.addWidget(self.auth_stack)   # index 0

        # ── Main app layout ────────────────────────────────────────────────
        self.main_widget = QWidget()
        main_layout = QHBoxLayout(self.main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self.sidebar = Sidebar()
        self.sidebar.page_changed.connect(self._navigate_to)
        self.sidebar.logout_requested.connect(self.logout)
        main_layout.addWidget(self.sidebar)

        # Content area (pages stacked)
        self.content_area = QStackedWidget()
        self.content_area.setStyleSheet(
            f"background-color: {T.c('bg_primary')};"
        )
        main_layout.addWidget(self.content_area, 1)

        self.central.addWidget(self.main_widget)  # index 1

        # ── Status bar ──────────────────────────────────────────────────────
        self._setup_statusbar()

    def _setup_statusbar(self):
        bar = QStatusBar()
        bar.setFixedHeight(T.STATUSBAR_HEIGHT)
        self.setStatusBar(bar)

        self.status_left = QLabel(" OBSERVER — SYSTEM ACTIVE")
        self.status_left.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; "
            f"letter-spacing: 1px; background: transparent;"
        )
        bar.addWidget(self.status_left)

        bar.addPermanentWidget(QLabel(""))   # Spacer

        from core.config import config
        self.status_right = QLabel(f"v{config.APP_VERSION}  ")
        self.status_right.setStyleSheet(
            f"color: {T.c('text_muted')}; font-size: {T.FONT_SIZE_XS}px; background: transparent;"
        )
        bar.addPermanentWidget(self.status_right)

    def _start_auth(self):
        # Auto-login if persistent session token exists and is valid
        if auth.try_restore_session():
            self._on_auth_complete()
            return

        self.central.setCurrentIndex(0)
        self.auth_stack.show_initial()

    def _on_auth_complete(self):
        """Switch from auth stack to main application."""
        # Setup sidebar immediately
        is_admin = session.is_admin_user()
        self.sidebar.show_admin_section(is_admin)
        self.sidebar.set_user_info(session.user_name, session.role)

        # Show main UI and load Home page immediately
        self.central.setCurrentIndex(1)
        self._navigate_to("home")

    def _load_single_page(self, page_id: str) -> QWidget:
        """Dynamically instantiate a single page on demand."""
        try:
            if page_id == "home":
                from ui.pages.home_page import HomePage
                return HomePage()
            elif page_id == "operations":
                from ui.pages.operations_page import OperationsPage
                return OperationsPage()
            elif page_id == "reports":
                from ui.pages.reports_page import ReportsPage
                return ReportsPage()
            elif page_id == "logs":
                from ui.pages.logs_page import LogsPage
                return LogsPage()
            elif page_id == "library":
                from ui.pages.library_page import LibraryPage
                return LibraryPage()
            elif page_id == "profile":
                from ui.pages.profile_page import ProfilePage
                return ProfilePage()
            elif page_id == "settings":
                from ui.pages.settings_page import SettingsPage
                return SettingsPage()
            elif page_id == "admin":
                from ui.pages.admin_page import AdminPage
                return AdminPage()
            else:
                raise ValueError(f"Unknown page identifier: {page_id}")
        except Exception as e:
            import traceback
            err_details = f"{e}\n\n{traceback.format_exc()}"
            return PageErrorWidget(page_id, err_details, on_retry=lambda: self._retry_load_page(page_id))

    def _retry_load_page(self, page_id: str):
        """Attempt to reload a failed page."""
        if page_id in self._page_map:
            old_widget = self._page_map.pop(page_id)
            self.content_area.removeWidget(old_widget)
            old_widget.deleteLater()
        self._navigate_to(page_id)

    def _navigate_to(self, page_id: str):
        """Navigate to a page with lazy instantiation."""
        # RBAC check for admin page
        if page_id == "admin" and not session.is_admin_user():
            return

        # Lazy load page if not yet in cache
        if page_id not in self._page_map:
            page = self._load_single_page(page_id)
            self._page_map[page_id] = page
            self.content_area.addWidget(page)

        page = self._page_map[page_id]

        # Trigger on_enter hook if available
        if hasattr(page, "on_enter"):
            try:
                page.on_enter()
            except Exception as _oe_exc:
                import logging, traceback
                logging.getLogger("observer.app").error(
                    "on_enter() crashed for page '%s': %s\n%s",
                    page_id, _oe_exc, traceback.format_exc()
                )

        self.content_area.setCurrentWidget(page)
        self.sidebar.set_active(page_id)

    def apply_theme(self, theme: Theme):
        """Switch between dark and light themes and refresh styles."""
        set_theme(theme)
        self.setStyleSheet(T.get_stylesheet())
        for widget in self.findChildren(QWidget):
            widget.setStyleSheet(widget.styleSheet())

    def logout(self):
        """Clear session, remove persistent token from disk, and return to login."""
        auth.clear_stored_session()
        session.clear()
        # Clear cached pages
        while self.content_area.count():
            w = self.content_area.widget(0)
            self.content_area.removeWidget(w)
            w.deleteLater()
        self._page_map.clear()
        self.central.setCurrentIndex(0)
        self.auth_stack.show_initial()

