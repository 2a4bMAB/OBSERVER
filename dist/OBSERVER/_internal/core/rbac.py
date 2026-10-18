"""
OBSERVER — Role-Based Access Control (RBAC)
Decorators and helpers for enforcing user permissions.
"""
from enum import Enum
from functools import wraps
from typing import Callable, Optional

from core.database import UserRole


class Permission(str, Enum):
    # User management
    MANAGE_USERS = "manage_users"
    # Targets
    APPROVE_TARGETS = "approve_targets"
    PROPOSE_TARGETS = "propose_targets"
    # Scans
    START_SCAN = "start_scan"
    VIEW_OWN_SCANS = "view_own_scans"
    VIEW_ALL_SCANS = "view_all_scans"
    DELETE_SCAN = "delete_scan"           # Admin only; Pentesters may delete their own
    DELETE_OWN_SCAN = "delete_own_scan"
    # Reports
    EXPORT_REPORT = "export_report"
    VIEW_ALL_REPORTS = "view_all_reports"
    # Config
    CONFIGURE_SYSTEM = "configure_system"
    MODIFY_DETECTION_RULES = "modify_detection_rules"


# Mapping of role → set of permissions
_ROLE_PERMISSIONS: dict[UserRole, set[Permission]] = {
    UserRole.ADMIN: {
        Permission.MANAGE_USERS,
        Permission.APPROVE_TARGETS,
        Permission.PROPOSE_TARGETS,
        Permission.START_SCAN,
        Permission.VIEW_OWN_SCANS,
        Permission.VIEW_ALL_SCANS,
        Permission.DELETE_SCAN,
        Permission.DELETE_OWN_SCAN,
        Permission.EXPORT_REPORT,
        Permission.VIEW_ALL_REPORTS,
        Permission.CONFIGURE_SYSTEM,
        Permission.MODIFY_DETECTION_RULES,
    },
    UserRole.PENTESTER: {
        Permission.PROPOSE_TARGETS,
        Permission.START_SCAN,
        Permission.VIEW_OWN_SCANS,
        Permission.DELETE_OWN_SCAN,
        Permission.EXPORT_REPORT,
    },
}


def has_permission(role: str | UserRole, permission: Permission) -> bool:
    """Check if a role has a specific permission."""
    if isinstance(role, str):
        try:
            role = UserRole(role)
        except ValueError:
            return False
    return permission in _ROLE_PERMISSIONS.get(role, set())


def get_permissions(role: str | UserRole) -> set[Permission]:
    """Return all permissions for a given role."""
    if isinstance(role, str):
        try:
            role = UserRole(role)
        except ValueError:
            return set()
    return _ROLE_PERMISSIONS.get(role, set()).copy()


def is_admin(role: str | UserRole) -> bool:
    """Quick check if a role is admin."""
    if isinstance(role, str):
        return role == UserRole.ADMIN.value
    return role == UserRole.ADMIN


# ─── Session Context ───────────────────────────────────────────────────────────

class SessionContext:
    """Holds the current authenticated user's session data in memory."""

    _instance: Optional["SessionContext"] = None

    def __init__(self):
        self.user_id: Optional[int] = None
        self.user_email: Optional[str] = None
        self.user_name: Optional[str] = None
        self.role: Optional[str] = None
        self.token: Optional[str] = None
        self.is_authenticated: bool = False

    @classmethod
    def get(cls) -> "SessionContext":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def set_user(self, user_id: int, email: str, name: str, role: str, token: str):
        self.user_id = user_id
        self.user_email = email
        self.user_name = name
        self.role = role
        self.token = token
        self.is_authenticated = True

    def clear(self):
        self.user_id = None
        self.user_email = None
        self.user_name = None
        self.role = None
        self.token = None
        self.is_authenticated = False

    def can(self, permission: Permission) -> bool:
        if not self.is_authenticated or not self.role:
            return False
        return has_permission(self.role, permission)

    def is_admin_user(self) -> bool:
        return self.role == UserRole.ADMIN.value

    def __repr__(self) -> str:
        return f"<Session user_id={self.user_id} role={self.role} auth={self.is_authenticated}>"


# Singleton accessor
session = SessionContext.get()
