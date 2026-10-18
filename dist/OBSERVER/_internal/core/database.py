"""
OBSERVER — Database Models & Session Manager
SQLAlchemy ORM definitions for all application entities.
"""
import enum
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, ForeignKey,
    Integer, String, Text, create_engine, event
)
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker, Session

from core.config import config


# ─── Base ──────────────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


# ─── Enums ────────────────────────────────────────────────────────────────────

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    PENTESTER = "pentester"


class OtpPurpose(str, enum.Enum):
    REGISTER = "register"
    LOGIN_2FA = "login_2fa"
    PROFILE_CHANGE = "profile_change"


class TargetStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class LogLevel(str, enum.Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


# ─── Models ───────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.PENTESTER)
    is_verified = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_login = Column(DateTime, nullable=True)
    failed_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)

    # Relationships
    otp_codes = relationship("OtpCode", back_populates="user", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="created_by_user", foreign_keys="Scan.created_by")
    reports = relationship("Report", back_populates="created_by_user", foreign_keys="Report.created_by")
    proposed_targets = relationship("Target", back_populates="created_by_user", foreign_keys="Target.created_by")

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email} role={self.role}>"


class OtpCode(Base):
    __tablename__ = "otp_codes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    code_hash = Column(String(255), nullable=False)
    purpose = Column(Enum(OtpPurpose), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    user = relationship("User", back_populates="otp_codes")

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at.replace(tzinfo=timezone.utc)

    @property
    def is_used(self) -> bool:
        return self.used_at is not None

    def __repr__(self) -> str:
        return f"<OtpCode id={self.id} user_id={self.user_id} purpose={self.purpose}>"


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String(2048), nullable=False)
    label = Column(String(255), nullable=True)
    notes = Column(Text, nullable=True)
    status = Column(Enum(TargetStatus), nullable=False, default=TargetStatus.PENDING)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    created_by_user = relationship("User", back_populates="proposed_targets", foreign_keys=[created_by])
    approved_by_user = relationship("User", foreign_keys=[approved_by])
    scans = relationship("Scan", back_populates="target")

    def __repr__(self) -> str:
        return f"<Target id={self.id} url={self.url} status={self.status}>"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    status = Column(Enum(ScanStatus), nullable=False, default=ScanStatus.QUEUED)
    config_json = Column(Text, nullable=True)   # JSON: selected OWASP categories, options
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    target = relationship("Target", back_populates="scans")
    created_by_user = relationship("User", back_populates="scans", foreign_keys=[created_by])
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    logs = relationship("ScanLog", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan")

    def __repr__(self) -> str:
        return f"<Scan id={self.id} status={self.status}>"


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    owasp_category = Column(String(10), nullable=False)   # e.g. "A03"
    owasp_name = Column(String(255), nullable=False)       # e.g. "Injection"
    title = Column(String(512), nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)                 # Technical proof
    request_raw = Column(Text, nullable=True)              # Raw HTTP request
    response_raw = Column(Text, nullable=True)             # Raw HTTP response snippet
    url_affected = Column(String(2048), nullable=True)
    parameter = Column(String(255), nullable=True)
    cwe_id = Column(String(50), nullable=True)             # e.g. "CWE-89"
    remediation = Column(Text, nullable=True)              # Recommended fix
    found_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    alert_sent = Column(Boolean, default=False, nullable=False)  # For critical email alert

    # Relationships
    scan = relationship("Scan", back_populates="findings")

    def __repr__(self) -> str:
        return f"<Finding id={self.id} severity={self.severity} title={self.title[:40]}>"


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String(512), nullable=False)
    file_path = Column(String(1024), nullable=True)        # Path to generated PDF
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    scan = relationship("Scan", back_populates="reports")
    created_by_user = relationship("User", back_populates="reports", foreign_keys=[created_by])

    def __repr__(self) -> str:
        return f"<Report id={self.id} title={self.title[:40]}>"


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    level = Column(Enum(LogLevel), nullable=False, default=LogLevel.INFO)
    message = Column(Text, nullable=False)
    module = Column(String(100), nullable=True)            # Which OWASP module logged this

    # Relationships
    scan = relationship("Scan", back_populates="logs")

    def __repr__(self) -> str:
        return f"<ScanLog id={self.id} level={self.level} msg={self.message[:40]}>"


# ─── Engine & Session ─────────────────────────────────────────────────────────

_engine = None
_SessionLocal = None


def get_engine():
    global _engine
    if _engine is None:
        _engine = create_engine(
            config.DATABASE_URL,
            connect_args={"check_same_thread": False},  # SQLite thread safety
            echo=config.DEBUG,
        )
        # Enable WAL mode for better concurrent read performance
        @event.listens_for(_engine, "connect")
        def set_sqlite_pragma(dbapi_conn, connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA cache_size=-64000")  # 64MB cache
            cursor.close()
    return _engine


def get_session_factory():
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            bind=get_engine(),
            autocommit=False,
            autoflush=False,
        )
    return _SessionLocal


def get_db() -> Session:
    """Return a new database session. Caller is responsible for closing."""
    factory = get_session_factory()
    return factory()


def init_db():
    """Create all tables if they don't exist."""
    engine = get_engine()
    Base.metadata.create_all(engine)


def check_first_run() -> bool:
    """Return True if no admin user exists (first run)."""
    with get_db() as session:
        admin = session.query(User).filter(User.role == UserRole.ADMIN).first()
        return admin is None
