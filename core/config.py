"""
OBSERVER — Configuration Manager
Loads settings from .env file with validation and defaults.

Data directory strategy:
  Both `python main.py` and `OBSERVER.exe` use the same shared directory:
      C:/Users/<user>/AppData/Local/OBSERVER/
  This guarantees the database, .env, and reports are always identical
  regardless of how the application is launched.
"""
import os
import sys
from pathlib import Path
from dotenv import load_dotenv


# ─── Shared Data Directory ────────────────────────────────────────────────────
# Always resolves to %LOCALAPPDATA%\OBSERVER on Windows (or ~/.observer on Linux/Mac)
_APPDATA = os.environ.get("LOCALAPPDATA") or os.environ.get("HOME", str(Path.home()))
DATA_DIR = Path(_APPDATA) / "OBSERVER"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Reports directory lives inside DATA_DIR
REPORTS_DIR = DATA_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ─── .env Resolution ──────────────────────────────────────────────────────────
# Priority: shared DATA_DIR .env → project root .env (dev) → .exe folder .env
_env_search_paths = [
    DATA_DIR,                                         # Shared: always wins
    Path(__file__).resolve().parent.parent,           # Dev: project root
    Path(sys.executable).parent,                      # Packaged .exe folder
    Path(sys.executable).parent / "_internal",
    Path.cwd(),
]

_loaded = False
_loaded_env_path: Path | None = None
for _d in _env_search_paths:
    _env_file = _d / ".env"
    if _env_file.exists():
        load_dotenv(_env_file, override=True)
        _loaded_env_path = _env_file
        _loaded = True
        break

if not _loaded:
    # Last resort: look for .env.example
    for _d in _env_search_paths:
        _ex = _d / ".env.example"
        if _ex.exists():
            load_dotenv(_ex, override=True)
            _loaded_env_path = _d / ".env"
            break
    load_dotenv()


def _get(key: str, default: str | None = None, required: bool = False) -> str | None:
    val = os.environ.get(key, default)
    if required and not val:
        raise EnvironmentError(
            f"[OBSERVER] Required environment variable '{key}' is not set.\n"
            f"Copy .env.example to .env and fill in your values."
        )
    return val


class Config:
    # ── SMTP ──────────────────────────────────────────────────────────────────
    SMTP_HOST: str = _get("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT: int = int(_get("SMTP_PORT", "587"))
    SMTP_USER: str = _get("SMTP_USER", "")
    SMTP_PASS: str = _get("SMTP_PASS", "")
    SMTP_FROM_NAME: str = _get("SMTP_FROM_NAME", "OBSERVER Security")

    # ── Security ──────────────────────────────────────────────────────────────
    JWT_SECRET: str = _get("JWT_SECRET", "dev-insecure-secret-change-in-production")
    JWT_EXPIRE_HOURS: int = int(_get("JWT_EXPIRE_HOURS", "168"))  # Default: 7 days (persistent desktop session)

    # ── OTP ───────────────────────────────────────────────────────────────────
    OTP_EXPIRE_MINUTES: int = int(_get("OTP_EXPIRE_MINUTES", "5"))
    OTP_LENGTH: int = int(_get("OTP_LENGTH", "6"))

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    MAX_LOGIN_ATTEMPTS: int = int(_get("MAX_LOGIN_ATTEMPTS", "5"))
    LOCKOUT_MINUTES: int = int(_get("LOCKOUT_MINUTES", "15"))

    # ── Database ──────────────────────────────────────────────────────────────
    # Stable and unified database location: %LOCALAPPDATA%/OBSERVER/observer.db.
    # For SQLite, this absolute path is ALWAYS enforced so dev mode and the .exe
    # packaged application always read and write the exact same database.
    # Non-SQLite database URLs (e.g. postgresql://, mysql://) may still be configured.
    _db_url_env: str = _get("DATABASE_URL", "") or ""
    DB_PATH: Path = DATA_DIR / "observer.db"

    if not _db_url_env or _db_url_env.lower().startswith("sqlite:"):
        DATABASE_URL: str = f"sqlite:///{DB_PATH}"
    else:
        DATABASE_URL: str = _db_url_env

    # ── Paths ──────────────────────────────────────────────────────────────────
    DATA_DIR: Path = DATA_DIR
    REPORTS_DIR: Path = REPORTS_DIR
    ENV_FILE: Path = _loaded_env_path or (DATA_DIR / ".env")

    # ── Application ───────────────────────────────────────────────────────────
    APP_ENV: str = _get("APP_ENV", "production")
    DEBUG: bool = _get("DEBUG", "false").lower() == "true"
    APP_VERSION: str = "1.0.0"
    APP_NAME: str = "OBSERVER"

    @classmethod
    def is_smtp_configured(cls) -> bool:
        """Check if SMTP credentials are set."""
        return bool(cls.SMTP_USER and cls.SMTP_PASS)


config = Config()
