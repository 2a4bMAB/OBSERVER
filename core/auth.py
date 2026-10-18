"""
OBSERVER — Authentication Core
Handles password hashing, JWT session tokens, OTP generation/validation,
and all auth business logic. Email-only 2FA.
"""
import hashlib
import json
import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import bcrypt
import jwt

from core.config import config
from core.database import OtpCode, OtpPurpose, User, UserRole, get_db


# ─── Password Hashing ─────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    """Hash a plaintext password using bcrypt with cost factor 12."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate password strength.
    Returns (is_valid, error_message).
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit."
    if not any(c in string.punctuation for c in password):
        return False, "Password must contain at least one special character."
    return True, ""


# ─── JWT Session Tokens ───────────────────────────────────────────────────────

def create_session_token(user_id: int, role: str) -> str:
    """Create a signed JWT session token for an authenticated user."""
    payload = {
        "sub": str(user_id),
        "role": role,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=config.JWT_EXPIRE_HOURS),
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm="HS256")


def verify_session_token(token: str) -> Optional[dict]:
    """
    Verify and decode a session token.
    Returns the payload dict or None if invalid/expired.
    """
    try:
        payload = jwt.decode(token, config.JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ─── Persistent Session Storage ──────────────────────────────────────────────

SESSION_FILE = config.DATA_DIR / "session.json"


def save_stored_session(token: str) -> None:
    """Save JWT session token to local user AppData (never stores password)."""
    try:
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)
        data = {"token": token}
        temp_file = SESSION_FILE.with_suffix(".tmp")
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(data, f)
        temp_file.replace(SESSION_FILE)
    except Exception:
        pass


def clear_stored_session() -> None:
    """Delete stored session file from disk on logout."""
    try:
        if SESSION_FILE.exists():
            SESSION_FILE.unlink()
    except Exception:
        pass


def try_restore_session() -> bool:
    """
    Check if a saved session exists and is still valid.
    If valid, populate rbac.session and return True.
    If expired/invalid, clean up file and return False.
    """
    if not SESSION_FILE.exists():
        return False

    try:
        with open(SESSION_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        token = data.get("token")
        if not token:
            clear_stored_session()
            return False

        payload = verify_session_token(token)
        if not payload or "sub" not in payload:
            clear_stored_session()
            return False

        user_id = int(payload["sub"])
        db = get_db()
        try:
            user = db.query(User).filter(User.id == user_id, User.is_active.is_(True)).first()
            if not user or not user.is_verified:
                clear_stored_session()
                return False

            from core.rbac import session
            session.set_user(
                user_id=user.id,
                email=user.email,
                name=user.full_name,
                role=user.role.value,
                token=token,
            )
            return True
        finally:
            db.close()
    except Exception:
        clear_stored_session()
        return False


# ─── OTP Generation & Validation ──────────────────────────────────────────────

def generate_otp() -> str:
    """Generate a cryptographically secure numeric OTP."""
    digits = string.digits
    return "".join(secrets.choice(digits) for _ in range(config.OTP_LENGTH))


def hash_otp(code: str) -> str:
    """Hash an OTP code using SHA-256 for safe storage."""
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def create_otp_for_user(user_id: int, purpose: OtpPurpose) -> str:
    """
    Generate an OTP, invalidate previous OTPs of the same purpose,
    store the hash in the DB, and return the plaintext code to send via email.
    """
    db = get_db()
    try:
        # Invalidate any existing unused OTPs of the same purpose for this user
        existing = (
            db.query(OtpCode)
            .filter(
                OtpCode.user_id == user_id,
                OtpCode.purpose == purpose,
                OtpCode.used_at.is_(None),
            )
            .all()
        )
        for otp in existing:
            otp.used_at = datetime.now(timezone.utc)  # Mark as used/invalidated

        # Generate new OTP
        code = generate_otp()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=config.OTP_EXPIRE_MINUTES)

        new_otp = OtpCode(
            user_id=user_id,
            code_hash=hash_otp(code),
            purpose=purpose,
            expires_at=expires_at,
        )
        db.add(new_otp)
        db.commit()
        return code
    finally:
        db.close()


def validate_otp(user_id: int, code: str, purpose: OtpPurpose) -> Tuple[bool, str]:
    """
    Validate an OTP code for a user.
    Returns (is_valid, error_message).
    Marks the OTP as used if valid.
    """
    db = get_db()
    try:
        code_hash = hash_otp(code)
        otp = (
            db.query(OtpCode)
            .filter(
                OtpCode.user_id == user_id,
                OtpCode.code_hash == code_hash,
                OtpCode.purpose == purpose,
                OtpCode.used_at.is_(None),
            )
            .order_by(OtpCode.created_at.desc())
            .first()
        )

        if otp is None:
            return False, "Invalid code. Please check and try again."

        if otp.is_expired:
            return False, f"Code expired. Codes are valid for {config.OTP_EXPIRE_MINUTES} minutes."

        # Mark as used
        otp.used_at = datetime.now(timezone.utc)
        db.commit()
        return True, ""
    finally:
        db.close()


# ─── User Registration & Login ────────────────────────────────────────────────

def register_user(
    email: str, password: str, full_name: str, role: UserRole = UserRole.PENTESTER
) -> Tuple[Optional[User], str]:
    """
    Register a new user.
    Returns (user, error_message). user is None on failure.
    """
    db = get_db()
    try:
        # Check email uniqueness
        existing = db.query(User).filter(User.email == email.lower()).first()
        if existing:
            return None, "An account with this email already exists."

        # Validate password strength
        valid, msg = validate_password_strength(password)
        if not valid:
            return None, msg

        user = User(
            email=email.lower().strip(),
            password_hash=hash_password(password),
            full_name=full_name.strip(),
            role=role,
            is_verified=False,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user, ""
    except Exception as e:
        db.rollback()
        return None, f"Registration failed: {str(e)}"
    finally:
        db.close()


def authenticate_user(email: str, password: str) -> Tuple[Optional[User], str]:
    """
    Validate email + password credentials.
    Handles rate limiting / lockout.
    Returns (user, error_message). user is None on failure.
    """
    db = get_db()
    try:
        user = db.query(User).filter(User.email == email.lower().strip()).first()

        if user is None:
            # Don't reveal whether email exists
            return None, "Invalid email or password."

        # Check if account is locked
        if user.locked_until:
            locked_until_aware = user.locked_until.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) < locked_until_aware:
                remaining = int((locked_until_aware - datetime.now(timezone.utc)).total_seconds() / 60) + 1
                return None, f"Account temporarily locked. Try again in {remaining} minute(s)."
            else:
                # Lockout expired — reset
                user.failed_attempts = 0
                user.locked_until = None

        if not user.is_active:
            return None, "This account has been deactivated."

        if not user.is_verified:
            return None, "Please verify your email before logging in."

        # Verify password
        if not verify_password(password, user.password_hash):
            user.failed_attempts += 1
            if user.failed_attempts >= config.MAX_LOGIN_ATTEMPTS:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=config.LOCKOUT_MINUTES)
                db.commit()
                return None, (
                    f"Too many failed attempts. Account locked for {config.LOCKOUT_MINUTES} minutes."
                )
            remaining_attempts = config.MAX_LOGIN_ATTEMPTS - user.failed_attempts
            db.commit()
            return None, f"Invalid email or password. {remaining_attempts} attempt(s) remaining."

        # Successful credential check — reset failed attempts
        user.failed_attempts = 0
        user.locked_until = None
        db.commit()
        db.refresh(user)
        return user, ""
    finally:
        db.close()


def complete_login(user_id: int) -> str:
    """
    Called after successful 2FA. Updates last_login and returns session token.
    """
    db = get_db()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError("User not found")
        user.last_login = datetime.now(timezone.utc)
        db.commit()
        return create_session_token(user.id, user.role.value)
    finally:
        db.close()


def verify_account(user_id: int) -> bool:
    """Mark user account as verified after email OTP confirmation."""
    db = get_db()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return False
        user.is_verified = True
        db.commit()
        return True
    finally:
        db.close()


def get_user_by_id(user_id: int) -> Optional[User]:
    """Fetch a user by ID. Returns a detached instance."""
    db = get_db()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            db.expunge(user)
        return user
    finally:
        db.close()


def update_user_password(user_id: int, new_password: str) -> Tuple[bool, str]:
    """Update user password after validation."""
    valid, msg = validate_password_strength(new_password)
    if not valid:
        return False, msg
    db = get_db()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return False, "User not found."
        user.password_hash = hash_password(new_password)
        db.commit()
        return True, ""
    finally:
        db.close()


def update_user_profile(user_id: int, full_name: str, email: str) -> Tuple[bool, str]:
    """Update user profile after revalidation."""
    db = get_db()
    try:
        # Check email uniqueness if changing
        existing = db.query(User).filter(
            User.email == email.lower(),
            User.id != user_id
        ).first()
        if existing:
            return False, "This email address is already in use."

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return False, "User not found."
        user.full_name = full_name.strip()
        user.email = email.lower().strip()
        db.commit()
        return True, ""
    finally:
        db.close()
