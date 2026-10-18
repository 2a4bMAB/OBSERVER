"""
OBSERVER — Email Mailer (SMTP)
Handles sending OTP codes and alert emails via Gmail SMTP.
Email-only 2FA implementation.
"""
import smtplib
import ssl
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Tuple

from core.config import config


# ─── Email Templates ──────────────────────────────────────────────────────────

_HTML_BASE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{subject}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: #0a0a0a; font-family: 'Segoe UI', Arial, sans-serif; padding: 40px 20px; }}
    .container {{ max-width: 520px; margin: 0 auto; background: #111; border: 1px solid #2a2a2a; border-radius: 4px; overflow: hidden; }}
    .header {{ background: #000; padding: 32px; text-align: center; border-bottom: 1px solid #2a2a2a; }}
    .logo-text {{ font-size: 28px; font-weight: 700; letter-spacing: 8px; color: #fff; font-family: 'Courier New', monospace; }}
    .logo-sub {{ font-size: 10px; color: #555; letter-spacing: 3px; margin-top: 6px; }}
    .body {{ padding: 36px 32px; }}
    .title {{ font-size: 18px; font-weight: 600; color: #e0e0e0; margin-bottom: 12px; }}
    .text {{ font-size: 14px; color: #888; line-height: 1.7; margin-bottom: 24px; }}
    .otp-box {{ background: #000; border: 1px solid #333; border-radius: 4px; padding: 24px; text-align: center; margin: 24px 0; }}
    .otp-code {{ font-size: 42px; font-weight: 700; letter-spacing: 12px; color: #c0c0c0; font-family: 'Courier New', monospace; }}
    .otp-expire {{ font-size: 12px; color: #555; margin-top: 12px; letter-spacing: 1px; }}
    .warning {{ font-size: 12px; color: #666; margin-top: 20px; padding: 12px; background: #0d0d0d; border-left: 2px solid #333; }}
    .footer {{ padding: 20px 32px; background: #0d0d0d; border-top: 1px solid #1a1a1a; }}
    .footer-text {{ font-size: 11px; color: #444; text-align: center; letter-spacing: 0.5px; }}
    {extra_style}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="logo-text">O B S E R V E R</div>
      <div class="logo-sub">SEE EVERYTHING. KNOW EVERYTHING.</div>
    </div>
    <div class="body">
      {body_content}
    </div>
    <div class="footer">
      <div class="footer-text">
        This message was sent by OBSERVER Security Platform &nbsp;|&nbsp; Do not reply to this email.<br>
        If you did not request this, please ignore this message and secure your account.
      </div>
    </div>
  </div>
</body>
</html>
"""


def _otp_html(title: str, intro: str, code: str, purpose_note: str) -> str:
    body = f"""
      <div class="title">{title}</div>
      <div class="text">{intro}</div>
      <div class="otp-box">
        <div class="otp-code">{code}</div>
        <div class="otp-expire">EXPIRES IN {config.OTP_EXPIRE_MINUTES} MINUTES</div>
      </div>
      <div class="warning">
        ⚠ {purpose_note} Never share this code with anyone.
        OBSERVER will never ask for your code by phone or chat.
      </div>
    """
    return _HTML_BASE.format(subject=title, body_content=body, extra_style="")


def _alert_html(target_url: str, severity: str, findings_summary: str, timestamp: str) -> str:
    severity_color = {
        "CRITICAL": "#ff2d2d",
        "HIGH": "#ff6b35",
    }.get(severity.upper(), "#c0c0c0")

    body = f"""
      <div class="title" style="color:{severity_color};">🔴 {severity} VULNERABILITY DETECTED</div>
      <div class="text">
        OBSERVER has detected a <strong style="color:{severity_color};">{severity}</strong> severity
        vulnerability during an active scan. Immediate review is recommended.
      </div>
      <div class="otp-box" style="text-align:left;">
        <div style="font-size:11px;color:#555;letter-spacing:2px;margin-bottom:8px;">SCAN TARGET</div>
        <div style="font-size:14px;color:#c0c0c0;font-family:'Courier New',monospace;word-break:break-all;">{target_url}</div>
        <div style="font-size:11px;color:#555;letter-spacing:2px;margin-top:16px;margin-bottom:8px;">FINDING SUMMARY</div>
        <div style="font-size:13px;color:#aaa;font-family:'Courier New',monospace;">{findings_summary}</div>
        <div style="font-size:11px;color:#555;letter-spacing:2px;margin-top:16px;margin-bottom:4px;">DETECTED AT</div>
        <div style="font-size:12px;color:#777;">{timestamp}</div>
      </div>
      <div class="warning">
        Review the full details in OBSERVER → Operations → Current Scan.
        A full report will be available upon scan completion.
      </div>
    """
    return _HTML_BASE.format(
        subject=f"[OBSERVER ALERT] {severity} Vulnerability Detected",
        body_content=body,
        extra_style=f".otp-box {{ border-color: {severity_color}33; }}"
    )


# ─── SMTP Send ────────────────────────────────────────────────────────────────

def _send_email(to_email: str, subject: str, html_body: str) -> Tuple[bool, str]:
    """
    Send an email via SMTP with TLS. Returns (success, error_message).
    """
    if not config.is_smtp_configured():
        return False, "SMTP not configured. Please set SMTP_USER and SMTP_PASS in .env"

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{config.SMTP_FROM_NAME} <{config.SMTP_USER}>"
        msg["To"] = to_email
        msg["X-Mailer"] = "OBSERVER Security Platform"

        msg.attach(MIMEText(html_body, "html", "utf-8"))

        context = ssl.create_default_context()
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(config.SMTP_USER, config.SMTP_PASS)
            server.sendmail(config.SMTP_USER, to_email, msg.as_bytes())

        return True, ""

    except smtplib.SMTPAuthenticationError:
        return False, "SMTP authentication failed. Check your email credentials in .env"
    except smtplib.SMTPRecipientsRefused:
        return False, f"Email address rejected: {to_email}"
    except TimeoutError:
        return False, "SMTP connection timed out. Check SMTP_HOST and SMTP_PORT."
    except Exception as e:
        return False, f"Failed to send email: {str(e)}"


# ─── Public API ───────────────────────────────────────────────────────────────

def send_registration_otp(to_email: str, full_name: str, code: str) -> Tuple[bool, str]:
    """Send account verification OTP after registration."""
    html = _otp_html(
        title="Verify Your OBSERVER Account",
        intro=f"Welcome to OBSERVER, <strong style='color:#c0c0c0;'>{full_name}</strong>.<br><br>"
              f"Enter the verification code below to activate your account:",
        code=code,
        purpose_note="This code is for account verification only.",
    )
    return _send_email(to_email, "OBSERVER — Verify Your Account", html)


def send_2fa_otp(to_email: str, full_name: str, code: str) -> Tuple[bool, str]:
    """Send 2FA code during login."""
    html = _otp_html(
        title="Two-Factor Authentication Code",
        intro=f"Hello, <strong style='color:#c0c0c0;'>{full_name}</strong>.<br><br>"
              f"A login attempt was made to your OBSERVER account. "
              f"Enter the code below to complete authentication:",
        code=code,
        purpose_note="This code was requested for your account login.",
    )
    return _send_email(to_email, "OBSERVER — Two-Factor Authentication", html)


def send_profile_change_otp(to_email: str, full_name: str, code: str) -> Tuple[bool, str]:
    """Send OTP for sensitive profile modifications."""
    html = _otp_html(
        title="Profile Change Authorization",
        intro=f"Hello, <strong style='color:#c0c0c0;'>{full_name}</strong>.<br><br>"
              f"A request was made to modify your OBSERVER account profile. "
              f"Enter the code below to authorize this change:",
        code=code,
        purpose_note="This code authorizes a sensitive account change.",
    )
    return _send_email(to_email, "OBSERVER — Profile Change Authorization", html)


def send_critical_alert(
    to_email: str, target_url: str, finding_title: str, severity: str = "CRITICAL"
) -> Tuple[bool, str]:
    """Send an immediate alert email for critical/high severity findings."""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    html = _alert_html(
        target_url=target_url,
        severity=severity,
        findings_summary=finding_title,
        timestamp=timestamp,
    )
    return _send_email(
        to_email,
        f"[OBSERVER ALERT] {severity} Vulnerability — {target_url[:60]}",
        html,
    )


def test_smtp_connection(
    host: str, port: int, user: str, password: str, use_tls: bool = True
) -> Tuple[bool, str]:
    """
    Test SMTP connection and authentication with given credentials without sending an email.
    Returns (success, message).
    """
    if not host or not port or not user or not password:
        return False, "Host, port, username, and password are all required."

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(host, int(port), timeout=10) as server:
            server.ehlo()
            if use_tls:
                server.starttls(context=context)
                server.ehlo()
            server.login(user, password)
            return True, "SMTP connection and authentication successful."
    except smtplib.SMTPAuthenticationError:
        return False, "Authentication failed. Check your username/password (for Gmail, use an App Password)."
    except smtplib.SMTPConnectError:
        return False, f"Could not connect to SMTP server at {host}:{port}."
    except TimeoutError:
        return False, f"Connection to {host}:{port} timed out."
    except Exception as e:
        return False, f"SMTP test failed: {str(e)}"
