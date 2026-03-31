"""
src/mfa/email_otp.py
──────────────────────────────────────────────────────────────────────────────
Email OTP delivery via SMTP.
SecureAuth | CSE212 Cyber Security | Ahmedabad University
Author: Ansh (AU2320008)

Supports Gmail, Outlook, or any SMTP server.
Use MockEmailOTPSender in development — no real emails sent.

Gmail setup
───────────
1. Enable 2-Step Verification on your Google account.
2. myaccount.google.com → Security → App Passwords → Mail
3. Use the generated 16-char password as `password=` below.
   (NOT your actual Google account password)
"""

import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

logger = logging.getLogger(__name__)


class EmailOTPSender:
    """
    Sends OTP codes by email over SMTP.

    Quick start
    ───────────
    >>> sender = EmailOTPSender(
    ...     smtp_host = "smtp.gmail.com",
    ...     smtp_port = 587,
    ...     username  = "your-app@gmail.com",
    ...     password  = "xxxx xxxx xxxx xxxx",   # App Password
    ... )
    >>> sender.send_otp("user@example.com", "847392", purpose="login")
    {"success": True, "message": "OTP sent to user@example.com"}
    """

    def __init__(
        self,
        smtp_host   : str,
        smtp_port   : int,
        username    : str,
        password    : str,
        sender_name : str  = "SecureAuth",
        use_ssl     : bool = False,   # False=STARTTLS(587)  True=SSL(465)
    ):
        self.smtp_host   = smtp_host
        self.smtp_port   = smtp_port
        self.username    = username
        self.password    = password
        self.sender_name = sender_name
        self.use_ssl     = use_ssl

    def send_otp(
        self,
        to_email       : str,
        otp_code       : str,
        purpose        : str = "login",
        expiry_minutes : int = 5,
        subject        : Optional[str] = None,
    ) -> dict:
        """
        Deliver *otp_code* to *to_email*.
        Returns { "success": bool, "message": str }
        """
        try:
            msg = self._build(to_email, otp_code, purpose, expiry_minutes, subject)
            self._smtp_send(msg, to_email)
            logger.info("OTP email sent  to=%s purpose=%s", to_email, purpose)
            return {"success": True, "message": f"OTP sent to {to_email}"}
        except smtplib.SMTPAuthenticationError:
            logger.error("SMTP auth failed — check .env credentials")
            return {"success": False, "message": "Email delivery failed: authentication error."}
        except smtplib.SMTPRecipientsRefused:
            return {"success": False, "message": "Email delivery failed: recipient address rejected."}
        except Exception as exc:
            logger.error("Email error: %s", exc)
            return {"success": False, "message": f"Email delivery failed: {exc}"}

    # ── Internals ──────────────────────────────────────────────────────────────

    def _build(self, to, code, purpose, expiry, subject):
        msg            = MIMEMultipart("alternative")
        msg["Subject"] = subject or "Your SecureAuth Verification Code"
        msg["From"]    = f"{self.sender_name} <{self.username}>"
        msg["To"]      = to
        msg.attach(MIMEText(self._plain(code, purpose, expiry), "plain"))
        msg.attach(MIMEText(self._html(code, purpose, expiry),  "html"))
        return msg

    def _smtp_send(self, msg, recipient):
        ctx = ssl.create_default_context()
        if self.use_ssl:
            with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, context=ctx) as s:
                s.login(self.username, self.password)
                s.sendmail(self.username, recipient, msg.as_string())
        else:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as s:
                s.ehlo(); s.starttls(context=ctx); s.ehlo()
                s.login(self.username, self.password)
                s.sendmail(self.username, recipient, msg.as_string())

    def _plain(self, code, purpose, expiry):
        return (
            f"SecureAuth — {purpose.replace('_',' ').title()} Verification\n\n"
            f"Your verification code: {code}\n\n"
            f"Valid for {expiry} minutes. Do NOT share this code.\n\n"
            "If you did not request this, secure your account immediately.\n"
            "— The SecureAuth Team"
        )

    def _html(self, code, purpose, expiry):
        label = purpose.replace("_", " ").title()
        return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>
  body{{font-family:Arial,sans-serif;background:#f4f4f4;margin:0;padding:20px}}
  .card{{background:#fff;max-width:460px;margin:0 auto;border-radius:10px;
         padding:36px;box-shadow:0 2px 10px rgba(0,0,0,.1)}}
  .brand{{font-size:22px;font-weight:700;color:#1a1a2e;margin-bottom:20px}}
  .otp-box{{background:#f0f4ff;border:2px dashed #4a6cf7;border-radius:8px;
            text-align:center;padding:20px;margin:24px 0}}
  .otp{{font-size:42px;font-weight:700;letter-spacing:10px;color:#4a6cf7}}
  .expiry{{font-size:13px;color:#888;margin-top:6px}}
  .warn{{font-size:13px;color:#c0392b;background:#fdf3f3;
         border-left:3px solid #c0392b;border-radius:5px;padding:10px;margin-top:18px}}
  .footer{{font-size:11px;color:#bbb;margin-top:28px;text-align:center}}
</style></head>
<body><div class="card">
  <div class="brand">🔐 SecureAuth</div>
  <p style="color:#333;font-size:16px"><strong>{label}</strong> Verification Code</p>
  <p style="color:#555">Use the code below to complete your {label.lower()}.</p>
  <div class="otp-box">
    <div class="otp">{code}</div>
    <div class="expiry">⏱ Expires in {expiry} minutes</div>
  </div>
  <div class="warn">⚠️ Never share this code. SecureAuth will never ask for it.</div>
  <div class="footer">SecureAuth · CSE212 Cyber Security · Ahmedabad University</div>
</div></body></html>"""


# ──────────────────────────────────────────────────────────────────────────────
# Mock sender  –  development / testing (no real emails)
# ──────────────────────────────────────────────────────────────────────────────

class MockEmailOTPSender(EmailOTPSender):
    """
    Drop-in replacement that prints to stdout instead of sending real email.

    >>> from src.mfa.email_otp import MockEmailOTPSender
    >>> sender = MockEmailOTPSender()
    """

    def __init__(self, sender_name: str = "SecureAuth [MOCK]"):
        self.sender_name = sender_name

    def send_otp(self, to_email, otp_code, purpose="login", expiry_minutes=5, subject=None):
        print(f"\n{'='*52}")
        print(f"  [MockEmail] TO      : {to_email}")
        print(f"  [MockEmail] PURPOSE : {purpose}")
        print(f"  [MockEmail] OTP     : {otp_code}")
        print(f"  [MockEmail] EXPIRES : {expiry_minutes} min")
        print(f"{'='*52}\n")
        return {"success": True, "message": f"[MOCK] OTP printed for {to_email}"}