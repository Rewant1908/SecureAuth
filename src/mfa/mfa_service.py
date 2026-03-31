"""
src/mfa/mfa_service.py
──────────────────────────────────────────────────────────────────────────────
Unified MFA entry point for SecureAuth.
CSE212 Cyber Security | Ahmedabad University
Author: Ansh (AU2320008)

This is the only class main.py needs to import.
It integrates with the existing SecureAuth flow:

    Security Check → Credential Verify → AI Risk Analysis → DECISION
        • LOW  (0–39)   → JWT tokens (no MFA needed)
        • MEDIUM(40–69) → MFAService.send_otp()  ← this module
        • HIGH (70–100) → Block + email alert

Supported methods
─────────────────
    "email"  –  6-digit OTP to email (SMTP)
    "sms"    –  6-digit OTP to phone (Twilio)
    "totp"   –  authenticator app (Google Authenticator, Authy …)
"""

import logging
from typing import Optional, Set

from .otp_manager  import OTPManager, RateLimitExceeded
from .totp_manager import TOTPManager
from .email_otp    import EmailOTPSender
from .sms_otp      import SMSOTPSender

logger = logging.getLogger(__name__)


class MFAService:
    """
    The single class main.py (and Flask routes) talks to.

    Initialise once at app startup
    ──────────────────────────────
    >>> from src.mfa import MFAService
    >>> from src.mfa.email_otp import MockEmailOTPSender   # or real EmailOTPSender
    >>> mfa = MFAService(email_sender=MockEmailOTPSender())

    MEDIUM-risk login flow
    ──────────────────────
    >>> result = mfa.send_otp(user_id, method="email")    # after password OK
    >>> # user gets the code in their inbox / phone
    >>> result = mfa.verify_otp(user_id, entered_code)
    >>> if result["success"]:
    ...     # issue JWT tokens (same as LOW-risk path)

    TOTP flow
    ─────────
    >>> info   = mfa.totp_setup(user_id)           # one-time enrollment
    >>> qr_uri = info["uri"]                        # render as QR code
    >>> # on every login:
    >>> result = mfa.verify_totp(user_id, secret_from_db, code_from_app)
    """

    def __init__(
        self,
        email_sender   : Optional[EmailOTPSender] = None,
        sms_sender     : Optional[SMSOTPSender]   = None,
        issuer         : str = "SecureAuth",
        otp_expiry     : int = 300,   # 5 minutes
        otp_digits     : int = 6,
        max_attempts   : int = 3,
    ):
        self._email = email_sender
        self._sms   = sms_sender
        self._otp   = OTPManager(
            expiry_seconds = otp_expiry,
            otp_digits     = otp_digits,
            max_attempts   = max_attempts,
        )
        self._totp  = TOTPManager(issuer=issuer)

    # ══════════════════════════════════════════════════════════════════════════
    # Email / SMS OTP
    # ══════════════════════════════════════════════════════════════════════════

    def send_otp(
        self,
        user_id     : str,
        method      : str,              # "email" | "sms"
        purpose     : str = "login",
        destination : Optional[str] = None,  # email addr or phone; defaults to user_id
    ) -> dict:
        """
        Generate an OTP and deliver it to the user.

        Call this when AI risk score is MEDIUM (40–69).

        Returns { "success": bool, "message": str }
        """
        dest = destination or user_id

        try:
            code = self._otp.generate(user_id, purpose=purpose)
        except RateLimitExceeded as exc:
            logger.warning("OTP rate limit hit  user=%s", user_id)
            return {"success": False, "message": str(exc)}

        expiry_min = self._otp.expiry_seconds // 60

        if method == "email":
            if not self._email:
                self._otp.invalidate(user_id, purpose)
                return {"success": False, "message": "Email sender not configured. Check .env / app setup."}
            result = self._email.send_otp(dest, code, purpose=purpose, expiry_minutes=expiry_min)

        elif method == "sms":
            if not self._sms:
                self._otp.invalidate(user_id, purpose)
                return {"success": False, "message": "SMS sender not configured. Check .env / app setup."}
            result = self._sms.send_otp(dest, code, purpose=purpose, expiry_minutes=expiry_min)

        else:
            self._otp.invalidate(user_id, purpose)
            return {"success": False, "message": f"Unknown MFA method '{method}'. Use 'email' or 'sms'."}

        # If delivery failed, clean up so user can retry
        if not result["success"]:
            self._otp.invalidate(user_id, purpose)

        return result

    def verify_otp(
        self,
        user_id : str,
        code    : str,
        purpose : str = "login",
    ) -> dict:
        """
        Verify a code entered by the user after send_otp().

        Returns { "success": bool, "message": str, "remaining_attempts": int|None }
        On success → caller should issue JWT tokens (same path as LOW-risk logins).
        """
        result = self._otp.verify(user_id, code, purpose=purpose)
        logger.info("OTP verify  user=%s  success=%s", user_id, result["success"])
        return result

    def otp_status(self, user_id: str, purpose: str = "login") -> Optional[dict]:
        """Metadata for UI countdown: time left, attempts remaining."""
        return self._otp.status(user_id, purpose)

    def cancel_otp(self, user_id: str, purpose: str = "login") -> bool:
        """Invalidate OTP when user clicks 'Resend'."""
        return self._otp.invalidate(user_id, purpose)

    # ══════════════════════════════════════════════════════════════════════════
    # TOTP  (authenticator app)
    # ══════════════════════════════════════════════════════════════════════════

    def totp_setup(self, user_id: str) -> dict:
        """
        One-time TOTP enrollment for a user.

        Returns
        ───────
        {
            "secret"        : str,        ← store ENCRYPTED in DB
            "uri"           : str,        ← render as QR code, show to user
            "backup_codes"  : list[str],  ← show ONCE to user, then discard
            "backup_hashes" : list[str],  ← store in DB
        }
        """
        secret  = self._totp.generate_secret()
        uri     = self._totp.provisioning_uri(secret, account=user_id)
        codes   = self._totp.generate_backup_codes()
        hashes  = [self._totp.hash_backup_code(c) for c in codes]
        logger.info("TOTP setup  user=%s", user_id)
        return {
            "secret"       : secret,
            "uri"          : uri,
            "backup_codes" : codes,
            "backup_hashes": hashes,
        }

    def verify_totp(
        self,
        user_id    : str,
        secret     : str,
        code       : str,
        used_codes : Optional[Set[str]] = None,
    ) -> dict:
        """
        Verify a TOTP code from an authenticator app.

        Parameters
        ──────────
        secret     : user's stored (and decrypted) TOTP secret from DB
        code       : 6-digit string the user entered
        used_codes : mutable set — add result["code"] on success to block replay

        Returns { "success": bool, "message": str, "code": str }
        """
        result = self._totp.verify(secret, code, used_codes=used_codes)
        if result["success"] and used_codes is not None:
            used_codes.add(code)
        logger.info("TOTP verify  user=%s  success=%s", user_id, result["success"])
        return result

    def verify_backup_code(
        self,
        user_id       : str,
        entered       : str,
        stored_hashes : list,
    ) -> dict:
        """
        Verify a TOTP backup / recovery code.
        On success, remove result["matched_hash"] from the user's DB record.
        """
        result = self._totp.verify_backup_code(entered, stored_hashes)
        logger.info("Backup code  user=%s  success=%s", user_id, result["success"])
        return result

    # ══════════════════════════════════════════════════════════════════════════
    # Maintenance
    # ══════════════════════════════════════════════════════════════════════════

    def cleanup(self) -> int:
        """Remove expired OTP records from memory. Call from a background task."""
        return self._otp.cleanup_expired()