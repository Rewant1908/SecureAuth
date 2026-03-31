"""
src/mfa/otp_manager.py
──────────────────────────────────────────────────────────────────────────────
Core OTP generation & verification engine.
SecureAuth | CSE212 Cyber Security | Ahmedabad University
Author: Ansh (AU2320008)

Security properties
───────────────────
• OTPs hashed with SHA-256   → never stored in plaintext
• hmac.compare_digest        → constant-time, no timing-attack leakage
• Max-attempts lock-out      → brute-force protection
• Single-use enforcement     → replay-attack prevention
• Per-user rate limiting     → OTP-flooding prevention
• In-memory store            → swap dict for Redis/MariaDB in production
"""

import hashlib
import hmac
import secrets
import string
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# ──────────────────────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class OTPRecord:
    hashed_otp : str    # SHA-256 of the plaintext code
    created_at : float
    expires_at : float
    purpose    : str    # "login" | "password_reset" | "email_verify" …
    attempts   : int  = 0
    used       : bool = False


# ──────────────────────────────────────────────────────────────────────────────
# Exceptions
# ──────────────────────────────────────────────────────────────────────────────

class RateLimitExceeded(Exception):
    """Raised when a user requests OTPs too frequently."""


# ──────────────────────────────────────────────────────────────────────────────
# Manager
# ──────────────────────────────────────────────────────────────────────────────

class OTPManager:
    """
    Generates and verifies time-limited, single-use OTPs.

    Quick start
    ───────────
    >>> mgr  = OTPManager()
    >>> code = mgr.generate("user@example.com", purpose="login")
    >>> # deliver `code` via email / SMS
    >>> result = mgr.verify("user@example.com", code, purpose="login")
    >>> result["success"]   # True
    """

    DEFAULT_DIGITS       = 6
    DEFAULT_EXPIRY       = 300    # 5 minutes
    DEFAULT_MAX_ATTEMPTS = 3
    RATE_LIMIT_WINDOW    = 60     # seconds
    MAX_PER_WINDOW       = 3

    def __init__(
        self,
        expiry_seconds : int = DEFAULT_EXPIRY,
        otp_digits     : int = DEFAULT_DIGITS,
        max_attempts   : int = DEFAULT_MAX_ATTEMPTS,
    ):
        if otp_digits not in (4, 6, 8):
            raise ValueError("otp_digits must be 4, 6, or 8")
        if expiry_seconds < 30:
            raise ValueError("expiry_seconds must be >= 30")

        self.expiry_seconds = expiry_seconds
        self.otp_digits     = otp_digits
        self.max_attempts   = max_attempts

        self._store      : Dict[Tuple[str, str], OTPRecord] = {}
        self._rate_limit : Dict[str, List[float]]           = {}

    # ── Public API ─────────────────────────────────────────────────────────────

    def generate(self, user_id: str, purpose: str = "login") -> str:
        """
        Create a new OTP.  Returns the plaintext code to send to the user.
        Raises RateLimitExceeded if the user has hit the request cap.
        """
        self._check_rate_limit(user_id)

        code = self._secure_code()
        now  = time.time()
        self._store[(user_id, purpose)] = OTPRecord(
            hashed_otp = self._hash(code),
            created_at = now,
            expires_at = now + self.expiry_seconds,
            purpose    = purpose,
        )
        self._record_request(user_id)
        return code

    def verify(self, user_id: str, code: str, purpose: str = "login") -> dict:
        """
        Verify a code entered by the user.

        Returns
        ───────
        { "success": bool, "message": str, "remaining_attempts": int | None }
        """
        key    = (user_id, purpose)
        record = self._store.get(key)

        if record is None:
            return self._r(False, "No active OTP. Please request a new one.")

        if record.used:
            return self._r(False, "OTP already used. Please request a new one.")

        if time.time() > record.expires_at:
            del self._store[key]
            return self._r(False, "OTP expired. Please request a new one.")

        if record.attempts >= self.max_attempts:
            del self._store[key]
            return self._r(False, "OTP invalidated — too many failed attempts.", rem=0)

        if not hmac.compare_digest(self._hash(code), record.hashed_otp):
            record.attempts += 1
            remaining = self.max_attempts - record.attempts
            if remaining == 0:
                del self._store[key]
                return self._r(False, "OTP invalidated — max attempts reached.", rem=0)
            return self._r(False, f"Incorrect OTP. {remaining} attempt(s) left.", rem=remaining)

        # ✅ success — single-use: delete immediately
        record.used = True
        del self._store[key]
        return self._r(True, "OTP verified successfully.")

    def invalidate(self, user_id: str, purpose: str = "login") -> bool:
        """Force-expire an OTP (e.g. user clicked 'resend')."""
        key = (user_id, purpose)
        if key in self._store:
            del self._store[key]
            return True
        return False

    def status(self, user_id: str, purpose: str = "login") -> Optional[dict]:
        """Metadata about an existing OTP — without revealing the code."""
        r = self._store.get((user_id, purpose))
        if not r:
            return None
        return {
            "exists"            : True,
            "expires_in_seconds": max(0, int(r.expires_at - time.time())),
            "attempts_used"     : r.attempts,
            "attempts_remaining": self.max_attempts - r.attempts,
            "is_expired"        : time.time() > r.expires_at,
            "is_used"           : r.used,
        }

    def cleanup_expired(self) -> int:
        """Remove stale records. Call from a background/cron task."""
        now  = time.time()
        dead = [k for k, r in self._store.items() if now > r.expires_at]
        for k in dead:
            del self._store[k]
        return len(dead)

    # ── Internals ──────────────────────────────────────────────────────────────

    def _secure_code(self) -> str:
        return "".join(secrets.choice(string.digits) for _ in range(self.otp_digits))

    def _hash(self, code: str) -> str:
        return hashlib.sha256(code.encode()).hexdigest()

    def _check_rate_limit(self, user_id: str) -> None:
        now    = time.time()
        cutoff = now - self.RATE_LIMIT_WINDOW
        recent = [t for t in self._rate_limit.get(user_id, []) if t > cutoff]
        if len(recent) >= self.MAX_PER_WINDOW:
            raise RateLimitExceeded(
                f"Too many OTP requests for '{user_id}'. "
                f"Please wait {self.RATE_LIMIT_WINDOW}s."
            )
        self._rate_limit[user_id] = recent

    def _record_request(self, user_id: str) -> None:
        self._rate_limit.setdefault(user_id, []).append(time.time())

    @staticmethod
    def _r(success: bool, message: str, rem: Optional[int] = None) -> dict:
        return {"success": success, "message": message, "remaining_attempts": rem}