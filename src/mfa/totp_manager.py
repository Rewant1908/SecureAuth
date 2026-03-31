"""
src/mfa/totp_manager.py
──────────────────────────────────────────────────────────────────────────────
TOTP (Authenticator-app) manager — RFC 6238 / RFC 4226 implementation.
SecureAuth | CSE212 Cyber Security | Ahmedabad University
Author: Ansh (AU2320008)

Compatible with: Google Authenticator, Authy, Microsoft Authenticator, 1Password
No third-party libraries required — pure Python stdlib.
"""

import base64
import hashlib
import hmac as hmac_mod
import secrets
import struct
import time
import urllib.parse
from typing import List, Optional, Set


class TOTPManager:
    """
    Manages TOTP-based MFA (authenticator-app codes).

    Quick start
    ───────────
    >>> totp   = TOTPManager(issuer="SecureAuth")
    >>> secret = totp.generate_secret()          # store encrypted in DB
    >>> uri    = totp.provisioning_uri(secret, "ansh@example.com")
    >>> # render `uri` as a QR code → user scans with their app

    >>> code   = "123456"   # from user's authenticator app
    >>> result = totp.verify(secret, code)
    >>> result["success"]   # True / False
    """

    DIGITS    = 6
    PERIOD    = 30   # seconds per window
    TOLERANCE = 1    # accept ±1 window  (handles ±30 s clock drift)

    def __init__(self, issuer: str = "SecureAuth", tolerance: int = TOLERANCE):
        self.issuer    = issuer
        self.tolerance = tolerance

    # ── Secret management ──────────────────────────────────────────────────────

    def generate_secret(self, byte_length: int = 32) -> str:
        """
        Generate a 256-bit cryptographically random Base32 secret.
        Store this ENCRYPTED in the database — never log or expose it.
        """
        return base64.b32encode(secrets.token_bytes(byte_length)).decode().rstrip("=")

    def provisioning_uri(self, secret: str, account: str, issuer: Optional[str] = None) -> str:
        """
        Build the otpauth:// URI to display as a QR code.
        Users scan this once to register in their authenticator app.
        """
        name  = issuer or self.issuer
        label = urllib.parse.quote(f"{name}:{account}", safe=":")
        params = urllib.parse.urlencode({
            "secret"   : secret,
            "issuer"   : name,
            "algorithm": "SHA1",
            "digits"   : self.DIGITS,
            "period"   : self.PERIOD,
        })
        return f"otpauth://totp/{label}?{params}"

    # ── Verification ───────────────────────────────────────────────────────────

    def get_current_code(self, secret: str) -> str:
        """Return the live code for testing purposes."""
        return self._compute(secret, int(time.time()) // self.PERIOD)

    def verify(
        self,
        secret     : str,
        code       : str,
        used_codes : Optional[Set[str]] = None,
    ) -> dict:
        """
        Verify a 6-digit code from the user's authenticator app.

        Parameters
        ──────────
        secret     : user's stored Base32 TOTP secret (from DB)
        code       : 6-digit string entered by the user
        used_codes : mutable set — caller adds result["code"] on success
                     to prevent replay within the same window

        Returns
        ───────
        { "success": bool, "message": str, "code": str }
        """
        if not (code and code.isdigit() and len(code) == self.DIGITS):
            return {"success": False, "message": "Code must be exactly 6 digits.", "code": code}

        if used_codes and code in used_codes:
            return {"success": False, "message": "Code already used. Wait for the next one.", "code": code}

        counter = int(time.time()) // self.PERIOD
        for delta in range(-self.tolerance, self.tolerance + 1):
            if hmac_mod.compare_digest(self._compute(secret, counter + delta), code):
                return {"success": True, "message": "TOTP verified successfully.", "code": code}

        return {"success": False, "message": "Invalid or expired code.", "code": code}

    # ── Backup codes ───────────────────────────────────────────────────────────

    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """
        Generate one-time backup codes (XXXX-XXXX format).
        Show plaintext to user ONCE; store only the hashes.
        """
        codes = []
        for _ in range(count):
            raw = secrets.token_hex(4).upper()
            codes.append(f"{raw[:4]}-{raw[4:]}")
        return codes

    def hash_backup_code(self, code: str) -> str:
        """Hash a backup code for safe DB storage."""
        return hashlib.sha256(code.replace("-", "").upper().encode()).hexdigest()

    def verify_backup_code(self, entered: str, stored_hashes: List[str]) -> dict:
        """
        Verify a backup code against DB hashes.
        On success, caller removes result["matched_hash"] from the DB.
        """
        h = self.hash_backup_code(entered)
        for stored in stored_hashes:
            if hmac_mod.compare_digest(h, stored):
                return {"success": True,  "message": "Backup code accepted.", "matched_hash": stored}
        return {"success": False, "message": "Invalid backup code.", "matched_hash": None}

    # ── RFC 6238 core ──────────────────────────────────────────────────────────

    def _compute(self, secret: str, counter: int) -> str:
        padding = (8 - len(secret) % 8) % 8
        key     = base64.b32decode((secret + "=" * padding).upper())
        msg     = struct.pack(">Q", counter)
        digest  = hmac_mod.new(key, msg, hashlib.sha1).digest()
        offset  = digest[-1] & 0x0F
        code    = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
        return str(code % (10 ** self.DIGITS)).zfill(self.DIGITS)