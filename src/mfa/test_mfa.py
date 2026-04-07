"""
src/mfa/test_mfa.py
──────────────────────────────────────────────────────────────────────────────
Full test suite for the MFA module.
SecureAuth | CSE212 Cyber Security | Ahmedabad University
Author: Ansh (AU2320008)

Run:  python -m pytest src/mfa/test_mfa.py -v
──────────────────────────────────────────────────────────────────────────────
"""

import sys, os
# Ensure project `src/` is on sys.path so imports like `from mfa...` work.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import time
import pytest
from unittest.mock import patch

from mfa.otp_manager  import OTPManager, RateLimitExceeded
from mfa.totp_manager import TOTPManager
from mfa.email_otp    import MockEmailOTPSender
from mfa.sms_otp      import MockSMSOTPSender
from mfa.mfa_service  import MFAService


# ══════════════════════════════════════════════════════════════════════════════
# OTPManager
# ══════════════════════════════════════════════════════════════════════════════

class TestOTPManager:

    def setup_method(self):
        self.mgr = OTPManager(expiry_seconds=60, otp_digits=6, max_attempts=3)

    def test_generate_returns_6_digits(self):
        code = self.mgr.generate("user1")
        assert code.isdigit() and len(code) == 6

    def test_verify_correct_code(self):
        code = self.mgr.generate("u1")
        assert self.mgr.verify("u1", code)["success"] is True

    def test_verify_wrong_code(self):
        self.mgr.generate("u2")
        r = self.mgr.verify("u2", "000000")
        assert r["success"] is False
        assert r["remaining_attempts"] == 2

    def test_single_use_enforcement(self):
        code = self.mgr.generate("u3")
        self.mgr.verify("u3", code)
        assert self.mgr.verify("u3", code)["success"] is False

    def test_max_attempts_lockout(self):
        self.mgr.generate("u4")
        for _ in range(3):
            self.mgr.verify("u4", "000000")
        assert self.mgr.verify("u4", "000000")["success"] is False

    def test_expired_otp(self):
        mgr  = OTPManager(expiry_seconds=30)
        code = mgr.generate("u5")
        with patch("time.time", return_value=time.time() + 400):
            r = mgr.verify("u5", code)
        assert r["success"] is False and "expired" in r["message"].lower()

    def test_no_otp_exists(self):
        r = self.mgr.verify("nobody", "123456")
        assert r["success"] is False and "No active" in r["message"]

    def test_invalidate(self):
        self.mgr.generate("u6")
        self.mgr.invalidate("u6")
        assert self.mgr.verify("u6", "123456")["success"] is False

    def test_rate_limit(self):
        mgr = OTPManager()
        for _ in range(3):
            mgr.generate("spammer")
        with pytest.raises(RateLimitExceeded):
            mgr.generate("spammer")

    def test_otp_digits_4(self):
        assert len(OTPManager(otp_digits=4).generate("u")) == 4

    def test_otp_digits_8(self):
        assert len(OTPManager(otp_digits=8).generate("u")) == 8

    def test_invalid_digits_raises(self):
        with pytest.raises(ValueError):
            OTPManager(otp_digits=5)

    def test_cleanup_expired(self):
        mgr = OTPManager(expiry_seconds=30)
        mgr.generate("old")
        with patch("time.time", return_value=time.time() + 400):
            assert mgr.cleanup_expired() == 1

    def test_status_returns_metadata(self):
        self.mgr.generate("u7")
        s = self.mgr.status("u7")
        assert s["exists"] is True and s["attempts_remaining"] == 3

    def test_status_none_when_no_otp(self):
        assert self.mgr.status("ghost") is None

    def test_purpose_isolation(self):
        """OTPs for different purposes don't interfere."""
        code_login = self.mgr.generate("u8", purpose="login")
        code_reset = self.mgr.generate("u8", purpose="password_reset")
        assert self.mgr.verify("u8", code_login, purpose="login")["success"] is True
        assert self.mgr.verify("u8", code_reset, purpose="password_reset")["success"] is True


# ══════════════════════════════════════════════════════════════════════════════
# TOTPManager
# ══════════════════════════════════════════════════════════════════════════════

class TestTOTPManager:

    def setup_method(self):
        self.totp = TOTPManager(issuer="SecureAuth-Test")

    def test_generate_secret_is_base32(self):
        import base64
        secret  = self.totp.generate_secret()
        padding = (8 - len(secret) % 8) % 8
        base64.b32decode(secret + "=" * padding)   # should not raise

    def test_provisioning_uri_format(self):
        uri = self.totp.provisioning_uri(self.totp.generate_secret(), "ansh@example.com")
        assert uri.startswith("otpauth://totp/")
        assert "secret=" in uri
        assert "issuer=SecureAuth-Test" in uri

    def test_verify_current_code(self):
        secret = self.totp.generate_secret()
        code   = self.totp.get_current_code(secret)
        assert self.totp.verify(secret, code)["success"] is True

    def test_verify_wrong_code(self):
        assert self.totp.verify(self.totp.generate_secret(), "000000")["success"] is False

    def test_replay_prevention(self):
        secret = self.totp.generate_secret()
        code   = self.totp.get_current_code(secret)
        used   = set()
        self.totp.verify(secret, code, used_codes=used)
        used.add(code)
        r = self.totp.verify(secret, code, used_codes=used)
        assert r["success"] is False and "already used" in r["message"].lower()

    def test_bad_format_rejected(self):
        assert self.totp.verify(self.totp.generate_secret(), "abc")["success"] is False

    def test_generate_backup_codes(self):
        codes = self.totp.generate_backup_codes()
        assert len(codes) == 10
        assert all("-" in c for c in codes)

    def test_verify_backup_code(self):
        codes  = self.totp.generate_backup_codes()
        hashes = [self.totp.hash_backup_code(c) for c in codes]
        r = self.totp.verify_backup_code(codes[0], hashes)
        assert r["success"] is True and r["matched_hash"] == hashes[0]

    def test_invalid_backup_code(self):
        hashes = [self.totp.hash_backup_code("ABCD-EFGH")]
        assert self.totp.verify_backup_code("XXXX-YYYY", hashes)["success"] is False


# ══════════════════════════════════════════════════════════════════════════════
# Mock senders
# ══════════════════════════════════════════════════════════════════════════════

class TestMockSenders:

    def test_email_always_succeeds(self):
        r = MockEmailOTPSender().send_otp("user@example.com", "123456")
        assert r["success"] is True

    def test_sms_always_succeeds(self):
        r = MockSMSOTPSender().send_otp("+919876543210", "654321")
        assert r["success"] is True and r["sid"] == "mock-sid"


# ══════════════════════════════════════════════════════════════════════════════
# MFAService  (integration)
# ══════════════════════════════════════════════════════════════════════════════

class TestMFAService:

    def setup_method(self):
        self.mfa = MFAService(
            email_sender = MockEmailOTPSender(),
            sms_sender   = MockSMSOTPSender(),
        )

    def _send_and_capture(self, user_id, method="email"):
        """Send OTP and capture the generated code by intercepting the sender."""
        sent = []
        sender = self.mfa._email if method == "email" else self.mfa._sms
        orig   = sender.send_otp
        def capture(to, code, **kw):
            sent.append(code)
            return orig(to, code, **kw)
        sender.send_otp = capture
        self.mfa.send_otp(user_id, method=method)
        sender.send_otp = orig   # restore
        return sent[0]

    def test_send_and_verify_email(self):
        code = self._send_and_capture("user@example.com", "email")
        assert self.mfa.verify_otp("user@example.com", code)["success"] is True

    def test_send_and_verify_sms(self):
        code = self._send_and_capture("+919876543210", "sms")
        assert self.mfa.verify_otp("+919876543210", code)["success"] is True

    def test_unknown_method(self):
        r = self.mfa.send_otp("u", method="carrier_pigeon")
        assert r["success"] is False and "Unknown" in r["message"]

    def test_no_email_sender(self):
        r = MFAService().send_otp("u", method="email")
        assert r["success"] is False and "not configured" in r["message"]

    def test_no_sms_sender(self):
        r = MFAService().send_otp("u", method="sms")
        assert r["success"] is False and "not configured" in r["message"]

    def test_totp_setup_and_verify(self):
        info   = self.mfa.totp_setup("ansh@example.com")
        secret = info["secret"]
        assert "uri" in info and len(info["backup_codes"]) == 10
        code   = self.mfa._totp.get_current_code(secret)
        assert self.mfa.verify_totp("ansh@example.com", secret, code)["success"] is True

    def test_cancel_otp(self):
        code = self._send_and_capture("u@example.com")
        self.mfa.cancel_otp("u@example.com")
        assert self.mfa.verify_otp("u@example.com", code)["success"] is False

    def test_rate_limit_propagated(self):
        for _ in range(3):
            self.mfa.send_otp("flood@example.com", method="email")
        r = self.mfa.send_otp("flood@example.com", method="email")
        assert r["success"] is False

    def test_backup_code_verify(self):
        info   = self.mfa.totp_setup("ansh@example.com")
        result = self.mfa.verify_backup_code(
            "ansh@example.com", info["backup_codes"][0], info["backup_hashes"]
        )
        assert result["success"] is True and result["matched_hash"] is not None

    def test_otp_status(self):
        self._send_and_capture("status_user@example.com")
        s = self.mfa.otp_status("status_user@example.com")
        assert s and s["exists"] is True

    def test_cleanup(self):
        """cleanup() should run without errors."""
        self.mfa.cleanup()
