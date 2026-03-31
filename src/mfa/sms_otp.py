"""
src/mfa/sms_otp.py
──────────────────────────────────────────────────────────────────────────────
SMS OTP delivery via Twilio.
SecureAuth | CSE212 Cyber Security | Ahmedabad University
Author: Ansh (AU2320008)

Twilio setup
────────────
1. Sign up at twilio.com (free trial available).
2. Console → Account Info → copy Account SID and Auth Token.
3. Use a Twilio phone number as `from_number` (E.164: "+12025551234").
4. pip install twilio

Use MockSMSOTPSender for development — no Twilio account needed.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class SMSOTPSender:
    """
    Sends OTP codes via SMS (Twilio).

    Quick start
    ───────────
    >>> sender = SMSOTPSender(
    ...     account_sid  = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    ...     auth_token   = "your_auth_token",
    ...     from_number  = "+12025551234",
    ... )
    >>> sender.send_otp("+919876543210", "847392", purpose="login")
    {"success": True, "message": "OTP sent to +919876543210", "sid": "SM..."}
    """

    def __init__(
        self,
        account_sid  : str,
        auth_token   : str,
        from_number  : str,
        service_name : str = "SecureAuth",
    ):
        try:
            from twilio.rest import Client  # type: ignore
        except ImportError:
            raise ImportError("Twilio not installed. Run:  pip install twilio")

        self.client       = Client(account_sid, auth_token)
        self.from_number  = from_number
        self.service_name = service_name

    def send_otp(
        self,
        to_number      : str,
        otp_code       : str,
        purpose        : str = "login",
        expiry_minutes : int = 5,
    ) -> dict:
        """
        Send *otp_code* to *to_number*.
        Returns { "success": bool, "message": str, "sid": str | None }
        """
        body = (
            f"[{self.service_name}] {purpose.replace('_',' ').title()} code: {otp_code}\n"
            f"Valid {expiry_minutes} min. Do NOT share."
        )
        try:
            msg = self.client.messages.create(body=body, from_=self.from_number, to=to_number)
            logger.info("SMS OTP sent  to=%s sid=%s purpose=%s", to_number, msg.sid, purpose)
            return {"success": True,  "message": f"OTP sent to {to_number}", "sid": msg.sid}
        except Exception as exc:
            logger.error("SMS error: %s", exc)
            return {"success": False, "message": f"SMS delivery failed: {exc}", "sid": None}


# ──────────────────────────────────────────────────────────────────────────────
# Mock sender  –  development / testing (no real SMS)
# ──────────────────────────────────────────────────────────────────────────────

class MockSMSOTPSender(SMSOTPSender):
    """
    Drop-in replacement that prints to stdout.

    >>> from src.mfa.sms_otp import MockSMSOTPSender
    >>> sender = MockSMSOTPSender()
    """

    def __init__(self, service_name: str = "SecureAuth [MOCK]"):
        self.service_name = service_name

    def send_otp(self, to_number, otp_code, purpose="login", expiry_minutes=5):
        print(f"\n{'='*52}")
        print(f"  [MockSMS] TO      : {to_number}")
        print(f"  [MockSMS] PURPOSE : {purpose}")
        print(f"  [MockSMS] OTP     : {otp_code}")
        print(f"  [MockSMS] EXPIRES : {expiry_minutes} min")
        print(f"{'='*52}\n")
        return {"success": True, "message": f"[MOCK] OTP printed for {to_number}", "sid": "mock-sid"}