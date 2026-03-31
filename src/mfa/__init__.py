# src/mfa/__init__.py
# SecureAuth – Multi-Factor Authentication Module
# CSE212 Cyber Security | Ahmedabad University | Author: Ansh (AU2320008)

from .otp_manager   import OTPManager, RateLimitExceeded
from .totp_manager  import TOTPManager
from .email_otp     import EmailOTPSender, MockEmailOTPSender
from .sms_otp       import SMSOTPSender, MockSMSOTPSender
from .mfa_service   import MFAService

__all__ = [
    "MFAService",
    "OTPManager",
    "TOTPManager",
    "EmailOTPSender", "MockEmailOTPSender",
    "SMSOTPSender",   "MockSMSOTPSender",
    "RateLimitExceeded",
]

__version__ = "1.0.0"
__author__  = "Ansh (AU2320008)"