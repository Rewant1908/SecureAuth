"""
src/main.py
──────────────────────────────────────────────────────────────────────────────
SecureAuth – Flask API server
CSE212 Cyber Security | Ahmedabad University

Authentication flow
───────────────────
Step 1  Security Check      brute-force / rate-limit / credential-stuffing
Step 2  Credential Verify   bcrypt password hash
Step 3  AI Risk Analysis    3-model ensemble → risk score 0-100
Step 4  Decision
          LOW    (0–39)  → issue JWT tokens immediately
          MEDIUM (40–69) → require MFA  ← NEW (Ansh, AU2320008)
          HIGH   (70+)   → block + security alert
Step 5  MFA Verify (MEDIUM path only)
          user submits OTP / TOTP code → issue JWT tokens on success

New endpoints added for MFA
────────────────────────────
  POST /api/mfa/send          trigger email/SMS OTP
  POST /api/mfa/verify        verify OTP → returns JWT on success
  POST /api/mfa/totp/setup    TOTP enrollment (QR code URI)
  POST /api/mfa/totp/verify   verify TOTP code → returns JWT on success
  GET  /api/mfa/status        OTP countdown metadata (for UI)
──────────────────────────────────────────────────────────────────────────────
"""

import os
import logging
from datetime import datetime

from dotenv import load_dotenv
from flask  import Flask, request, jsonify

# ── SecureAuth modules ────────────────────────────────────────────────────────
from database          import get_connection, init_db
from jwt_handler.jwt_manager       import JWTManager
from security.security_protection  import SecurityProtection
from adaptive.pro_adaptive_auth    import ProAdaptiveAuthenticator

# ── MFA (Ansh – AU2320008) ────────────────────────────────────────────────────
from mfa                import MFAService
from mfa.email_otp      import EmailOTPSender, MockEmailOTPSender
from mfa.sms_otp        import SMSOTPSender,   MockSMSOTPSender

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "../Config/.env"))

logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("secureauth.main")

app = Flask(__name__)

# ── DB & module initialisation ────────────────────────────────────────────────
conn     = get_connection()
init_db(conn)

jwt_mgr  = JWTManager(secret_key=os.getenv("JWT_SECRET", "change-me-in-production"))
security = SecurityProtection(conn)
ai_auth  = ProAdaptiveAuthenticator(conn, models_dir="../Config/models/")

# ── MFA service initialisation ────────────────────────────────────────────────
# Swap MockEmailOTPSender → real EmailOTPSender when credentials are in .env
_email_sender = (
    EmailOTPSender(
        smtp_host   = os.getenv("SMTP_HOST",     "smtp.gmail.com"),
        smtp_port   = int(os.getenv("SMTP_PORT", "587")),
        username    = os.getenv("SMTP_USER",     ""),
        password    = os.getenv("SMTP_PASSWORD", ""),
        sender_name = "SecureAuth",
    )
    if os.getenv("SMTP_USER")
    else MockEmailOTPSender()
)

_sms_sender = (
    SMSOTPSender(
        account_sid = os.getenv("TWILIO_ACCOUNT_SID", ""),
        auth_token  = os.getenv("TWILIO_AUTH_TOKEN",  ""),
        from_number = os.getenv("TWILIO_FROM_NUMBER", ""),
    )
    if os.getenv("TWILIO_ACCOUNT_SID")
    else MockSMSOTPSender()
)

mfa = MFAService(
    email_sender = _email_sender,
    sms_sender   = _sms_sender,
    issuer       = "SecureAuth",
    otp_expiry   = int(os.getenv("MFA_OTP_EXPIRY", "300")),   # default 5 min
)

# ─────────────────────────────────────────────────────────────────────────────
# Existing endpoint: POST /api/login
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
def login():
    """
    Main login endpoint.

    Body: { username, password, ip_address, user_agent, … }

    Returns on LOW risk  : { access_token, refresh_token, risk_score, … }
    Returns on MEDIUM    : { mfa_required: true, mfa_token, risk_score, … }
    Returns on HIGH      : { error: "blocked", risk_score, explanation }
    """
    data       = request.get_json() or {}
    username   = data.get("username", "").strip()
    password   = data.get("password", "")
    ip_address = data.get("ip_address") or request.remote_addr
    user_agent = data.get("user_agent") or request.headers.get("User-Agent", "")

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    # Step 1 – Security checks
    sec_result = security.check_login_attempt(username, ip_address)
    if not sec_result["allowed"]:
        return jsonify({"error": sec_result["reason"], "blocked_until": sec_result.get("blocked_until")}), 429

    # Step 2 – Credential verification
    user = _get_user(username)
    if not user or not _verify_password(password, user["password_hash"]):
        security.record_failed_attempt(username, ip_address)
        return jsonify({"error": "Invalid username or password."}), 401

    # Step 3 – AI risk analysis
    ai_result = ai_auth.analyze_login(
        user_id    = user["id"],
        login_data = {
            "hour"            : datetime.now().hour,
            "day_of_week"     : datetime.now().weekday(),
            "ip_address"      : ip_address,
            "user_agent"      : user_agent,
            "location_changed": data.get("location_changed", False),
            "device_changed"  : data.get("device_changed",   False),
            "country_changed" : data.get("country_changed",  False),
            "typing_speed"    : data.get("typing_speed",     100),
            "account_age_days": data.get("account_age_days", 365),
        },
    )

    risk_score = ai_result.get("risk_score", 0)
    risk_level = ai_result.get("risk_level", "LOW")
    action     = ai_result.get("action",     "ALLOW")

    # Step 4 – Decision
    # ── HIGH risk ──────────────────────────────────────────────────────────────
    if action == "BLOCK" or risk_score >= 70:
        security.record_blocked_login(username, ip_address, risk_score)
        return jsonify({
            "error"      : "Login blocked due to suspicious activity.",
            "risk_score" : risk_score,
            "risk_level" : risk_level,
            "explanation": ai_result.get("explanation", ""),
        }), 403

    # ── MEDIUM risk → require MFA ──────────────────────────────────────────────
    if action == "REQUIRE_MFA" or 40 <= risk_score < 70:
        # Issue a short-lived MFA session token so the client can come back
        # to /api/mfa/verify without re-submitting their password.
        mfa_token = jwt_mgr.create_mfa_pending_token(user["id"])

        # Auto-send OTP via preferred method (email default, sms if phone known)
        mfa_method = user.get("preferred_mfa", "email")
        destination = user.get("email") if mfa_method == "email" else user.get("phone")
        send_result = mfa.send_otp(
            user_id     = str(user["id"]),
            method      = mfa_method,
            purpose     = "login",
            destination = destination,
        )

        return jsonify({
            "mfa_required" : True,
            "mfa_token"    : mfa_token,
            "mfa_method"   : mfa_method,
            "risk_score"   : risk_score,
            "risk_level"   : risk_level,
            "explanation"  : ai_result.get("explanation", ""),
            "otp_sent"     : send_result["success"],
            "message"      : send_result["message"],
        }), 200

    # ── LOW risk → issue tokens immediately ───────────────────────────────────
    security.record_successful_login(username, ip_address)
    tokens = jwt_mgr.create_tokens(user["id"], user["username"])
    return jsonify({
        "access_token" : tokens["access_token"],
        "refresh_token": tokens["refresh_token"],
        "risk_score"   : risk_score,
        "risk_level"   : risk_level,
        "explanation"  : ai_result.get("explanation", ""),
        "message"      : "Login successful.",
    }), 200


# ─────────────────────────────────────────────────────────────────────────────
# NEW: MFA endpoints  (Ansh – AU2320008)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/mfa/send", methods=["POST"])
def mfa_send():
    """
    Trigger an email or SMS OTP.

    Body: { "mfa_token": "...", "method": "email"|"sms" }
    The mfa_token was returned by /api/login when MFA was required.
    """
    data      = request.get_json() or {}
    mfa_token = data.get("mfa_token", "")
    method    = data.get("method", "email")

    user_id = _validate_mfa_token(mfa_token)
    if not user_id:
        return jsonify({"error": "Invalid or expired MFA session token."}), 401

    user        = _get_user_by_id(user_id)
    destination = user.get("email") if method == "email" else user.get("phone")

    result = mfa.send_otp(
        user_id     = str(user_id),
        method      = method,
        purpose     = "login",
        destination = destination,
    )
    status = 200 if result["success"] else 429
    return jsonify(result), status


@app.route("/api/mfa/verify", methods=["POST"])
def mfa_verify():
    """
    Verify an OTP.  On success, issue full JWT tokens.

    Body: { "mfa_token": "...", "code": "847392" }
    """
    data      = request.get_json() or {}
    mfa_token = data.get("mfa_token", "")
    code      = data.get("code", "").strip()

    user_id = _validate_mfa_token(mfa_token)
    if not user_id:
        return jsonify({"error": "Invalid or expired MFA session token."}), 401

    result = mfa.verify_otp(str(user_id), code, purpose="login")

    if result["success"]:
        user   = _get_user_by_id(user_id)
        tokens = jwt_mgr.create_tokens(user_id, user["username"])
        return jsonify({
            "success"      : True,
            "access_token" : tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "message"      : "MFA verified. Login successful.",
        }), 200

    return jsonify(result), 401


@app.route("/api/mfa/totp/setup", methods=["POST"])
def mfa_totp_setup():
    """
    Enrol a user in TOTP (authenticator app).  Call once per user.

    Body: { "mfa_token": "..." }   OR authenticated JWT
    Returns { "uri": "otpauth://...", "backup_codes": [...] }
    Caller must render `uri` as a QR code and show `backup_codes` once.
    """
    data      = request.get_json() or {}
    mfa_token = data.get("mfa_token", "")

    user_id = _validate_mfa_token(mfa_token) or _get_user_id_from_jwt()
    if not user_id:
        return jsonify({"error": "Authentication required."}), 401

    user = _get_user_by_id(user_id)
    info = mfa.totp_setup(user.get("email", str(user_id)))

    # Persist to DB (encrypt secret before storing in production)
    from database import save_totp_secret
    save_totp_secret(conn, user_id, info["secret"], info["backup_hashes"])

    return jsonify({
        "success"     : True,
        "uri"         : info["uri"],           # render as QR code
        "backup_codes": info["backup_codes"],  # show ONCE to user
        "message"     : "Scan the QR code with your authenticator app.",
    }), 200


@app.route("/api/mfa/totp/verify", methods=["POST"])
def mfa_totp_verify():
    """
    Verify a TOTP code from an authenticator app.  Issues JWT on success.

    Body: { "mfa_token": "...", "code": "123456" }
    """
    data      = request.get_json() or {}
    mfa_token = data.get("mfa_token", "")
    code      = data.get("code", "").strip()

    user_id = _validate_mfa_token(mfa_token)
    if not user_id:
        return jsonify({"error": "Invalid or expired MFA session token."}), 401

    from database import get_totp_secret
    row = get_totp_secret(conn, user_id)
    if not row or not row["totp_enabled"]:
        return jsonify({"error": "TOTP not set up for this account."}), 404

    # Used-codes set should be persisted per user; simplified here with in-memory set.
    # In production: load from Redis / DB, save back after verification.
    result = mfa.verify_totp(
        user_id    = str(user_id),
        secret     = row["encrypted_secret"],   # decrypt first in production
        code       = code,
    )

    if result["success"]:
        user   = _get_user_by_id(user_id)
        tokens = jwt_mgr.create_tokens(user_id, user["username"])
        return jsonify({
            "success"      : True,
            "access_token" : tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "message"      : "TOTP verified. Login successful.",
        }), 200

    return jsonify(result), 401


@app.route("/api/mfa/status", methods=["GET"])
def mfa_status():
    """
    OTP countdown metadata for UI (timer, attempts left).

    Query: ?mfa_token=<token>
    """
    mfa_token = request.args.get("mfa_token", "")
    user_id   = _validate_mfa_token(mfa_token)
    if not user_id:
        return jsonify({"error": "Invalid MFA token."}), 401

    status = mfa.otp_status(str(user_id))
    return jsonify(status or {"exists": False}), 200


# ─────────────────────────────────────────────────────────────────────────────
# Existing endpoints (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/refresh", methods=["POST"])
def refresh():
    data          = request.get_json() or {}
    refresh_token = data.get("refresh_token", "")
    result        = jwt_mgr.refresh_access_token(refresh_token)
    if result["success"]:
        return jsonify(result), 200
    return jsonify({"error": result["message"]}), 401


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status" : "healthy",
        "modules": {
            "jwt"     : "active",
            "ai"      : "active",
            "security": "active",
            "mfa"     : "active",   # ← new
        },
    }), 200


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _get_user(username: str) -> dict | None:
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username=%s AND is_active=TRUE", (username,))
    row = cursor.fetchone()
    cursor.close()
    return row


def _get_user_by_id(user_id: int) -> dict | None:
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE id=%s AND is_active=TRUE", (user_id,))
    row = cursor.fetchone()
    cursor.close()
    return row


def _verify_password(plain: str, hashed: str) -> bool:
    import bcrypt
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def _validate_mfa_token(token: str) -> int | None:
    """
    Validates a short-lived MFA-pending JWT.
    Returns the user_id on success, None otherwise.
    """
    if not token:
        return None
    result = jwt_mgr.verify_mfa_pending_token(token)
    return result.get("user_id") if result and result.get("valid") else None


def _get_user_id_from_jwt() -> int | None:
    """Extract user_id from Bearer token in Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    result = jwt_mgr.verify_access_token(auth[7:])
    return result.get("user_id") if result and result.get("valid") else None


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("SecureAuth starting — MFA module active")
    app.run(
        host  = os.getenv("FLASK_HOST", "0.0.0.0"),
        port  = int(os.getenv("FLASK_PORT", "5000")),
        debug = os.getenv("FLASK_DEBUG", "false").lower() == "true",
    )