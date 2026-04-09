import importlib.util
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from flask_cors import CORS
import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import jwt
import pymysql
from flask import Flask, g, jsonify, request

from adaptive.adaptive_auth import AdaptiveAuthenticator
from database import (
    get_connection,
    get_totp_secret,
    init_database,
    remove_backup_hash,
    save_totp_secret,
)
from jwt_handler.jwt_manager import JWTHandler
from mfa import MFAService
from mfa.email_otp import EmailOTPSender, MockEmailOTPSender
from mfa.sms_otp import MockSMSOTPSender, SMSOTPSender
from security.security_protection import SecurityProtection
from security.active_defense import active_defense_bp, start_active_defense_fuzzer


def _load_auth_package():
    package_dir = Path(__file__).resolve().parent / "RBAC & Sessions"
    init_file = package_dir / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        "rbac_sessions",
        init_file,
        submodule_search_locations=[str(package_dir)],
    )

    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load RBAC package from {package_dir}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


auth_package = _load_auth_package()
RBACManager = auth_package.RBACManager
SessionManager = auth_package.SessionManager
require_active_session = auth_package.require_active_session
require_permission = auth_package.require_permission


app = Flask(__name__)
CORS(app)
@app.route("/create-user")
def create_user():
    conn = get_connection()
    cursor = conn.cursor()

    ph = PasswordHasher()

    username = "admin"
    email = "admin@test.com"
    password = "admin123"

    hashed = ph.hash(password)

    try:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, is_active) VALUES (%s, %s, %s, 1)",
            (username, email, hashed)
        )
        conn.commit()
        return "User created: admin / admin123"
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        conn.close()
app.register_blueprint(active_defense_bp)
MFA_TOKEN_MINUTES = int(os.getenv("MFA_TOKEN_MINUTES", "10"))


def _build_mfa_service():
    email_sender = (
        EmailOTPSender(
            smtp_host=os.getenv("SMTP_HOST", "smtp.gmail.com"),
            smtp_port=int(os.getenv("SMTP_PORT", "587")),
            username=os.getenv("SMTP_USER", ""),
            password=os.getenv("SMTP_PASSWORD", ""),
            sender_name=os.getenv("SMTP_SENDER_NAME", "SecureAuth"),
        )
        if os.getenv("SMTP_USER")
        else MockEmailOTPSender()
    )

    sms_sender = (
        SMSOTPSender(
            account_sid=os.getenv("TWILIO_ACCOUNT_SID", ""),
            auth_token=os.getenv("TWILIO_AUTH_TOKEN", ""),
            from_number=os.getenv("TWILIO_FROM_NUMBER", ""),
        )
        if os.getenv("TWILIO_ACCOUNT_SID")
        else MockSMSOTPSender()
    )

    return MFAService(
        email_sender=email_sender,
        sms_sender=sms_sender,
        issuer=os.getenv("MFA_ISSUER", "SecureAuth"),
        otp_expiry=int(os.getenv("MFA_OTP_EXPIRY", "300")),
        otp_digits=int(os.getenv("MFA_OTP_DIGITS", "6")),
        max_attempts=int(os.getenv("MFA_MAX_ATTEMPTS", "3")),
    )


mfa_service = _build_mfa_service()


def _bootstrap_application():
    init_database()

    conn = get_connection()
    try:
        RBACManager(conn).initialize_default_roles_and_permissions()
    finally:
        conn.close()


_bootstrap_application()
start_active_defense_fuzzer()


@app.route("/")
def home():
    return "SecureAuth API running"


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    ip_address = request.remote_addr or data.get("ip_address") or "unknown"
    user_agent = (request.headers.get("User-Agent") or "")[:255]

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    conn = get_connection()
    try:
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute(
            "SELECT * FROM users WHERE username = %s AND is_active = 1",
            (username,),
        )
        user = cursor.fetchone()

        security = SecurityProtection(conn)
        is_locked, unlock_time = security.check_brute_force(username, ip_address)
        if is_locked:
            return jsonify(
                {"error": "Account locked", "unlock_time": unlock_time}
            ), 403

        if not user:
            security.record_login_attempt(
                None,
                username,
                ip_address,
                user_agent,
                False,
                "Invalid username",
            )
            return jsonify({"error": "Invalid credentials"}), 401

        stored_hash = user["password_hash"]
        password_verified = False
        
        if stored_hash.startswith("$2"):  # Old bcrypt hashes
            password_verified = bcrypt.checkpw(password.encode(), stored_hash.encode())
            if password_verified:
                # Upgrade transparently to Argon2id
                ph = PasswordHasher()
                new_hash = ph.hash(password)
                cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, user["id"]))
                conn.commit()
        else:
            try:
                ph = PasswordHasher()
                ph.verify(stored_hash, password)
                password_verified = True
                if ph.check_needs_rehash(stored_hash):
                    new_hash = ph.hash(password)
                    cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, user["id"]))
                    conn.commit()
            except VerifyMismatchError:
                password_verified = False
            except Exception:
                password_verified = False

        if not password_verified:
            security.record_login_attempt(
                user["id"],
                username,
                ip_address,
                user_agent,
                False,
                "Invalid password",
            )
            return jsonify({"error": "Invalid credentials"}), 401

        now = datetime.now()
        login_data = {
            "hour": now.hour,
            "day_of_week": now.weekday(),
            "location_changed": bool(data.get("location_changed", False)),
            "device_changed": bool(data.get("device_changed", False)),
            "hours_since_last": _get_hours_since_last_login(conn, user["id"]),
            "unusual_hour": now.hour < 6 or now.hour > 22,
        }

        adaptive = AdaptiveAuthenticator(conn)
        risk_score, risk_level, is_anomaly = adaptive.analyze_login_attempt(
            user["id"], login_data
        )

        if risk_score >= 70:
            security.record_login_attempt(
                user["id"],
                username,
                ip_address,
                user_agent,
                False,
                "High risk login blocked",
            )
            security.log_security_event(
                user["id"],
                "blocked_login",
                "high",
                f"Blocked suspicious login for {username} (risk={risk_score}, anomaly={is_anomaly})",
                ip_address,
            )
            return jsonify(
                {
                    "error": "High risk login blocked",
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "is_anomaly": is_anomaly,
                }
            ), 403

        mfa_method, destination = _resolve_mfa_challenge(conn, user)
        if risk_score >= 40:
            mfa_token = _generate_mfa_token(user["id"], user.get("role", "user"))

            if mfa_method == "totp":
                security.log_security_event(
                    user["id"],
                    "mfa_required",
                    "medium",
                    "Medium-risk login requires TOTP verification",
                    ip_address,
                )
                return jsonify(
                    {
                        "message": "MFA required",
                        "mfa_required": True,
                        "mfa_method": "totp",
                        "mfa_token": mfa_token,
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                    }
                ), 200

            if not mfa_method or not destination:
                return jsonify(
                    {
                        "error": "MFA required but no delivery method is configured for this user",
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                    }
                ), 500

            send_result = mfa_service.send_otp(
                str(user["id"]),
                method=mfa_method,
                purpose="login",
                destination=destination,
            )

            if send_result["success"]:
                security.log_security_event(
                    user["id"],
                    "mfa_required",
                    "medium",
                    f"Medium-risk login requires {mfa_method} OTP verification",
                    ip_address,
                )

            return jsonify(
                {
                    "message": "MFA required",
                    "mfa_required": True,
                    "mfa_method": mfa_method,
                    "mfa_token": mfa_token,
                    "otp_sent": send_result["success"],
                    "delivery_message": send_result["message"],
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                }
            ), 200

        security.record_login_attempt(
            user["id"],
            username,
            ip_address,
            user_agent,
            True,
        )
        security.reset_failed_attempts(username)
        _update_last_login(conn, user["id"])

        auth_response = _issue_session_tokens(conn, user)
        auth_response.update(
            {
                "status": "success",
                "message": "Login successful",
                "risk_score": risk_score,
                "risk_level": risk_level,
                "roles": _get_user_role_names(conn, user["id"], user.get("role")),
            }
        )
        return jsonify(auth_response), 200
    finally:
        conn.close()


@app.route("/api/mfa/send", methods=["POST"])
def send_mfa_code():
    data = request.get_json(silent=True) or {}
    mfa_token = data.get("mfa_token") or ""
    requested_method = data.get("method")

    payload = _verify_mfa_token(mfa_token)
    if not payload:
        return jsonify({"error": "Invalid or expired MFA token"}), 401

    conn = get_connection()
    try:
        user = _get_user_by_id(conn, payload["user_id"])
        if not user:
            return jsonify({"error": "User not found"}), 404

        method, destination = _resolve_mfa_challenge(conn, user, requested_method)
        if method == "totp":
            return jsonify({"error": "Use /api/mfa/totp/verify for TOTP challenges"}), 400

        if not method or not destination:
            return jsonify({"error": "No MFA delivery destination available"}), 400

        result = mfa_service.send_otp(
            str(user["id"]),
            method=method,
            purpose="login",
            destination=destination,
        )
        return jsonify({"mfa_method": method, **result}), 200 if result["success"] else 429
    finally:
        conn.close()


@app.route("/api/mfa/verify", methods=["POST"])
def verify_mfa_code():
    data = request.get_json(silent=True) or {}
    mfa_token = data.get("mfa_token") or ""
    code = (data.get("code") or "").strip()

    payload = _verify_mfa_token(mfa_token)
    if not payload:
        return jsonify({"error": "Invalid or expired MFA token"}), 401

    if not code:
        return jsonify({"error": "OTP code is required"}), 400

    conn = get_connection()
    try:
        user = _get_user_by_id(conn, payload["user_id"])
        if not user:
            return jsonify({"error": "User not found"}), 404

        result = mfa_service.verify_otp(str(user["id"]), code, purpose="login")
        if not result["success"]:
            return jsonify(result), 401

        security = SecurityProtection(conn)
        security.record_login_attempt(
            user["id"],
            user["username"],
            request.remote_addr or "unknown",
            (request.headers.get("User-Agent") or "")[:255],
            True,
        )
        security.reset_failed_attempts(user["username"])
        _update_last_login(conn, user["id"])

        auth_response = _issue_session_tokens(conn, user)
        auth_response.update(
            {
                "success": True,
                "message": "MFA verified. Login successful",
                "roles": _get_user_role_names(conn, user["id"], user.get("role")),
            }
        )
        return jsonify(auth_response), 200
    finally:
        conn.close()


@app.route("/api/mfa/totp/setup", methods=["POST"])
def setup_totp():
    data = request.get_json(silent=True) or {}
    mfa_token = data.get("mfa_token") or ""

    payload = _verify_mfa_token(mfa_token) or _get_bearer_payload()
    if not payload:
        return jsonify({"error": "Authentication required"}), 401

    conn = get_connection()
    try:
        user = _get_user_by_id(conn, payload["user_id"])
        if not user:
            return jsonify({"error": "User not found"}), 404

        account_name = user.get("email") or user["username"]
        totp_info = mfa_service.totp_setup(account_name)
        save_totp_secret(
            conn,
            user["id"],
            totp_info["secret"],
            totp_info["backup_hashes"],
        )

        return jsonify(
            {
                "success": True,
                "uri": totp_info["uri"],
                "backup_codes": totp_info["backup_codes"],
                "message": "Scan the QR URI with your authenticator app and store the backup codes safely",
            }
        ), 200
    finally:
        conn.close()


@app.route("/api/mfa/totp/verify", methods=["POST"])
def verify_totp():
    data = request.get_json(silent=True) or {}
    mfa_token = data.get("mfa_token") or ""
    code = (data.get("code") or "").strip()
    backup_code = (data.get("backup_code") or "").strip()

    payload = _verify_mfa_token(mfa_token) or _get_bearer_payload()
    if not payload:
        return jsonify({"error": "Authentication required"}), 401

    conn = get_connection()
    try:
        user = _get_user_by_id(conn, payload["user_id"])
        if not user:
            return jsonify({"error": "User not found"}), 404

        totp_record = get_totp_secret(conn, user["id"])
        if not totp_record or not totp_record.get("totp_enabled"):
            return jsonify({"error": "TOTP is not enabled for this user"}), 404

        if backup_code:
            result = mfa_service.verify_backup_code(
                user.get("email") or user["username"],
                backup_code,
                totp_record["backup_hashes"],
            )
            if not result["success"]:
                return jsonify(result), 401

            remove_backup_hash(conn, user["id"], result["matched_hash"])
        else:
            if not code:
                return jsonify({"error": "TOTP code is required"}), 400

            result = mfa_service.verify_totp(
                user.get("email") or user["username"],
                totp_record["encrypted_secret"],
                code,
            )
            if not result["success"]:
                return jsonify(result), 401

        security = SecurityProtection(conn)
        security.record_login_attempt(
            user["id"],
            user["username"],
            request.remote_addr or "unknown",
            (request.headers.get("User-Agent") or "")[:255],
            True,
        )
        security.reset_failed_attempts(user["username"])
        _update_last_login(conn, user["id"])

        auth_response = _issue_session_tokens(conn, user)
        auth_response.update(
            {
                "success": True,
                "message": "TOTP verified. Login successful",
                "roles": _get_user_role_names(conn, user["id"], user.get("role")),
            }
        )
        return jsonify(auth_response), 200
    finally:
        conn.close()


@app.route("/api/mfa/status", methods=["GET"])
def mfa_status():
    payload = _verify_mfa_token(request.args.get("mfa_token") or "")
    if not payload:
        return jsonify({"error": "Invalid or expired MFA token"}), 401

    status = mfa_service.otp_status(str(payload["user_id"])) or {"exists": False}
    return jsonify(status), 200


@app.route("/api/refresh", methods=["POST"])
def refresh():
    data = request.get_json(silent=True) or {}
    refresh_token = data.get("refresh_token") or ""

    if not refresh_token:
        return jsonify({"error": "Refresh token is required"}), 400

    conn = get_connection()
    try:
        session_manager = SessionManager(conn)
        session = session_manager.validate_refresh_token(refresh_token)
        payload = JWTHandler.verify_token(refresh_token)

        if not session or not payload:
            return jsonify({"error": "Invalid or expired refresh token"}), 401

        user = _get_user_by_id(conn, payload["user_id"])
        if not user:
            return jsonify({"error": "User not found"}), 404

        new_access_token = JWTHandler.generate_access_token(
            user["id"],
            user.get("role", "user"),
            session_id=session["session_id"],
        )
        new_refresh_token = JWTHandler.generate_refresh_token(user["id"])
        session_manager.rotate_refresh_token(refresh_token, new_refresh_token)

        return jsonify(
            {
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "session_id": session["session_id"],
            }
        ), 200
    finally:
        conn.close()


@app.route("/api/logout", methods=["POST"])
def logout():
    data = request.get_json(silent=True) or {}
    refresh_token = data.get("refresh_token") or ""

    if not refresh_token:
        return jsonify({"error": "Refresh token is required to logout"}), 400

    conn = get_connection()
    try:
        session_manager = SessionManager(conn)
        session = session_manager.validate_refresh_token(refresh_token)
        if not session:
            return jsonify({"error": "Invalid or expired refresh token"}), 401

        session_manager.invalidate_session(session["session_id"])
        return jsonify({"success": True, "message": "Session logged out"}), 200
    finally:
        conn.close()


@app.route("/api/webauthn/register", methods=["POST"])
def webauthn_register():
    # Placeholder for FIDO2 WebAuthn credential creation options
    return jsonify({"error": "Not implemented - Requires FIDO2 JS framework"}), 501

@app.route("/api/webauthn/authenticate", methods=["POST"])
def webauthn_authenticate():
    # Placeholder for FIDO2 WebAuthn assertion options
    return jsonify({"error": "Not implemented - Requires FIDO2 JS framework"}), 501


@app.route("/api/sessions", methods=["GET"])
@require_active_session
def get_sessions():
    conn = get_connection()
    try:
        sessions = SessionManager(conn).get_user_active_sessions(g.user_id)
        return jsonify({"count": len(sessions), "sessions": sessions}), 200
    finally:
        conn.close()


@app.route("/api/admin/security-events", methods=["GET"])
@require_permission("view_security_events")
def get_security_events():
    hours = request.args.get("hours", "24")
    severity = request.args.get("severity")

    try:
        hours = max(1, int(hours))
    except ValueError:
        return jsonify({"error": "hours must be an integer"}), 400

    conn = get_connection()
    try:
        events = SecurityProtection(conn).get_recent_security_events(
            hours=hours,
            severity=severity,
        )
        return jsonify({"count": len(events), "events": events}), 200
    finally:
        conn.close()


def _get_user_by_id(conn, user_id):
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute("SELECT * FROM users WHERE id = %s AND is_active = 1", (user_id,))
    return cursor.fetchone()


def _get_hours_since_last_login(conn, user_id):
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute(
        """
        SELECT timestamp
        FROM login_attempts
        WHERE user_id = %s AND success = 1
        ORDER BY timestamp DESC
        LIMIT 1
        """,
        (user_id,),
    )
    row = cursor.fetchone()

    if not row or not row["timestamp"]:
        return 24

    delta = datetime.utcnow() - row["timestamp"]
    return max(1, min(int(delta.total_seconds() // 3600), 168))


def _update_last_login(conn, user_id):
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s",
        (user_id,),
    )
    conn.commit()


def _issue_session_tokens(conn, user):
    refresh_token = JWTHandler.generate_refresh_token(user["id"])
    session_id = SessionManager(conn).create_session(
        user["id"],
        refresh_token,
        request.remote_addr or "unknown",
        (request.headers.get("User-Agent") or "")[:255],
    )
    access_token = JWTHandler.generate_access_token(
        user["id"],
        user.get("role", "user"),
        session_id=session_id,
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "session_id": session_id,
    }


def _generate_mfa_token(user_id, role):
    payload = {
        "user_id": user_id,
        "role": role,
        "scope": "mfa_pending",
        "exp": datetime.utcnow() + timedelta(minutes=MFA_TOKEN_MINUTES),
    }
    return jwt.encode(
        payload,
        JWTHandler.SECRET_KEY,
        algorithm=JWTHandler.ALGORITHM,
    )


def _verify_mfa_token(token):
    if not token:
        return None

    try:
        payload = jwt.decode(
            token,
            JWTHandler.SECRET_KEY,
            algorithms=[JWTHandler.ALGORITHM],
        )
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

    if payload.get("scope") != "mfa_pending":
        return None

    return payload


def _get_bearer_payload():
    auth_header = request.headers.get("Authorization") or ""
    if not auth_header.startswith("Bearer "):
        return None

    return JWTHandler.verify_token(auth_header.split(" ", 1)[1])


def _resolve_mfa_challenge(conn, user, requested_method=None):
    totp_record = get_totp_secret(conn, user["id"])
    if requested_method == "totp" and totp_record and totp_record.get("totp_enabled"):
        return "totp", None

    if requested_method in {"email", "sms"}:
        method = requested_method
    else:
        preferred = (user.get("preferred_mfa") or "email").lower()
        if preferred == "sms" and user.get("phone"):
            method = "sms"
        else:
            method = "email"

    if method == "email" and user.get("email"):
        return "email", user["email"]

    if method == "sms" and user.get("phone"):
        return "sms", user["phone"]

    if totp_record and totp_record.get("totp_enabled"):
        return "totp", None

    if user.get("email"):
        return "email", user["email"]

    if user.get("phone"):
        return "sms", user["phone"]

    return None, None


def _get_user_role_names(conn, user_id, fallback_role=None):
    roles = RBACManager(conn).get_user_roles(user_id)
    role_names = [role["name"] for role in roles if role.get("name")]

    if role_names:
        return role_names

    return [fallback_role] if fallback_role else []


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify(
        {
            "status": "healthy",
            "modules": {
                "jwt": "active",
                "adaptive_auth": "active",
                "security": "active",
                "mfa": "active",
                "rbac": "active",
                "abac": "active",
                "sessions": "active",
                "active_defense": "active",
                "argon2id": "active",
                "tarpitting": "active",
                "adversarial_ml": "active",
            },
        }
    ), 200


if __name__ == "__main__":
    app.run(port=5000, debug=True)
