from flask import Flask, request, jsonify
from database import get_connection
from jwt_handler.jwt_manager import JWTHandler
from adaptive.adaptive_auth import AdaptiveAuthenticator
from security.security_protection import SecurityProtection
import bcrypt
import datetime
import pymysql

app = Flask(__name__)

@app.route('/')
def home():
    return "SecureAuth API running"


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")
    ip = request.remote_addr

    # DB connection
    conn = get_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    # Check if user exists
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Security check
    security = SecurityProtection(conn)
    is_locked, unlock_time = security.check_brute_force(username, ip)

    if is_locked:
        return jsonify({"error": "Account locked"}), 403

    # Password check
    stored_hash = user['password_hash']

    if not bcrypt.checkpw(password.encode(), stored_hash.encode()):
        return jsonify({"error": "Invalid credentials"}), 401

    # AI Risk Analysis
    adaptive = AdaptiveAuthenticator(conn)

    login_data = {
        "hour": datetime.datetime.now().hour,
        "day": datetime.datetime.now().weekday(),
        "ip_changed": False,
        "device_changed": False,
        "time_since_last_login": 1
    }

    risk_score, risk_level, is_anomaly = adaptive.analyze_login_attempt(
        user['id'], login_data
    )

    # Decision
    if risk_score > 70:
        return jsonify({"error": "High risk login blocked"}), 403

    if risk_score > 40:
        return jsonify({
            "message": "MFA required",
            "risk_score": risk_score
        }), 200

    # Generate tokens
    access_token = JWTHandler.generate_access_token(user['id'], user['role'])
    refresh_token = JWTHandler.generate_refresh_token(user['id'])

    return jsonify({
        "status": "success",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "risk_score": risk_score
    })


if __name__ == '__main__':
    app.run(port=5000, debug=True)