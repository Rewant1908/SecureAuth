"""
src/database.py
──────────────────────────────────────────────────────────────────────────────
MariaDB connection + schema initialisation for SecureAuth.
CSE212 Cyber Security | Ahmedabad University

Original schema (Rewant): users, login_history, ai_metrics,
                           security_events, model_performance
MFA tables added (Ansh)  : mfa_otp_store, mfa_totp_secrets
──────────────────────────────────────────────────────────────────────────────
"""

import os
import mysql.connector
from mysql.connector import Error


def get_connection():
    """Return a MariaDB connection using .env values."""
    return mysql.connector.connect(
        host     = os.getenv("DB_HOST",     "localhost"),
        port     = int(os.getenv("DB_PORT", "3306")),
        user     = os.getenv("DB_USER",     "root"),
        password = os.getenv("DB_PASSWORD", ""),
        database = os.getenv("DB_NAME",     "secureauth"),
    )


def init_db(conn):
    """
    Initialise all tables.
    Safe to call on every startup (CREATE TABLE IF NOT EXISTS).
    """
    cursor = conn.cursor()

    # ── Original tables (Rewant) ───────────────────────────────────────────────

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INT AUTO_INCREMENT PRIMARY KEY,
            username      VARCHAR(100) UNIQUE NOT NULL,
            email         VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login    TIMESTAMP NULL,
            is_active     BOOLEAN DEFAULT TRUE,
            INDEX idx_username (username),
            INDEX idx_email    (email)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_history (
            id             INT AUTO_INCREMENT PRIMARY KEY,
            user_id        INT NOT NULL,
            ip_address     VARCHAR(45),
            user_agent     TEXT,
            timestamp      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            success        BOOLEAN,
            risk_score     FLOAT,
            risk_level     VARCHAR(20),
            action_taken   VARCHAR(50),
            ai_explanation TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_user_id   (user_id),
            INDEX idx_ip        (ip_address),
            INDEX idx_timestamp (timestamp)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ai_metrics (
            id            INT AUTO_INCREMENT PRIMARY KEY,
            user_id       INT NOT NULL,
            model_version VARCHAR(50),
            features      JSON,
            risk_score    FLOAT,
            confidence    FLOAT,
            timestamp     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_user_id (user_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id           INT AUTO_INCREMENT PRIMARY KEY,
            user_id      INT,
            event_type   VARCHAR(50),
            ip_address   VARCHAR(45),
            details      TEXT,
            severity     VARCHAR(20),
            timestamp    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_user_id    (user_id),
            INDEX idx_event_type (event_type),
            INDEX idx_timestamp  (timestamp)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS model_performance (
            id           INT AUTO_INCREMENT PRIMARY KEY,
            model_name   VARCHAR(100),
            accuracy     FLOAT,
            false_pos    FLOAT,
            true_pos     FLOAT,
            trained_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            sample_count INT
        )
    """)

    # ── MFA tables (Ansh – AU2320008) ─────────────────────────────────────────

    # Stores active email/SMS OTPs.
    # NOTE: In-memory OTPManager handles real-time checks;
    #       this table provides persistence across restarts and audit logs.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mfa_otp_store (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            user_id     INT NOT NULL,
            purpose     VARCHAR(50)  NOT NULL DEFAULT 'login',
            hashed_otp  VARCHAR(64)  NOT NULL,          -- SHA-256 hex
            expires_at  TIMESTAMP    NOT NULL,
            used        BOOLEAN      DEFAULT FALSE,
            attempts    TINYINT      DEFAULT 0,
            created_at  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_user_purpose  (user_id, purpose),
            INDEX idx_expires       (expires_at)
        )
    """)

    # Stores per-user TOTP secrets and backup-code hashes.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mfa_totp_secrets (
            id               INT AUTO_INCREMENT PRIMARY KEY,
            user_id          INT          NOT NULL UNIQUE,
            encrypted_secret TEXT         NOT NULL,   -- AES-encrypted Base32 secret
            backup_hashes    JSON         NOT NULL,   -- list of SHA-256 hashed backup codes
            totp_enabled     BOOLEAN      DEFAULT TRUE,
            enrolled_at      TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
            last_used_at     TIMESTAMP    NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_user_id (user_id)
        )
    """)

    conn.commit()
    cursor.close()
    print("[DB] All tables initialised (including MFA tables).")


# ── MFA DB helpers ────────────────────────────────────────────────────────────
# These are thin wrappers — MFAService (in-memory) is the source of truth
# during a request; these persist state across restarts and provide audit logs.

def save_otp_record(conn, user_id: int, purpose: str, hashed_otp: str, expires_at) -> None:
    """Persist an OTP record (called by MFAService after generation)."""
    cursor = conn.cursor()
    # Invalidate any existing active OTP for this user+purpose first
    cursor.execute(
        "UPDATE mfa_otp_store SET used=TRUE WHERE user_id=%s AND purpose=%s AND used=FALSE",
        (user_id, purpose),
    )
    cursor.execute(
        "INSERT INTO mfa_otp_store (user_id, purpose, hashed_otp, expires_at) VALUES (%s, %s, %s, %s)",
        (user_id, purpose, hashed_otp, expires_at),
    )
    conn.commit()
    cursor.close()


def mark_otp_used(conn, user_id: int, purpose: str) -> None:
    """Mark the latest OTP for this user+purpose as used."""
    cursor = conn.cursor()
    cursor.execute(
        """UPDATE mfa_otp_store SET used=TRUE
           WHERE user_id=%s AND purpose=%s AND used=FALSE
           ORDER BY created_at DESC LIMIT 1""",
        (user_id, purpose),
    )
    conn.commit()
    cursor.close()


def save_totp_secret(conn, user_id: int, encrypted_secret: str, backup_hashes: list) -> None:
    """Insert or update a user's TOTP secret."""
    import json
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO mfa_totp_secrets (user_id, encrypted_secret, backup_hashes)
           VALUES (%s, %s, %s)
           ON DUPLICATE KEY UPDATE
               encrypted_secret = VALUES(encrypted_secret),
               backup_hashes    = VALUES(backup_hashes),
               enrolled_at      = CURRENT_TIMESTAMP""",
        (user_id, encrypted_secret, json.dumps(backup_hashes)),
    )
    conn.commit()
    cursor.close()


def get_totp_secret(conn, user_id: int) -> dict | None:
    """Fetch a user's TOTP secret row."""
    import json
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT encrypted_secret, backup_hashes, totp_enabled FROM mfa_totp_secrets WHERE user_id=%s",
        (user_id,),
    )
    row = cursor.fetchone()
    cursor.close()
    if row:
        row["backup_hashes"] = json.loads(row["backup_hashes"])
    return row


def remove_backup_hash(conn, user_id: int, matched_hash: str) -> None:
    """Remove a used backup code hash from the DB."""
    import json
    row = get_totp_secret(conn, user_id)
    if not row:
        return
    updated = [h for h in row["backup_hashes"] if h != matched_hash]
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE mfa_totp_secrets SET backup_hashes=%s WHERE user_id=%s",
        (json.dumps(updated), user_id),
    )
    conn.commit()
    cursor.close()