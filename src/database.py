"""
Database configuration and connection manager for SecureAuth.
"""

import json
import os

import pymysql
from dotenv import load_dotenv
from pymysql.cursors import DictCursor

load_dotenv()


DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "secureauth_user"),
    "password": os.getenv("DB_PASSWORD", "SecurePass123!"),
    "database": os.getenv("DB_NAME", "secureauth_db"),
    "charset": "utf8mb4",
    "cursorclass": DictCursor,
}


def get_connection():
    try:
        return pymysql.connect(**DB_CONFIG)
    except pymysql.Error as exc:
        print(f"Database connection failed: {exc}")
        raise


def test_connection():
    try:
        conn = get_connection()
        conn.close()
        print("Database connection successful")
        return True
    except Exception:
        print("Database connection failed")
        return False


def init_database():
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(20) DEFAULT 'user',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME NULL,
                is_active TINYINT DEFAULT 1,
                INDEX idx_username (username),
                INDEX idx_email (email)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        _add_column_if_missing(cursor, "users", "phone", "VARCHAR(20) NULL")
        _add_column_if_missing(
            cursor,
            "users",
            "preferred_mfa",
            "VARCHAR(10) DEFAULT 'email'",
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                username VARCHAR(50),
                ip_address VARCHAR(50),
                user_agent VARCHAR(255),
                success TINYINT DEFAULT 0,
                failure_reason VARCHAR(255),
                risk_score FLOAT DEFAULT 0,
                predicted_anomaly TINYINT DEFAULT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_id (user_id),
                INDEX idx_username (username),
                INDEX idx_ip_address (ip_address),
                INDEX idx_timestamp (timestamp)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS behavior_patterns (
                user_id INT PRIMARY KEY,
                typical_login_hours TEXT,
                typical_locations TEXT,
                typical_devices TEXT,
                average_session_duration INT DEFAULT 30,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                id INT AUTO_INCREMENT PRIMARY KEY,
                event_type VARCHAR(50),
                user_id INT,
                ip_address VARCHAR(50),
                description TEXT,
                details TEXT,
                severity VARCHAR(20),
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_event_type (event_type),
                INDEX idx_timestamp (timestamp),
                INDEX idx_severity (severity)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS ai_metrics (
                id INT AUTO_INCREMENT PRIMARY KEY,
                date DATE NOT NULL,
                total_predictions INT DEFAULT 0,
                true_positives INT DEFAULT 0,
                false_positives INT DEFAULT 0,
                true_negatives INT DEFAULT 0,
                false_negatives INT DEFAULT 0,
                precision_score FLOAT DEFAULT 0,
                recall_score FLOAT DEFAULT 0,
                f1_score FLOAT DEFAULT 0,
                accuracy FLOAT DEFAULT 0,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_date (date)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS mfa_otp_store (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                purpose VARCHAR(50) NOT NULL DEFAULT 'login',
                hashed_otp VARCHAR(64) NOT NULL,
                expires_at DATETIME NOT NULL,
                used TINYINT DEFAULT 0,
                attempts TINYINT DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_mfa_otp_user_purpose (user_id, purpose),
                INDEX idx_mfa_otp_expires (expires_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS mfa_totp_secrets (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL UNIQUE,
                encrypted_secret TEXT NOT NULL,
                backup_hashes JSON NOT NULL,
                totp_enabled TINYINT DEFAULT 1,
                enrolled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used_at DATETIME NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_mfa_totp_user (user_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS roles (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(50) NOT NULL UNIQUE,
                description TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_roles_name (name)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS permissions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100) NOT NULL UNIQUE,
                description TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_permissions_name (name)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS user_roles (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                role_id INT NOT NULL,
                assigned_by INT NULL,
                assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_user_role (user_id, role_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
                FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE SET NULL,
                INDEX idx_user_roles_user (user_id),
                INDEX idx_user_roles_role (role_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS role_permissions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                role_id INT NOT NULL,
                permission_id INT NOT NULL,
                assigned_by INT NULL,
                assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_role_permission (role_id, permission_id),
                FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
                FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
                FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE SET NULL,
                INDEX idx_role_permissions_role (role_id),
                INDEX idx_role_permissions_permission (permission_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id VARCHAR(128) PRIMARY KEY,
                user_id INT NOT NULL,
                refresh_token_hash VARCHAR(64) NOT NULL,
                ip_address VARCHAR(50),
                user_agent VARCHAR(255),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                is_active TINYINT DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE KEY uniq_refresh_token_hash (refresh_token_hash),
                INDEX idx_sessions_user (user_id),
                INDEX idx_sessions_active (is_active),
                INDEX idx_sessions_expires (expires_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS abac_policies (
                id INT AUTO_INCREMENT PRIMARY KEY,
                role_id INT NULL,
                user_id INT NULL,
                resource_type VARCHAR(100) NOT NULL,
                action VARCHAR(100) NOT NULL,
                environment_conditions JSON,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_abac_resource (resource_type)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS honeypot_events (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(50) NOT NULL,
                user_agent VARCHAR(255),
                endpoint_hit VARCHAR(255) NOT NULL,
                payload_dump TEXT,
                severity VARCHAR(20) DEFAULT 'CRITICAL',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_honeypot_ip (ip_address)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )

        conn.commit()
        print("All database tables initialized, including MFA, RBAC, ABAC, Honeypots, and sessions.")
    finally:
        cursor.close()
        conn.close()


def _add_column_if_missing(cursor, table_name, column_name, definition):
    cursor.execute(
        """
        SELECT COUNT(*) AS count
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_NAME = %s
        """,
        (DB_CONFIG["database"], table_name, column_name),
    )
    result = cursor.fetchone()

    if result and result["count"] == 0:
        cursor.execute(
            f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}"
        )


def save_otp_record(conn, user_id, purpose, hashed_otp, expires_at):
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE mfa_otp_store
        SET used = 1
        WHERE user_id = %s AND purpose = %s AND used = 0
        """,
        (user_id, purpose),
    )
    cursor.execute(
        """
        INSERT INTO mfa_otp_store (user_id, purpose, hashed_otp, expires_at)
        VALUES (%s, %s, %s, %s)
        """,
        (user_id, purpose, hashed_otp, expires_at),
    )
    conn.commit()
    cursor.close()


def mark_otp_used(conn, user_id, purpose):
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE mfa_otp_store
        SET used = 1
        WHERE user_id = %s AND purpose = %s AND used = 0
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (user_id, purpose),
    )
    conn.commit()
    cursor.close()


def save_totp_secret(conn, user_id, encrypted_secret, backup_hashes):
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO mfa_totp_secrets (user_id, encrypted_secret, backup_hashes)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE
            encrypted_secret = VALUES(encrypted_secret),
            backup_hashes = VALUES(backup_hashes),
            totp_enabled = 1,
            enrolled_at = CURRENT_TIMESTAMP
        """,
        (user_id, encrypted_secret, json.dumps(backup_hashes)),
    )
    conn.commit()
    cursor.close()


def get_totp_secret(conn, user_id):
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT encrypted_secret, backup_hashes, totp_enabled, enrolled_at, last_used_at
        FROM mfa_totp_secrets
        WHERE user_id = %s
        """,
        (user_id,),
    )
    row = cursor.fetchone()
    cursor.close()

    if not row:
        return None

    if isinstance(row["backup_hashes"], str):
        row["backup_hashes"] = json.loads(row["backup_hashes"])
    return row


def remove_backup_hash(conn, user_id, matched_hash):
    row = get_totp_secret(conn, user_id)
    if not row:
        return

    updated_hashes = [item for item in row["backup_hashes"] if item != matched_hash]
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE mfa_totp_secrets
        SET backup_hashes = %s, last_used_at = CURRENT_TIMESTAMP
        WHERE user_id = %s
        """,
        (json.dumps(updated_hashes), user_id),
    )
    conn.commit()
    cursor.close()


if __name__ == "__main__":
    print("=" * 60)
    print("Database Connection Test")
    print("=" * 60)
    test_connection()
    init_database()
