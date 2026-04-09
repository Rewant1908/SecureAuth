#!/usr/bin/env python3
import pymysql
from argon2 import PasswordHasher

DB_HOST = "localhost"
DB_USER = "secureauth_user"
DB_PASSWORD = "SecurePass123!"
DB_NAME = "secureauth_db"

def reset_database():
    try:
        conn = pymysql.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor()

        print("Resetting database...")

        cursor.execute("DELETE FROM login_attempts")
        print("Cleared login_attempts")

        cursor.execute("DELETE FROM failed_login_attempts")
        print("Cleared failed_login_attempts")

        cursor.execute("DELETE FROM sessions")
        print("Cleared sessions")

        cursor.execute("UPDATE users SET last_login = NULL")
        print("Reset last_login")

        cursor.execute("SELECT * FROM users WHERE username = %s", ("admin",))
        admin = cursor.fetchone()

        if not admin:
            print("Creating admin user...")
            ph = PasswordHasher()
            hashed = ph.hash("admin123")
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, is_active) VALUES (%s, %s, %s, 1)",
                ("admin", "admin@test.com", hashed)
            )

        conn.commit()
        conn.close()

        print("\nDATABASE RESET COMPLETE")
        print("Username: admin")
        print("Password: admin123")

    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    reset_database()