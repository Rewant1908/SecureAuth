"""
Database Configuration and Connection Manager
SecureAuth Project

Author: Rewant
Course: CSE212 Cyber Security
"""

import pymysql
from pymysql.cursors import DictCursor

# ============================================================
# Database Configuration
# ============================================================

DB_CONFIG = {
    'host': 'localhost',
    'user': 'secureauth_user',
    'password': 'SecurePass123!',
    'database': 'secureauth_db',
    'charset': 'utf8mb4',
    'cursorclass': DictCursor
}


def get_connection():
    """
    Get a new database connection
    
    Returns:
        pymysql connection object
    """
    try:
        conn = pymysql.connect(**DB_CONFIG)
        return conn
    except pymysql.Error as e:
        print(f"✗ Database connection failed: {e}")
        raise


def test_connection():
    """
    Test if database connection works
    
    Returns:
        True if connected, False if failed
    """
    try:
        conn = get_connection()
        conn.close()
        print("✓ Database connection successful")
        return True
    except:
        print("✗ Database connection failed")
        return False


def init_database():
    """
    Initialize all required database tables
    Creates tables if they don't exist
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(20) DEFAULT 'user',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_active TINYINT DEFAULT 1
        )
    """)

    # Login attempts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            username VARCHAR(50),
            ip_address VARCHAR(50),
            user_agent VARCHAR(255),
            success TINYINT DEFAULT 0,
            failure_reason VARCHAR(255),
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Behavior patterns table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS behavior_patterns (
            user_id INT PRIMARY KEY,
            typical_login_hours TEXT,
            typical_locations TEXT,
            typical_devices TEXT,
            average_session_duration INT DEFAULT 30,
            last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Security events table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INT AUTO_INCREMENT PRIMARY KEY,
            event_type VARCHAR(50),
            user_id INT,
            ip_address VARCHAR(50),
            description TEXT,
            details TEXT,
            severity VARCHAR(20),
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()
    print("✓ All database tables initialized")


# ============================================================
# TEST - Run this file directly to test DB connection
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Database Connection Test")
    print("=" * 60)
    test_connection()
    init_database()
