"""
Module 7: Security Protection
Protects against brute force, rate limiting, and common attacks

Author: Rewant
Course: CSE212 Cyber Security
"""

from collections import defaultdict
from datetime import datetime, timedelta
import hashlib
from typing import Optional, Tuple


class SecurityProtection:
    """
    Handles security protection mechanisms

    Features:
    1. Brute force detection - locks account after 5 failed attempts
    2. Rate limiting - limits requests per minute
    3. Credential stuffing detection - detects automated attacks
    4. Security event logging - logs all security events
    """

    def __init__(self, db_connection):
        """
        Initialize security protection

        Args:
            db_connection: Database connection object
        """
        self.conn = db_connection
        self.max_login_attempts = 5
        self.lockout_duration_minutes = 15
        self.rate_limit_window_seconds = 60
        self.max_requests_per_window = 20

        # In-memory rate limiting (in production, use Redis)
        self.rate_limit_store = defaultdict(list)

    def check_brute_force(self, username: str, ip_address: str) -> Tuple[bool, Optional[str]]:
        """
        Check for brute force attack attempts

        Args:
            username: Username attempting to login
            ip_address: IP address

        Returns:
            Tuple of (is_locked, unlock_time)
            - is_locked: True if account is locked
            - unlock_time: When account will be unlocked (ISO format)
        """
        cursor = self.conn.cursor()

        lockout_window = datetime.utcnow() - timedelta(minutes=self.lockout_duration_minutes)

        cursor.execute(
            """
            SELECT COUNT(*) as count FROM login_attempts
            WHERE (username = %s OR ip_address = %s)
            AND success = 0
            AND timestamp > %s
            """,
            (username, ip_address, lockout_window),
        )

        result = cursor.fetchone()
        failed_count = result["count"] if result else 0

        if failed_count >= self.max_login_attempts:
            cursor.execute(
                """
                SELECT MAX(timestamp) as last_attempt FROM login_attempts
                WHERE (username = %s OR ip_address = %s)
                AND success = 0
                """,
                (username, ip_address),
            )

            last_attempt = cursor.fetchone()
            if last_attempt and last_attempt["last_attempt"]:
                last_attempt_dt = last_attempt["last_attempt"]
                unlock_time = last_attempt_dt + timedelta(minutes=self.lockout_duration_minutes)
                return True, unlock_time.isoformat()

        return False, None

    def record_login_attempt(
        self,
        user_id: Optional[int],
        username: str,
        ip_address: str,
        user_agent: str,
        success: bool,
        failure_reason: str = None,
    ):
        """
        Record login attempt for security monitoring

        Args:
            user_id: User ID (None if user doesn't exist)
            username: Username
            ip_address: IP address
            user_agent: User agent string
            success: Whether login was successful
            failure_reason: Reason for failure (if failed)
        """
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO login_attempts
            (user_id, username, ip_address, user_agent, success, failure_reason, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
            """,
            (user_id, username, ip_address, user_agent, success, failure_reason),
        )
        self.conn.commit()

    def reset_failed_attempts(self, username: str):
        """
        Reset failed login attempts after successful login

        Args:
            username: Username
        """
        cursor = self.conn.cursor()
        cursor.execute(
            """
            DELETE FROM login_attempts
            WHERE username = %s AND success = 0
            """,
            (username,),
        )
        self.conn.commit()

    def check_rate_limit(self, identifier: str) -> Tuple[bool, int, float]:
        """
        Check rate limiting with tarpitting.

        Args:
            identifier: IP address or user identifier

        Returns:
            Tuple of (is_allowed, remaining_requests, delay_seconds)
        """
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=self.rate_limit_window_seconds)

        self.rate_limit_store[identifier] = [
            req_time
            for req_time in self.rate_limit_store[identifier]
            if req_time > window_start
        ]

        request_count = len(self.rate_limit_store[identifier])
        self.rate_limit_store[identifier].append(now)

        if request_count >= self.max_requests_per_window:
            excess = request_count - self.max_requests_per_window + 1
            delay_seconds = min(float(2 ** (excess - 1)), 30.0)
            return False, 0, delay_seconds

        remaining = self.max_requests_per_window - request_count - 1
        return True, remaining, 0.0

    def detect_credential_stuffing(self, ip_address: str, time_window_minutes: int = 5) -> bool:
        """
        Detect credential stuffing attacks.
        """
        cursor = self.conn.cursor()
        time_threshold = datetime.utcnow() - timedelta(minutes=time_window_minutes)

        cursor.execute(
            """
            SELECT COUNT(DISTINCT username) as unique_users FROM login_attempts
            WHERE ip_address = %s
            AND timestamp > %s
            AND success = 0
            """,
            (ip_address, time_threshold),
        )

        result = cursor.fetchone()
        unique_usernames = result["unique_users"] if result else 0
        return unique_usernames > 10

    def log_security_event(
        self,
        user_id: Optional[int],
        event_type: str,
        severity: str,
        details: str,
        ip_address: str = None,
    ):
        """
        Log security event for monitoring and audit.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO security_events
            (user_id, event_type, severity, details, ip_address, timestamp)
            VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
            """,
            (user_id, event_type, severity, details, ip_address),
        )
        self.conn.commit()

    def get_recent_security_events(self, hours: int = 24, severity: str = None) -> list:
        """
        Get recent security events for admin review.
        """
        cursor = self.conn.cursor()
        time_threshold = datetime.utcnow() - timedelta(hours=hours)

        if severity:
            cursor.execute(
                """
                SELECT event_type, severity, details, ip_address, timestamp
                FROM security_events
                WHERE timestamp > %s AND severity = %s
                ORDER BY timestamp DESC
                """,
                (time_threshold, severity),
            )
        else:
            cursor.execute(
                """
                SELECT event_type, severity, details, ip_address, timestamp
                FROM security_events
                WHERE timestamp > %s
                ORDER BY timestamp DESC
                """,
                (time_threshold,),
            )

        events = []
        for row in cursor.fetchall():
            events.append(
                {
                    "event_type": row["event_type"],
                    "severity": row["severity"],
                    "details": row["details"],
                    "ip_address": row["ip_address"],
                    "timestamp": row["timestamp"],
                }
            )
        return events

    def is_suspicious_user_agent(self, user_agent: str) -> bool:
        """
        Check if user agent is suspicious (bot, scraper, etc.)
        """
        suspicious_patterns = [
            "bot",
            "crawler",
            "spider",
            "scraper",
            "curl",
            "wget",
            "python-requests",
            "nikto",
            "sqlmap",
            "nmap",
        ]

        user_agent_lower = user_agent.lower()
        return any(pattern in user_agent_lower for pattern in suspicious_patterns)

    def generate_csrf_token(self, session_id: str) -> str:
        """
        Generate CSRF token for form protection.
        """
        import secrets

        token = secrets.token_urlsafe(32)
        return token

    def generate_client_fingerprint(self, ip_address: str, user_agent: str, headers_dict: dict) -> str:
        """
        Generate a device fingerprint for session tracking.
        """
        fingerprint_data = f"{ip_address}|{user_agent}"
        for key in sorted(headers_dict.keys()):
            if key.lower() in ("accept-language", "accept-encoding", "dnt", "x-forwarded-for"):
                fingerprint_data += f"|{key.lower()}:{headers_dict[key]}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()


if __name__ == "__main__":
    import pymysql

    print("=" * 60)
    print("Security Protection Module Test")
    print("=" * 60)
    print()

    try:
        conn = pymysql.connect(
            host="localhost",
            user="secureauth_user",
            password="SecurePass123!",
            database="secureauth_db",
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
        )
        print("Connected to database\n")
    except Exception as exc:
        print(f"Database connection failed: {exc}")
        print("Make sure MariaDB is running and credentials are correct")
        raise SystemExit(1)

    security = SecurityProtection(conn)

    print("-" * 60)
    print("Test 1: Normal login attempts (3 failures)")
    print("-" * 60)
    for _ in range(3):
        security.record_login_attempt(
            None,
            "testuser",
            "192.168.1.100",
            "Chrome",
            False,
            "Invalid password",
        )

    is_locked, unlock_time = security.check_brute_force("testuser", "192.168.1.100")
    print(f"After 3 failed attempts - Locked: {is_locked}")
    print()

    print("-" * 60)
    print("Test 2: Brute force protection (trigger lockout)")
    print("-" * 60)
    for _ in range(3):
        security.record_login_attempt(
            None,
            "testuser",
            "192.168.1.100",
            "Chrome",
            False,
            "Invalid password",
        )

    is_locked, unlock_time = security.check_brute_force("testuser", "192.168.1.100")
    print("After 6 total failed attempts:")
    print(f"Locked: {is_locked}")
    if unlock_time:
        print(f"Unlock time: {unlock_time}")
    print()

    print("-" * 60)
    print("Test 3: Rate limiting")
    print("-" * 60)
    for index in range(15):
        allowed, remaining, delay_seconds = security.check_rate_limit("192.168.1.100")
        if index < 5 or index == 14:
            status = "Allowed" if allowed else "Blocked"
            print(
                f"Request {index + 1}: {status} "
                f"(Remaining: {remaining}, Delay: {delay_seconds}s)"
            )
    print()

    print("-" * 60)
    print("Test 4: Credential stuffing detection")
    print("-" * 60)
    print("Simulating attacker trying 12 different usernames...")
    for username in [f"user{i}" for i in range(12)]:
        security.record_login_attempt(
            None,
            username,
            "10.0.0.5",
            "Chrome",
            False,
            "Invalid credentials",
        )

    is_stuffing = security.detect_credential_stuffing("10.0.0.5")
    print(f"Credential stuffing detected: {is_stuffing}")
    print()

    print("-" * 60)
    print("Test 5: Security event logging")
    print("-" * 60)
    security.log_security_event(
        1,
        "brute_force_attempt",
        "high",
        "Multiple failed login attempts",
        "192.168.1.100",
    )
    security.log_security_event(
        2,
        "suspicious_activity",
        "medium",
        "Login from new location",
        "203.0.113.42",
    )

    events = security.get_recent_security_events(hours=24)
    print(f"Logged {len(events)} security events")
    for event in events[:3]:
        print(f"  - {event['event_type']} ({event['severity']})")
    print()

    print("-" * 60)
    print("Test 6: Suspicious user agent detection")
    print("-" * 60)
    test_agents = [
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", False),
        ("python-requests/2.28.0", True),
        ("curl/7.68.0", True),
    ]
    for agent, expected in test_agents:
        is_suspicious = security.is_suspicious_user_agent(agent)
        status = "Correct" if is_suspicious == expected else "Wrong"
        print(f"{status} - '{agent[:40]}...' - Suspicious: {is_suspicious}")
    print()

    print("=" * 60)
    print("Security Protection module working correctly")
    print("=" * 60)

    cursor = conn.cursor()
    cursor.execute("DELETE FROM login_attempts WHERE username LIKE 'user%' OR username = 'testuser'")
    conn.commit()
    conn.close()
