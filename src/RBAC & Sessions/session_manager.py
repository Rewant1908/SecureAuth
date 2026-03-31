"""
Session Manager
Handles user sessions, refresh tokens, and session validation

Author: Nandan
Course: CSE212 Cyber Security
"""

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict
import pymysql


class SessionManager:
    """
    Manages user sessions for authentication

    Features:
    - Session creation and validation
    - Refresh token management
    - Session expiration handling
    - IP and user agent tracking
    """

    def __init__(self, db_connection):
        """
        Initialize Session Manager

        Args:
            db_connection: Database connection object
        """
        self.conn = db_connection
        self.session_expiry_days = 7  # Default session expiry

    def create_session(self, user_id: int, refresh_token: str, ip_address: str,
                      user_agent: str, expiry_days: int = None) -> str:
        """
        Create a new session for a user

        Args:
            user_id: User ID
            refresh_token: JWT refresh token
            ip_address: Client IP address
            user_agent: Client user agent
            expiry_days: Session expiry in days (default: 7)

        Returns:
            Session ID
        """
        session_id = secrets.token_urlsafe(32)
        refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        expires_at = datetime.utcnow() + timedelta(days=expiry_days or self.session_expiry_days)

        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO sessions
            (session_id, user_id, refresh_token_hash, ip_address, user_agent, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (session_id, user_id, refresh_token_hash, ip_address, user_agent, expires_at))
        self.conn.commit()

        return session_id

    def validate_session(self, session_id: str) -> Optional[Dict]:
        """
        Validate a session and update last seen

        Args:
            session_id: Session ID

        Returns:
            Session data if valid, None if invalid/expired
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT s.*, u.username
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_id = %s AND s.is_active = 1
        """, (session_id,))
        session = cursor.fetchone()

        if not session:
            return None

        # Check if session is expired
        if datetime.utcnow() > session['expires_at']:
            self.invalidate_session(session_id)
            return None

        # Update last seen
        cursor.execute("""
            UPDATE sessions
            SET last_seen_at = CURRENT_TIMESTAMP
            WHERE session_id = %s
        """, (session_id,))
        self.conn.commit()

        return session

    def validate_refresh_token(self, refresh_token: str) -> Optional[Dict]:
        """
        Validate refresh token against active sessions

        Args:
            refresh_token: JWT refresh token

        Returns:
            Session data if valid, None if invalid
        """
        refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT s.*, u.username
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.refresh_token_hash = %s AND s.is_active = 1
        """, (refresh_token_hash,))
        session = cursor.fetchone()

        if not session:
            return None

        # Check if session is expired
        if datetime.utcnow() > session['expires_at']:
            self.invalidate_session(session['session_id'])
            return None

        return session

    def invalidate_session(self, session_id: str) -> bool:
        """
        Invalidate a session (logout)

        Args:
            session_id: Session ID

        Returns:
            True if session was invalidated
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE sessions
            SET is_active = 0
            WHERE session_id = %s
        """, (session_id,))
        self.conn.commit()
        return cursor.rowcount > 0

    def invalidate_all_user_sessions(self, user_id: int) -> int:
        """
        Invalidate all sessions for a user (force logout everywhere)

        Args:
            user_id: User ID

        Returns:
            Number of sessions invalidated
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE sessions
            SET is_active = 0
            WHERE user_id = %s AND is_active = 1
        """, (user_id,))
        self.conn.commit()
        return cursor.rowcount

    def rotate_refresh_token(self, old_refresh_token: str, new_refresh_token: str) -> bool:
        """
        Rotate refresh token for a session (token refresh)

        Args:
            old_refresh_token: Current refresh token
            new_refresh_token: New refresh token

        Returns:
            True if rotation successful
        """
        old_hash = hashlib.sha256(old_refresh_token.encode()).hexdigest()
        new_hash = hashlib.sha256(new_refresh_token.encode()).hexdigest()

        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE sessions
            SET refresh_token_hash = %s, last_seen_at = CURRENT_TIMESTAMP
            WHERE refresh_token_hash = %s AND is_active = 1
        """, (new_hash, old_hash))
        self.conn.commit()
        return cursor.rowcount > 0

    def get_user_active_sessions(self, user_id: int) -> list:
        """
        Get all active sessions for a user

        Args:
            user_id: User ID

        Returns:
            List of active session dictionaries
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT session_id, ip_address, user_agent, created_at, last_seen_at, expires_at
            FROM sessions
            WHERE user_id = %s AND is_active = 1 AND expires_at > CURRENT_TIMESTAMP
            ORDER BY last_seen_at DESC
        """, (user_id,))
        return cursor.fetchall()

    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions

        Returns:
            Number of sessions cleaned up
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE sessions
            SET is_active = 0
            WHERE expires_at <= CURRENT_TIMESTAMP AND is_active = 1
        """)
        self.conn.commit()
        return cursor.rowcount

    def extend_session(self, session_id: str, additional_days: int = 7) -> bool:
        """
        Extend session expiry

        Args:
            session_id: Session ID
            additional_days: Days to add to expiry

        Returns:
            True if extended successfully
        """
        new_expiry = datetime.utcnow() + timedelta(days=additional_days)
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE sessions
            SET expires_at = %s, last_seen_at = CURRENT_TIMESTAMP
            WHERE session_id = %s AND is_active = 1
        """, (new_expiry, session_id))
        self.conn.commit()
        return cursor.rowcount > 0

    def get_session_stats(self) -> Dict:
        """
        Get session statistics

        Returns:
            Dictionary with session stats
        """
        cursor = self.conn.cursor()

        # Total sessions
        cursor.execute("SELECT COUNT(*) as total FROM sessions")
        total = cursor.fetchone()['total']

        # Active sessions
        cursor.execute("""
            SELECT COUNT(*) as active
            FROM sessions
            WHERE is_active = 1 AND expires_at > CURRENT_TIMESTAMP
        """)
        active = cursor.fetchone()['active']

        # Expired sessions
        cursor.execute("""
            SELECT COUNT(*) as expired
            FROM sessions
            WHERE expires_at <= CURRENT_TIMESTAMP
        """)
        expired = cursor.fetchone()['expired']

        return {
            'total_sessions': total,
            'active_sessions': active,
            'expired_sessions': expired,
            'inactive_sessions': total - active - expired
        }