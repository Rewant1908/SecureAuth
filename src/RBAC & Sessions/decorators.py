"""
Authentication Decorators
Provides decorators for RBAC and session validation

Author: Nandan
Course: CSE212 Cyber Security
"""

from functools import wraps
from flask import request, jsonify, g
from jwt_handler.jwt_manager import JWTHandler
from .rbac import RBACManager
from .session_manager import SessionManager
from database import get_connection


def require_active_session(f):
    """
    Decorator to require an active session

    Validates JWT token and checks session validity
    Updates last_seen_at on each request
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Missing or invalid authorization header"}), 401

        token = auth_header.split(' ')[1]

        # Verify JWT token
        payload = JWTHandler.verify_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401

        user_id = payload.get('user_id')
        if not user_id:
            return jsonify({"error": "Invalid token payload"}), 401

        # Check session validity
        conn = get_connection()
        session_mgr = SessionManager(conn)

        # For access tokens, we need to validate the session exists
        # In a more advanced setup, we could store session_id in token
        # For now, we'll check if user has any active sessions
        active_sessions = session_mgr.get_user_active_sessions(user_id)
        if not active_sessions:
            conn.close()
            return jsonify({"error": "No active session found"}), 401

        # Store user info in Flask g for use in route
        g.user_id = user_id
        g.user_role = payload.get('role')
        g.session_count = len(active_sessions)

        conn.close()
        return f(*args, **kwargs)

    return decorated_function


def require_permission(permission_name: str):
    """
    Decorator to require specific permission

    Args:
        permission_name: Name of the permission required

    Returns:
        Decorated function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get Authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({"error": "Missing or invalid authorization header"}), 401

            token = auth_header.split(' ')[1]

            # Verify JWT token
            payload = JWTHandler.verify_token(token)
            if not payload:
                return jsonify({"error": "Invalid or expired token"}), 401

            user_id = payload.get('user_id')
            if not user_id:
                return jsonify({"error": "Invalid token payload"}), 401

            # Check session validity
            conn = get_connection()
            session_mgr = SessionManager(conn)

            # For access tokens, we need to validate the session exists
            active_sessions = session_mgr.get_user_active_sessions(user_id)
            if not active_sessions:
                conn.close()
                return jsonify({"error": "No active session found"}), 401

            # Check permissions
            rbac_mgr = RBACManager(conn)

            if not rbac_mgr.user_has_permission(user_id, permission_name):
                conn.close()
                return jsonify({
                    "error": "Insufficient permissions",
                    "required_permission": permission_name
                }), 403

            # Store user info in Flask g for use in route
            g.user_id = user_id
            g.user_role = payload.get('role')
            g.session_count = len(active_sessions)

            conn.close()
            return f(*args, **kwargs)

        return decorated_function
    return decorator


def require_role(role_name: str):
    """
    Decorator to require specific role (alternative to permission-based)

    Args:
        role_name: Name of the role required

    Returns:
        Decorated function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check session first
            session_decorated = require_active_session(lambda: None)
            session_result = session_decorated()

            if session_result and hasattr(session_result, 'status_code'):
                return session_result

            # Check role
            user_role = getattr(g, 'user_role', None)
            if not user_role or user_role.lower() != role_name.lower():
                return jsonify({
                    "error": "Insufficient role",
                    "required_role": role_name
                }), 403

            return f(*args, **kwargs)

        return decorated_function
    return decorator


def optional_auth(f):
    """
    Decorator for optional authentication

    Sets user info in g if authenticated, but doesn't require it
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')

        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            payload = JWTHandler.verify_token(token)

            if payload:
                g.user_id = payload.get('user_id')
                g.user_role = payload.get('role')
                g.authenticated = True
            else:
                g.authenticated = False
        else:
            g.authenticated = False

        return f(*args, **kwargs)

    return decorated_function