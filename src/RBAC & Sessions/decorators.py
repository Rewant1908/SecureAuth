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
        payload, session_info, error_response = _authenticate_request()
        if error_response:
            return error_response

        g.user_id = payload.get('user_id')
        g.user_role = payload.get('role')
        g.session_id = session_info.get('session_id') if session_info else payload.get('session_id')
        g.session_count = 1

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
            payload, session_info, error_response = _authenticate_request()
            if error_response:
                return error_response

            conn = get_connection()
            try:
                rbac_mgr = RBACManager(conn)
                user_id = payload.get('user_id')
                if not rbac_mgr.user_has_permission(user_id, permission_name):
                    return jsonify({
                        "error": "Insufficient permissions",
                        "required_permission": permission_name
                    }), 403

                g.user_id = user_id
                g.user_role = payload.get('role')
                g.session_id = session_info.get('session_id') if session_info else payload.get('session_id')
                g.session_count = 1
            finally:
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


def _authenticate_request():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None, None, (jsonify({"error": "Missing or invalid authorization header"}), 401)

    token = auth_header.split(' ')[1]
    payload = JWTHandler.verify_token(token)
    if not payload:
        return None, None, (jsonify({"error": "Invalid or expired token"}), 401)

    user_id = payload.get('user_id')
    if not user_id:
        return None, None, (jsonify({"error": "Invalid token payload"}), 401)

    conn = get_connection()
    try:
        session_mgr = SessionManager(conn)
        session_id = payload.get('session_id')

        if session_id:
            session = session_mgr.validate_session(session_id)
            if not session or session.get('user_id') != user_id:
                return None, None, (jsonify({"error": "No active session found"}), 401)
            return payload, session, None

        active_sessions = session_mgr.get_user_active_sessions(user_id)
        if not active_sessions:
            return None, None, (jsonify({"error": "No active session found"}), 401)

        return payload, active_sessions[0], None
    finally:
        conn.close()
