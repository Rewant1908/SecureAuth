"""
Authentication Module
Handles RBAC and Session Management for SecureAuth

Author: Nandan
Course: CSE212 Cyber Security
"""

from .rbac import RBACManager
from .session_manager import SessionManager
from .decorators import require_permission, require_active_session

__all__ = ['RBACManager', 'SessionManager', 'require_permission', 'require_active_session']