"""
RBAC (Role-Based Access Control) Manager
Handles roles, permissions, and user-role assignments

Author: Nandan
Course: CSE212 Cyber Security
"""

from typing import List, Optional
import pymysql


class RBACManager:
    """
    Manages Role-Based Access Control

    Features:
    - Role and permission management
    - User-role assignments
    - Permission checking
    - Backward compatibility with users.role column
    """

    def __init__(self, db_connection):
        """
        Initialize RBAC Manager

        Args:
            db_connection: Database connection object
        """
        self.conn = db_connection

    def create_role(self, name: str, description: str = None) -> int:
        """
        Create a new role

        Args:
            name: Role name
            description: Role description

        Returns:
            Role ID
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO roles (name, description)
            VALUES (%s, %s)
        """, (name, description))
        self.conn.commit()
        return cursor.lastrowid

    def create_permission(self, name: str, description: str = None) -> int:
        """
        Create a new permission

        Args:
            name: Permission name
            description: Permission description

        Returns:
            Permission ID
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO permissions (name, description)
            VALUES (%s, %s)
        """, (name, description))
        self.conn.commit()
        return cursor.lastrowid

    def assign_role_to_user(self, user_id: int, role_id: int, assigned_by: int = None) -> bool:
        """
        Assign a role to a user

        Args:
            user_id: User ID
            role_id: Role ID
            assigned_by: Admin user ID who assigned the role

        Returns:
            True if successful
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO user_roles (user_id, role_id, assigned_by)
                VALUES (%s, %s, %s)
            """, (user_id, role_id, assigned_by))
            self.conn.commit()
            return True
        except pymysql.IntegrityError:
            # Role already assigned to user
            return False

    def assign_permission_to_role(self, role_id: int, permission_id: int, assigned_by: int = None) -> bool:
        """
        Assign a permission to a role

        Args:
            role_id: Role ID
            permission_id: Permission ID
            assigned_by: Admin user ID who assigned the permission

        Returns:
            True if successful
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO role_permissions (role_id, permission_id, assigned_by)
                VALUES (%s, %s, %s)
            """, (role_id, permission_id, assigned_by))
            self.conn.commit()
            return True
        except pymysql.IntegrityError:
            # Permission already assigned to role
            return False

    def get_user_roles(self, user_id: int) -> List[dict]:
        """
        Get all roles assigned to a user

        Args:
            user_id: User ID

        Returns:
            List of role dictionaries
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT r.id, r.name, r.description, ur.assigned_at
            FROM roles r
            JOIN user_roles ur ON r.id = ur.role_id
            WHERE ur.user_id = %s
        """, (user_id,))
        return cursor.fetchall()

    def get_role_permissions(self, role_ids: List[int]) -> List[dict]:
        """
        Get all permissions for given roles

        Args:
            role_ids: List of role IDs

        Returns:
            List of permission dictionaries
        """
        if not role_ids:
            return []

        cursor = self.conn.cursor()
        placeholders = ','.join(['%s'] * len(role_ids))
        cursor.execute(f"""
            SELECT DISTINCT p.id, p.name, p.description
            FROM permissions p
            JOIN role_permissions rp ON p.id = rp.permission_id
            WHERE rp.role_id IN ({placeholders})
        """, role_ids)
        return cursor.fetchall()

    def user_has_permission(self, user_id: int, permission_name: str) -> bool:
        """
        Check if user has a specific permission

        Args:
            user_id: User ID
            permission_name: Permission name

        Returns:
            True if user has permission
        """
        # First check new RBAC system
        user_roles = self.get_user_roles(user_id)
        if user_roles:
            role_ids = [role['id'] for role in user_roles]
            permissions = self.get_role_permissions(role_ids)
            if any(p['name'] == permission_name for p in permissions):
                return True

        # Fallback to legacy users.role column for backward compatibility
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT role FROM users WHERE id = %s
        """, (user_id,))
        user = cursor.fetchone()

        if user and user['role']:
            # Simple mapping: admin role gets all permissions
            if user['role'].lower() == 'admin':
                return True
            elif user['role'].lower() == 'moderator' and permission_name in [
                'read_profile', 'update_profile', 'view_security_events'
            ]:
                return True
            # user role gets basic permissions
            elif user['role'].lower() == 'user' and permission_name in ['read_profile', 'update_profile']:
                return True

        return False

    def get_all_roles(self) -> List[dict]:
        """
        Get all available roles

        Returns:
            List of role dictionaries
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, name, description FROM roles ORDER BY name")
        return cursor.fetchall()

    def get_all_permissions(self) -> List[dict]:
        """
        Get all available permissions

        Returns:
            List of permission dictionaries
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, name, description FROM permissions ORDER BY name")
        return cursor.fetchall()

    def remove_role_from_user(self, user_id: int, role_id: int) -> bool:
        """
        Remove a role from a user

        Args:
            user_id: User ID
            role_id: Role ID

        Returns:
            True if successful
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            DELETE FROM user_roles
            WHERE user_id = %s AND role_id = %s
        """, (user_id, role_id))
        self.conn.commit()
        return cursor.rowcount > 0

    def remove_permission_from_role(self, role_id: int, permission_id: int) -> bool:
        """
        Remove a permission from a role

        Args:
            role_id: Role ID
            permission_id: Permission ID

        Returns:
            True if successful
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            DELETE FROM role_permissions
            WHERE role_id = %s AND permission_id = %s
        """, (role_id, permission_id))
        self.conn.commit()
        return cursor.rowcount > 0

    def initialize_default_roles_and_permissions(self):
        """
        Initialize default roles and permissions for the system
        """
        # Create default permissions
        permissions = [
            ('read_profile', 'Read user profile'),
            ('update_profile', 'Update user profile'),
            ('admin_users', 'Administer users'),
            ('admin_roles', 'Administer roles and permissions'),
            ('view_security_events', 'View security events'),
            ('view_ai_metrics', 'View AI performance metrics'),
        ]

        permission_ids = {}
        for name, desc in permissions:
            try:
                perm_id = self.create_permission(name, desc)
                permission_ids[name] = perm_id
            except pymysql.IntegrityError:
                # Permission already exists, get its ID
                cursor = self.conn.cursor()
                cursor.execute("SELECT id FROM permissions WHERE name = %s", (name,))
                result = cursor.fetchone()
                if result:
                    permission_ids[name] = result['id']

        # Create default roles
        roles = [
            ('user', 'Regular user with basic permissions'),
            ('admin', 'Administrator with full access'),
            ('moderator', 'Moderator with limited admin permissions'),
        ]

        role_ids = {}
        for name, desc in roles:
            try:
                role_id = self.create_role(name, desc)
                role_ids[name] = role_id
            except pymysql.IntegrityError:
                # Role already exists, get its ID
                cursor = self.conn.cursor()
                cursor.execute("SELECT id FROM roles WHERE name = %s", (name,))
                result = cursor.fetchone()
                if result:
                    role_ids[name] = result['id']

        # Assign permissions to roles
        role_permissions = {
            'user': ['read_profile', 'update_profile'],
            'moderator': ['read_profile', 'update_profile', 'view_security_events'],
            'admin': ['read_profile', 'update_profile', 'admin_users', 'admin_roles', 'view_security_events', 'view_ai_metrics'],
        }

        for role_name, perm_names in role_permissions.items():
            if role_name in role_ids:
                role_id = role_ids[role_name]
                for perm_name in perm_names:
                    if perm_name in permission_ids:
                        self.assign_permission_to_role(role_id, permission_ids[perm_name])
