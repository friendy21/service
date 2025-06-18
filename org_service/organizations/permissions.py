# org_service/organizations/permissions.py
import hmac
import hashlib
import time
from rest_framework.permissions import BasePermission
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class ServiceTokenPermission(BasePermission):
    """
    Permission class for service-to-service authentication
    """
    
    def has_permission(self, request, view):
        # Get headers
        service_token = request.headers.get('X-Service-Token')
        service_id = request.headers.get('X-Service-ID')
        timestamp = request.headers.get('X-Timestamp')
        signature = request.headers.get('X-Signature')
        
        # Check required headers
        if not all([service_token, service_id, timestamp, signature]):
            logger.warning(f"Missing service authentication headers from {request.META.get('REMOTE_ADDR')}")
            return False
        
        # Check token
        if service_token != settings.SERVICE_TOKEN:
            logger.warning(f"Invalid service token from {service_id}")
            return False
        
        # Check timestamp (prevent replay attacks)
        try:
            request_time = int(timestamp)
            current_time = int(time.time())
            if abs(current_time - request_time) > 300:  # 5 minutes tolerance
                logger.warning(f"Timestamp too old/new from {service_id}")
                return False
        except (ValueError, TypeError):
            logger.warning(f"Invalid timestamp from {service_id}")
            return False
        
        # Verify signature
        method = request.method
        path = request.path
        body = request.body.decode('utf-8') if request.body else ''
        
        payload = f"{method}|{path}|{body}|{service_id}|{timestamp}"
        expected_signature = hmac.new(
            settings.SERVICE_SECRET.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            logger.warning(f"Invalid signature from {service_id}")
            return False
        
        logger.info(f"Service authentication successful for {service_id}")
        return True


class IsAuthenticated(BasePermission):
    """
    Allows access only to authenticated users.
    """
    
    def has_permission(self, request, view):
        return hasattr(request, 'user') and request.user is not None


class IsAdminUser(BasePermission):
    """
    Allows access only to admin users.
    """
    
    def has_permission(self, request, view):
        return (hasattr(request, 'user') and 
                request.user is not None and 
                request.user.role == 'admin')


class IsAdminOrSelf(BasePermission):
    """
    Allows access to admin users or the user themselves.
    """
    
    def has_permission(self, request, view):
        return hasattr(request, 'user') and request.user is not None
    
    def has_object_permission(self, request, view, obj):
        # Admin can access any user in their organization
        if request.user.role == 'admin' and request.user.org == obj.org:
            return True
        
        # Users can access their own data
        return request.user == obj


class IsOrganizationMember(BasePermission):
    """
    Allows access only to members of the organization.
    """
    
    def has_permission(self, request, view):
        if not hasattr(request, 'user') or request.user is None:
            return False
        
        # Get organization ID from URL parameters
        org_id = view.kwargs.get('org_id')
        if org_id:
            return str(request.user.org.id) == str(org_id)
        
        return True
    
    def has_object_permission(self, request, view, obj):
        # Check if user belongs to the same organization as the object
        if hasattr(obj, 'org'):
            return request.user.org == obj.org
        elif hasattr(obj, 'organization'):
            return request.user.org == obj.organization
        return False


class CanManageUsers(BasePermission):
    """
    Allows user management operations based on role hierarchy.
    """
    
    def has_permission(self, request, view):
        if not hasattr(request, 'user') or request.user is None:
            return False
        
        # Only admin and member roles can manage users
        return request.user.role in ['admin', 'member']
    
    def has_object_permission(self, request, view, obj):
        # Admin can manage any user in their organization
        if request.user.role == 'admin' and request.user.org == obj.org:
            return True
        
        # Members can only manage themselves
        if request.user.role == 'member':
            return request.user == obj
        
        return False


class CanChangeRole(BasePermission):
    """
    Allows role changes only by admin users.
    """
    
    def has_permission(self, request, view):
        return (hasattr(request, 'user') and 
                request.user is not None and 
                request.user.role == 'admin')
    
    def has_object_permission(self, request, view, obj):
        # Admin can change roles of users in their organization
        return (request.user.role == 'admin' and 
                request.user.org == obj.org)


class CanDeactivateUsers(BasePermission):
    """
    Allows user deactivation only by admin users.
    """
    
    def has_permission(self, request, view):
        return (hasattr(request, 'user') and 
                request.user is not None and 
                request.user.role == 'admin')
    
    def has_object_permission(self, request, view, obj):
        # Admin can deactivate users in their organization
        # But cannot deactivate themselves
        return (request.user.role == 'admin' and 
                request.user.org == obj.org and 
                request.user != obj)


class OrganizationResourcePermission(BasePermission):
    """
    Permission for organization-level resources.
    """
    
    def has_permission(self, request, view):
        if not hasattr(request, 'user') or request.user is None:
            return False
        
        # Check method-based permissions
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            # All authenticated users can read
            return True
        elif request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            # Only admin can modify
            return request.user.role == 'admin'
        
        return False
    
    def has_object_permission(self, request, view, obj):
        # Users can only access resources from their organization
        if hasattr(obj, 'org'):
            return request.user.org == obj.org
        elif hasattr(obj, 'organization'):
            return request.user.org == obj.organization
        
        return False


def get_user_permissions(user):
    """
    Get list of permissions for a user based on their role.
    """
    base_permissions = [
        'view_own_profile',
        'update_own_profile',
        'change_own_password',
    ]
    
    role_permissions = {
        'admin': [
            'view_all_users',
            'create_users',
            'update_any_user',
            'deactivate_users',
            'reactivate_users',
            'change_user_roles',
            'delete_users',
            'manage_organization',
            'view_audit_logs',
        ],
        'member': [
            'view_org_users',
            'view_organization',
        ],
        'viewer': [
            'view_org_users',
            'view_organization',
        ]
    }
    
    permissions = base_permissions.copy()
    permissions.extend(role_permissions.get(user.role, []))
    
    return permissions