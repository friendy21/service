# org_service/organizations/views/user_management_views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.db import transaction, IntegrityError
from django.shortcuts import get_object_or_404
from django.core.exceptions import ValidationError
from django.utils import timezone
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from organizations.models.models import Organization, OrgUser
from organizations.serializers.user_serializers import (
    UserCreateSerializer, UserUpdateSerializer, UserResponseSerializer,
    UserListSerializer, UserDetailSerializer, ChangePasswordSerializer,
    RoleUpdateSerializer, UserDeactivateSerializer, UserReactivateSerializer,
    OrganizationUsersSerializer
)
from organizations.permissions import (
    IsAuthenticated, IsAdminUser, IsAdminOrSelf, IsOrganizationMember,
    CanManageUsers, CanChangeRole, CanDeactivateUsers
)
import logging

logger = logging.getLogger(__name__)

class UserListView(APIView):
    """
    List all users (admin only) or users in same organization
    """
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_summary="List Users",
        operation_description="""
        List users based on current user's role:
        - **Admin**: Can see all users in their organization
        - **Member/Viewer**: Can see basic info of users in their organization
        """,
        responses={
            200: UserListSerializer(many=True),
            401: "Unauthorized",
            403: "Forbidden"
        },
        tags=['User Management']
    )
    def get(self, request):
        try:
            # Users can only see users from their organization
            if request.user.role == 'admin':
                users = OrgUser.objects.filter(org=request.user.org).order_by('-created_at')
            else:
                # Members and viewers see limited info
                users = OrgUser.objects.filter(
                    org=request.user.org, 
                    is_active=True
                ).order_by('-created_at')
            
            serializer = UserListSerializer(users, many=True)
            return Response({
                "users": serializer.data,
                "total_count": users.count()
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error listing users: {str(e)}")
            return Response({
                "message": "Internal server error",
                "detail": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserRetrieveView(APIView):
    """
    Retrieve detailed user information
    """
    permission_classes = [IsAuthenticated, IsAdminOrSelf]
    
    @swagger_auto_schema(
        operation_summary="Get User Details",
        operation_description="Retrieve detailed information about a specific user",
        responses={
            200: UserDetailSerializer,
            401: "Unauthorized",
            403: "Forbidden",
            404: "User not found"
        },
        tags=['User Management']
    )
    def get(self, request, user_id):
        try:
            user = get_object_or_404(OrgUser, id=user_id)
            
            # Check permissions
            self.check_object_permissions(request, user)
            
            serializer = UserDetailSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error retrieving user {user_id}: {str(e)}")
            return Response({
                "message": "User not found",
                "detail": str(e)
            }, status=status.HTTP_404_NOT_FOUND)


class UserUpdateView(APIView):
    """
    Update user information
    """
    permission_classes = [IsAuthenticated, IsAdminOrSelf]
    
    @swagger_auto_schema(
        operation_summary="Update User",
        operation_description="Update user information (name, email)",
        request_body=UserUpdateSerializer,
        responses={
            200: UserResponseSerializer,
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "User not found"
        },
        tags=['User Management']
    )
    def put(self, request, user_id):
        try:
            user = get_object_or_404(OrgUser, id=user_id)
            
            # Check permissions
            self.check_object_permissions(request, user)
            
            serializer = UserUpdateSerializer(user, data=request.data, partial=True)
            if not serializer.is_valid():
                return Response({
                    "message": "Validation failed",
                    "errors": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
            
            with transaction.atomic():
                updated_user = serializer.save()
                updated_user.updated_at = timezone.now()
                updated_user.save()
            
            response_serializer = UserResponseSerializer(updated_user)
            
            logger.info(f"User updated: {updated_user.email} by {request.user.email}")
            return Response({
                "message": "User updated successfully",
                "user": response_serializer.data
            }, status=status.HTTP_200_OK)
            
        except IntegrityError as e:
            return Response({
                "message": "Email already exists",
                "detail": "User with this email already exists"
            }, status=status.HTTP_409_CONFLICT)
        except Exception as e:
            logger.error(f"Error updating user {user_id}: {str(e)}")
            return Response({
                "message": "Internal server error",
                "detail": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserDeleteView(APIView):
    """
    Delete user (admin only)
    """
    permission_classes = [IsAuthenticated, CanDeactivateUsers]
    
    @swagger_auto_schema(
        operation_summary="Delete User",
        operation_description="Permanently delete a user (admin only)",
        responses={
            200: "User deleted successfully",
            401: "Unauthorized",
            403: "Forbidden",
            404: "User not found"
        },
        tags=['User Management']
    )
    def delete(self, request, user_id):
        try:
            user = get_object_or_404(OrgUser, id=user_id)
            
            # Check permissions
            self.check_object_permissions(request, user)
            
            # Prevent admin from deleting themselves
            if user == request.user:
                return Response({
                    "message": "Cannot delete your own account"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            user_email = user.email
            user.delete()
            
            logger.info(f"User deleted: {user_email} by {request.user.email}")
            return Response({
                "message": "User deleted successfully"
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error deleting user {user_id}: {str(e)}")
            return Response({
                "message": "Internal server error",
                "detail": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserDeactivateView(APIView):
    """
    Deactivate user account (admin only)
    """
    permission_classes = [IsAuthenticated, CanDeactivateUsers]
    
    @swagger_auto_schema(
        operation_summary="Deactivate User",
        operation_description="Deactivate a user account (admin only)",
        request_body=UserDeactivateSerializer,
        responses={
            200: "User deactivated successfully",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "User not found"
        },
        tags=['User Management']
    )
    def post(self, request, user_id):
        try:
            user = get_object_or_404(OrgUser, id=user_id)
            
            # Check permissions
            self.check_object_permissions(request, user)
            
            # Prevent admin from deactivating themselves
            if user == request.user:
                return Response({
                    "message": "Cannot deactivate your own account"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if not user.is_active:
                return Response({
                    "message": "User is already deactivated"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            serializer = UserDeactivateSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({
                    "message": "Validation failed",
                    "errors": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
            
            user.deactivate(deactivated_by=request.user)
            
            logger.info(f"User deactivated: {user.email} by {request.user.email}")
            return Response({
                "message": "User deactivated successfully"
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error deactivating user {user_id}: {str(e)}")
            return Response({
                "message": "Internal server error",
                "detail": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserReactivateView(APIView):
    """
    Reactivate user account (admin only)
    """
    permission_classes = [IsAuthenticated, IsAdminUser]
    
    @swagger_auto_schema(
        operation_summary="Reactivate User",
        operation_description="Reactivate a deactivated user account (admin only)",
        request_body=UserReactivateSerializer,
        responses={
            200: "User reactivated successfully",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "User not found"
        },
        tags=['User Management']
    )
    def post(self, request, user_id):
        try:
            user = get_object_or_404(OrgUser, id=user_id)
            
            # Check same organization
            if user.org != request.user.org:
                return Response({
                    "message": "User not found"
                }, status=status.HTTP_404_NOT_FOUND)
            
            if user.is_active:
                return Response({
                    "message": "User is already active"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            serializer = UserReactivateSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({
                    "message": "Validation failed",
                    "errors": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
            
            user.reactivate()
            
            # Reset password if requested
            if serializer.validated_data.get('reset_password'):
                # Generate temporary password
                import secrets
                import string
                temp_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
                user.set_password(temp_password)
                user.save()
                
                logger.info(f"User reactivated with password reset: {user.email} by {request.user.email}")
                return Response({
                    "message": "User reactivated successfully with new password",
                    "temporary_password": temp_password
                }, status=status.HTTP_200_OK)
            
            logger.info(f"User reactivated: {user.email} by {request.user.email}")
            return Response({
                "message": "User reactivated successfully"
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error reactivating user {user_id}: {str(e)}")
            return Response({
                "message": "Internal server error",
                "detail": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserChangePasswordView(APIView):
    """
    Change user password
    """
    permission_classes = [IsAuthenticated, IsAdminOrSelf]
    
    @swagger_auto_schema(
        operation_summary="Change User Password",
        operation_description="Change user password (admin can change any user's password)",
        request_body=ChangePasswordSerializer,
        responses={
            200: "Password changed successfully",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "User not found"
        },
        tags=['User Management']
    )
    def post(self, request, user_id):
        try:
            user = get_object_or_404(OrgUser, id=user_id)
            
            # Check permissions
            self.check_object_permissions(request, user)
            
            serializer = ChangePasswordSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({
                    "message": "Validation failed",
                    "errors": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Verify current password (unless admin changing another user's password)
            if request.user == user:
                if not user.check_password(serializer.validated_data['current_password']):
                    return Response({
                        "message": "Current password is incorrect"
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            # Set new password
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            
            logger.info(f"Password changed for user: {user.email} by {request.user.email}")
            return Response({
                "message": "Password changed successfully"
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error changing password for user {user_id}: {str(e)}")
            return Response({
                "message": "Internal server error",
                "detail": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserRoleUpdateView(APIView):
    """
    Update user role (admin only)
    """
    permission_classes = [IsAuthenticated, CanChangeRole]
    
    @swagger_auto_schema(
        operation_summary="Update User Role",
        operation_description="Update user role (admin only)",
        request_body=RoleUpdateSerializer,
        responses={
            200: UserResponseSerializer,
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "User not found"
        },
        tags=['User Management']
    )
    def put(self, request, user_id):
        try:
            user = get_object_or_404(OrgUser, id=user_id)
            
            # Check permissions
            self.check_object_permissions(request, user)
            
            # Prevent admin from changing their own role
            if user == request.user:
                return Response({
                    "message": "Cannot change your own role"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            serializer = RoleUpdateSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({
                    "message": "Validation failed",
                    "errors": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
            
            old_role = user.role
            user.role = serializer.validated_data['role']
            user.save()
            
            response_serializer = UserResponseSerializer(user)
            
            logger.info(f"User role changed: {user.email} from {old_role} to {user.role} by {request.user.email}")
            return Response({
                "message": "User role updated successfully",
                "user": response_serializer.data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error updating role for user {user_id}: {str(e)}")
            return Response({
                "message": "Internal server error",
                "detail": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class OrganizationUsersView(APIView):
    """
    Get all users in an organization
    """
    permission_classes = [IsAuthenticated, IsOrganizationMember]
    
    @swagger_auto_schema(
        operation_summary="Get Organization Users",
        operation_description="Get all users in a specific organization",
        responses={
            200: OrganizationUsersSerializer,
            401: "Unauthorized",
            403: "Forbidden",
            404: "Organization not found"
        },
        tags=['User Management']
    )
    def get(self, request, org_id):
        try:
            organization = get_object_or_404(Organization, id=org_id)
            
            # Check if user can access this organization
            if request.user.org != organization:
                return Response({
                    "message": "Access denied"
                }, status=status.HTTP_403_FORBIDDEN)
            
            serializer = OrganizationUsersSerializer(organization)
            return Response(serializer.data, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error getting organization users {org_id}: {str(e)}")
            return Response({
                "message": "Internal server error",
                "detail": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)