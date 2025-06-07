from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from authentication.serializers.serializers import (
    LoginSerializer, LogoutSerializer, RefreshTokenSerializer,
    PasswordResetRequestSerializer, PasswordResetConfirmSerializer,
    EmailVerificationSerializer, ChangePasswordSerializer,
    UserSessionSerializer
)
from authentication.services.services import (
    AuthenticationService, VerificationService, SecurityService
)
from authentication.models.models import UserSession, AuthUser
import logging

logger = logging.getLogger(__name__)

def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def get_device_info(request):
    """Extract device information from request"""
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    device_id = request.headers.get('X-Device-ID')
    device_type = request.headers.get('X-Device-Type', 'web')
    device_name = request.headers.get('X-Device-Name')
    
    return {
        'user_agent': user_agent,
        'device_id': device_id,
        'device_type': device_type,
        'device_name': device_name
    }

@method_decorator(csrf_exempt, name='dispatch')
class LoginView(APIView):
    def __init__(self):
        super().__init__()
        self.auth_service = AuthenticationService()

    def post(self, request):
        """
        Enhanced login with session management and security checks
        """
        try:
            # Get client info
            ip_address = get_client_ip(request)
            device_info = get_device_info(request)
            
            # Validate request data
            serializer = LoginSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({
                    "message": "Invalid request data",
                    "errors": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            email = serializer.validated_data['email']
            password = serializer.validated_data['password']

            # Check rate limiting
            rate_check, rate_message = SecurityService.check_rate_limit(
                identifier=ip_address,
                action='login_attempt',
                limit=10,
                window=300  # 5 minutes
            )
            if not rate_check:
                return Response({
                    "message": rate_message
                }, status=status.HTTP_429_TOO_MANY_REQUESTS)

            # Authenticate user credentials
            auth_user, auth_message = AuthenticationService.authenticate_user(
                email, password, ip_address, device_info['user_agent']
            )
            
            if not auth_user:
                return Response({
                    "message": auth_message
                }, status=status.HTTP_401_UNAUTHORIZED)

            # Check for suspicious activity
            is_suspicious, suspicious_reason = SecurityService.detect_suspicious_activity(
                auth_user, ip_address
            )
            
            # Get user organization information
            try:
                org_info = self.auth_service.get_user_org_info(email)
            except Exception as e:
                logger.error(f"Failed to get org info for {email}: {str(e)}")
                return Response({
                    "message": "Service unavailable",
                    "detail": str(e)
                }, status=status.HTTP_503_SERVICE_UNAVAILABLE)

            # Create user session
            session = AuthenticationService.create_user_session(
                user=auth_user,
                ip_address=ip_address,
                user_agent=device_info['user_agent'],
                device_id=device_info['device_id'],
                device_type=device_info['device_type'],
                device_name=device_info['device_name']
            )

            # Generate JWT token
            jwt_token = AuthenticationService.generate_jwt_token(session, org_info)

            response_data = {
                "message": "Login successful",
                "access_token": jwt_token,
                "refresh_token": session.refresh_token,
                "session_id": str(session.id),
                "expires_in": 3600,  # 1 hour
                "user": {
                    "email": auth_user.email,
                    "is_verified": auth_user.is_verified,
                    "org_id": org_info['org_id'],
                    "role": org_info['role']
                }
            }

            # Add security warnings if suspicious
            if is_suspicious:
                response_data["security_warning"] = suspicious_reason

            logger.info(f"Successful login for user: {email}")
            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Unexpected error during login: {str(e)}")
            return Response({
                "message": "Internal server error",
                "detail": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutView(APIView):
    def post(self, request):
        """
        Logout from current session
        """
        try:
            ip_address = get_client_ip(request)
            device_info = get_device_info(request)
            
            serializer = LogoutSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({
                    "message": "Invalid request data",
                    "errors": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            session_token = serializer.validated_data.get('session_token')
            
            # If no session token provided, try to get from Authorization header
            if not session_token:
                auth_header = request.headers.get('Authorization', '')
                if auth_header.startswith('Bearer '):
                    # Extract session from JWT if needed
                    jwt_token = auth_header[7:]
                    payload, message = AuthenticationService.validate_jwt_token(jwt_token)
                    if payload:
                        session_id = payload.get('session_id')
                        if session_id:
                            try:
                                session = UserSession.objects.get(id=session_id)
                                session_token = session.session_token
                            except UserSession.DoesNotExist:
                                pass

            if not session_token:
                return Response({
                    "message": "Session token required"
                }, status=status.HTTP_400_BAD_REQUEST)

            success, message = AuthenticationService.logout_user(
                session_token, ip_address, device_info['user_agent']
            )

            if success:
                return Response({
                    "message": message
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "message": message
                }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"Error during logout: {str(e)}")
            return Response({
                "message": "Internal server error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutAllView(APIView):
    def post(self, request):
        """
        Logout from all devices/sessions
        """
        try:
            ip_address = get_client_ip(request)
            device_info = get_device_info(request)
            
            # Get user from JWT token
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return Response({
                    "message": "Authentication required"
                }, status=status.HTTP_401_UNAUTHORIZED)

            jwt_token = auth_header[7:]
            payload, message = AuthenticationService.validate_jwt_token(jwt_token)
            
            if not payload:
                return Response({
                    "message": message
                }, status=status.HTTP_401_UNAUTHORIZED)

            # Get user
            try:
                user = AuthUser.objects.get(email=payload['email'])
            except AuthUser.DoesNotExist:
                return Response({
                    "message": "User not found"
                }, status=status.HTTP_404_NOT_FOUND)

            # Logout from all devices
            session_count = AuthenticationService.logout_all_devices(
                user, ip_address, device_info['user_agent']
            )

            return Response({
                "message": f"Logged out from {session_count} devices",
                "revoked_sessions": session_count
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error during logout all: {str(e)}")
            return Response({
                "message": "Internal server error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RefreshTokenView(APIView):
    def post(self, request):
        """
        Refresh access token using refresh token
        """
        try:
            ip_address = get_client_ip(request)
            
            serializer = RefreshTokenSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({
                    "message": "Invalid request data",
                    "errors": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            refresh_token = serializer.validated_data['refresh_token']
            
            result, message = AuthenticationService.refresh_session(refresh_token, ip_address)
            
            if result:
                return Response({
                    "message": message,
                    "access_token": result['jwt_token'],
                    "refresh_token": result['refresh_token'],
                    "expires_in": 3600
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "message": message
                }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"Error during token refresh: {str(e)}")
            return Response({
                "message": "Internal server error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasswordResetRequestView(APIView):
    def post(self, request):
        """
        Request password reset token
        """
        try:
            ip_address = get_client_ip(request)
            
            serializer = PasswordResetRequestSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({
                    "message": "Invalid request data",
                    "errors": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            email = serializer.validated_data['email']
            
            # Check rate limiting
            rate_check, rate_message = SecurityService.check_rate_limit(
                identifier=email,
                action='password_reset_request',
                limit=3,
                window=3600  # 1 hour
            )
            if not rate_check:
                return Response({
                    "message": rate_message
                }, status=status.HTTP_429_TOO_MANY_REQUESTS)

            token, message = VerificationService.create_password_reset_token(email, ip_address)
            
            # Always return success to prevent email enumeration
            return Response({
                "message": "If the email exists, a password reset link has been sent"
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error during password reset request: {str(e)}")
            return Response({
                "message": "Internal server error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasswordResetConfirmView(APIView):
    def post(self, request):
        """
        Confirm password reset with token
        """
        try:
            ip_address = get_client_ip(request)
            
            serializer = PasswordResetConfirmSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({
                    "message": "Invalid request data",
                    "errors": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            token = serializer.validated_data['token']
            new_password = serializer.validated_data['new_password']
            
            success, message = VerificationService.reset_password(token, new_password, ip_address)
            
            if success:
                return Response({
                    "message": message
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "message": message
                }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"Error during password reset confirm: {str(e)}")
            return Response({
                "message": "Internal server error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class EmailVerificationView(APIView):
    def post(self, request):
        """
        Verify email with token
        """
        try:
            ip_address = get_client_ip(request)
            
            serializer = EmailVerificationSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({
                    "message": "Invalid request data",
                    "errors": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            token = serializer.validated_data['token']
            
            success, message = VerificationService.verify_email(token, ip_address)
            
            if success:
                return Response({
                    "message": message
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "message": message
                }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"Error during email verification: {str(e)}")
            return Response({
                "message": "Internal server error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """
        Change user password (requires authentication)
        """
        try:
            ip_address = get_client_ip(request)
            device_info = get_device_info(request)
            
            # Get user from JWT token
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return Response({
                    "message": "Authentication required"
                }, status=status.HTTP_401_UNAUTHORIZED)

            jwt_token = auth_header[7:]
            payload, message = AuthenticationService.validate_jwt_token(jwt_token)
            
            if not payload:
                return Response({
                    "message": message
                }, status=status.HTTP_401_UNAUTHORIZED)

            serializer = ChangePasswordSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({
                    "message": "Invalid request data",
                    "errors": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            current_password = serializer.validated_data['current_password']
            new_password = serializer.validated_data['new_password']
            
            # Get user and verify current password
            try:
                user = AuthUser.objects.get(email=payload['email'])
            except AuthUser.DoesNotExist:
                return Response({
                    "message": "User not found"
                }, status=status.HTTP_404_NOT_FOUND)

            if not user.check_password(current_password):
                return Response({
                    "message": "Current password is incorrect"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Update password
            user.set_password(new_password)
            user.save()
            
            # Option to logout from all other devices
            logout_all = serializer.validated_data.get('logout_all_devices', False)
            if logout_all:
                # Keep current session, revoke others
                current_session_id = payload.get('session_id')
                sessions_to_revoke = UserSession.objects.filter(
                    user=user, 
                    status='active'
                ).exclude(id=current_session_id) if current_session_id else UserSession.objects.filter(user=user, status='active')
                
                revoked_count = sessions_to_revoke.count()
                sessions_to_revoke.update(status='revoked')
            else:
                revoked_count = 0

            # Log the password change
            from authentication.models.models import AuditLog
            AuditLog.log_event(
                action='password_changed',
                ip_address=ip_address,
                user=user,
                user_agent=device_info['user_agent'],
                details={'logout_all_devices': logout_all, 'revoked_sessions': revoked_count}
            )

            response_data = {
                "message": "Password changed successfully"
            }
            
            if logout_all:
                response_data["revoked_sessions"] = revoked_count

            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error during password change: {str(e)}")
            return Response({
                "message": "Internal server error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserSessionsView(APIView):
    def get(self, request):
        """
        Get user's active sessions
        """
        try:
            # Get user from JWT token
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return Response({
                    "message": "Authentication required"
                }, status=status.HTTP_401_UNAUTHORIZED)

            jwt_token = auth_header[7:]
            payload, message = AuthenticationService.validate_jwt_token(jwt_token)
            
            if not payload:
                return Response({
                    "message": message
                }, status=status.HTTP_401_UNAUTHORIZED)

            # Get user
            try:
                user = AuthUser.objects.get(email=payload['email'])
            except AuthUser.DoesNotExist:
                return Response({
                    "message": "User not found"
                }, status=status.HTTP_404_NOT_FOUND)

            # Get user sessions
            sessions = AuthenticationService.get_user_sessions(user)
            serializer = UserSessionSerializer(sessions, many=True)
            
            return Response({
                "sessions": serializer.data,
                "total_sessions": len(serializer.data)
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error getting user sessions: {str(e)}")
            return Response({
                "message": "Internal server error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RevokeSessionView(APIView):
    def post(self, request, session_id):
        """
        Revoke a specific session
        """
        try:
            ip_address = get_client_ip(request)
            device_info = get_device_info(request)
            
            # Get user from JWT token
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return Response({
                    "message": "Authentication required"
                }, status=status.HTTP_401_UNAUTHORIZED)

            jwt_token = auth_header[7:]
            payload, message = AuthenticationService.validate_jwt_token(jwt_token)
            
            if not payload:
                return Response({
                    "message": message
                }, status=status.HTTP_401_UNAUTHORIZED)

            # Get user and session
            try:
                user = AuthUser.objects.get(email=payload['email'])
                session = UserSession.objects.get(id=session_id, user=user, status='active')
            except (AuthUser.DoesNotExist, UserSession.DoesNotExist):
                return Response({
                    "message": "Session not found"
                }, status=status.HTTP_404_NOT_FOUND)

            # Revoke session
            session.revoke()
            
            # Log the action
            from authentication.models.models import AuditLog
            AuditLog.log_event(
                action='session_revoked',
                ip_address=ip_address,
                user=user,
                user_agent=device_info['user_agent'],
                details={'revoked_session_id': str(session_id), 'device_type': session.device_type}
            )

            return Response({
                "message": "Session revoked successfully"
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error revoking session: {str(e)}")
            return Response({
                "message": "Internal server error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SecuritySummaryView(APIView):
    def get(self, request):
        """
        Get user security summary
        """
        try:
            # Get user from JWT token
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return Response({
                    "message": "Authentication required"
                }, status=status.HTTP_401_UNAUTHORIZED)

            jwt_token = auth_header[7:]
            payload, message = AuthenticationService.validate_jwt_token(jwt_token)
            
            if not payload:
                return Response({
                    "message": message
                }, status=status.HTTP_401_UNAUTHORIZED)

            # Get user
            try:
                user = AuthUser.objects.get(email=payload['email'])
            except AuthUser.DoesNotExist:
                return Response({
                    "message": "User not found"
                }, status=status.HTTP_404_NOT_FOUND)

            # Get security summary
            summary = SecurityService.get_security_summary(user)
            
            return Response(summary, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error getting security summary: {str(e)}")
            return Response({
                "message": "Internal server error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)