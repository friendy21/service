import jwt
import requests
import hmac
import hashlib
import time
import secrets
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from django.core.cache import cache
from authentication.models.models import AuthUser, UserSession, EmailVerification, PasswordResetToken, AuditLog
import logging

logger = logging.getLogger(__name__)

class ServiceClient:
    """
    Secure client for making authenticated requests to other services
    """
    def __init__(self, service_id='auth-service'):
        self.service_id = service_id
        self.service_token = settings.SERVICE_TOKEN
        self.service_secret = settings.SERVICE_SECRET
        
    def _generate_signature(self, method, path, body=''):
        """
        Generate HMAC signature for service request
        """
        timestamp = str(int(time.time()))
        payload = f"{method}|{path}|{body}|{self.service_id}|{timestamp}"
        
        signature = hmac.new(
            self.service_secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return signature, timestamp
    
    def _get_service_headers(self, method, path, body=''):
        """
        Generate headers for service authentication
        """
        signature, timestamp = self._generate_signature(method, path, body)
        
        return {
            'X-Service-Token': self.service_token,
            'X-Service-ID': self.service_id,
            'X-Timestamp': timestamp,
            'X-Signature': signature,
            'Content-Type': 'application/json',
            'User-Agent': f'Django-Service/{self.service_id}'
        }
    
    def get(self, url, **kwargs):
        """
        Make authenticated GET request to another service
        """
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path
        
        headers = self._get_service_headers('GET', path)
        headers.update(kwargs.get('headers', {}))
        kwargs['headers'] = headers
        
        return requests.get(url, **kwargs)


class AuthenticationService:
    def __init__(self):
        self.service_client = ServiceClient()
    
    @staticmethod
    def authenticate_user(email, password, ip_address, user_agent=None):
        """
        Authenticate user credentials with enhanced security
        """
        try:
            user = AuthUser.objects.get(email=email.lower())
            
            # Check if account is locked
            if user.is_locked():
                AuditLog.log_event(
                    action='login_failed',
                    ip_address=ip_address,
                    user=user,
                    user_agent=user_agent,
                    details={'reason': 'account_locked'}
                )
                return None, "Account is temporarily locked due to multiple failed attempts"
            
            # Check if account is active
            if not user.is_active:
                AuditLog.log_event(
                    action='login_failed',
                    ip_address=ip_address,
                    user=user,
                    user_agent=user_agent,
                    details={'reason': 'account_inactive'}
                )
                return None, "Account is inactive"
            
            # Verify password
            if user.check_password(password):
                # Reset failed attempts on successful login
                user.reset_failed_attempts()
                
                AuditLog.log_event(
                    action='login_success',
                    ip_address=ip_address,
                    user=user,
                    user_agent=user_agent
                )
                return user, "Login successful"
            else:
                # Increment failed attempts
                user.increment_failed_attempts()
                
                AuditLog.log_event(
                    action='login_failed',
                    ip_address=ip_address,
                    user=user,
                    user_agent=user_agent,
                    details={'reason': 'invalid_password', 'failed_attempts': user.failed_login_attempts}
                )
                return None, "Invalid credentials"
                
        except AuthUser.DoesNotExist:
            # Log failed attempt for non-existent user
            AuditLog.log_event(
                action='login_failed',
                ip_address=ip_address,
                user_agent=user_agent,
                details={'reason': 'user_not_found', 'email': email}
            )
            return None, "Invalid credentials"

    def get_user_org_info(self, email):
        """
        Get user organization information from Organization Service with enhanced security
        """
        url = f"{settings.ORG_SERVICE_URL}/internal/users/{email}/"
        
        try:
            # Use enhanced service client for secure communication
            response = self.service_client.get(url, timeout=(3.05, 27))
            response.raise_for_status()
            
            logger.info(f"Successfully retrieved org info for user: {email}")
            return response.json()
            
        except requests.exceptions.Timeout:
            logger.error(f"Timeout calling org service for user {email}")
            raise Exception("Organization service timeout")
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error calling org service for user {email}")
            raise Exception("Organization service unavailable")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.error(f"User {email} not found in org service")
                raise Exception("User not found in organization")
            elif e.response.status_code == 403:
                logger.error(f"Service authentication failed for org service")
                raise Exception("Service authentication failed")
            logger.error(f"HTTP error calling org service: {e}")
            raise Exception("Organization service error")
        except Exception as e:
            logger.error(f"Unexpected error calling org service: {str(e)}")
            raise Exception("Organization service error")

    @staticmethod
    def create_user_session(user, ip_address, user_agent=None, device_id=None, device_type='web', device_name=None):
        """
        Create a new user session with tokens
        """
        # Clean up expired sessions
        UserSession.objects.filter(user=user, expires_at__lt=timezone.now()).update(status='expired')
        
        # Generate tokens
        session_token, refresh_token = UserSession.generate_tokens()
        
        # Create session
        session = UserSession.objects.create(
            user=user,
            session_token=session_token,
            refresh_token=refresh_token,
            device_id=device_id,
            device_type=device_type,
            device_name=device_name,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=timezone.now() + timedelta(hours=24)  # 24 hour session
        )
        
        return session

    @staticmethod
    def generate_jwt_token(session, org_info):
        """
        Generate JWT token with session and user information
        """
        payload = {
            'sub': org_info['user_id'],
            'session_id': str(session.id),
            'email': session.user.email,
            'org_id': org_info['org_id'],
            'role': org_info['role'],
            'exp': datetime.utcnow() + timedelta(hours=1),  # 1 hour JWT
            'iat': datetime.utcnow(),
            'iss': 'auth-service',
            'password_changed_at': int(session.user.password_changed_at.timestamp())
        }
        
        token = jwt.encode(payload, settings.JWT_SECRET, algorithm='HS256')
        return token

    @staticmethod
    def logout_user(session_token, ip_address, user_agent=None):
        """
        Logout user from specific session
        """
        try:
            session = UserSession.objects.get(session_token=session_token, status='active')
            session.revoke()
            
            AuditLog.log_event(
                action='logout',
                ip_address=ip_address,
                user=session.user,
                user_agent=user_agent,
                details={'session_id': str(session.id), 'device_type': session.device_type}
            )
            
            return True, "Logged out successfully"
        except UserSession.DoesNotExist:
            return False, "Invalid session"

    @staticmethod
    def logout_all_devices(user, ip_address, user_agent=None):
        """
        Logout user from all active sessions
        """
        active_sessions = UserSession.objects.filter(user=user, status='active')
        session_count = active_sessions.count()
        
        # Revoke all active sessions
        active_sessions.update(status='revoked')
        
        AuditLog.log_event(
            action='logout_all',
            ip_address=ip_address,
            user=user,
            user_agent=user_agent,
            details={'revoked_sessions': session_count}
        )
        
        return session_count

    @staticmethod
    def refresh_session(refresh_token, ip_address):
        """
        Refresh session with new tokens
        """
        try:
            session = UserSession.objects.get(refresh_token=refresh_token, status='active')
            
            if session.is_expired():
                session.status = 'expired'
                session.save()
                return None, "Session expired"
            
            # Generate new tokens
            new_session_token, new_refresh_token = session.refresh()
            
            # Generate new JWT
            try:
                org_info = AuthenticationService().get_user_org_info(session.user.email)
                jwt_token = AuthenticationService.generate_jwt_token(session, org_info)
                
                return {
                    'session_token': new_session_token,
                    'refresh_token': new_refresh_token,
                    'jwt_token': jwt_token
                }, "Session refreshed"
            except Exception as e:
                logger.error(f"Failed to refresh session for user {session.user.email}: {str(e)}")
                return None, "Failed to refresh session"
                
        except UserSession.DoesNotExist:
            return None, "Invalid refresh token"

    @staticmethod
    def validate_jwt_token(token):
        """
        Validate JWT token and check session status
        """
        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=['HS256'])
            
            # Check if session is still active
            session_id = payload.get('session_id')
            if session_id:
                try:
                    session = UserSession.objects.get(id=session_id, status='active')
                    if session.is_expired():
                        return None, "Session expired"
                    
                    # Check if password was changed after token issuance
                    password_changed_at = payload.get('password_changed_at')
                    if password_changed_at and password_changed_at < int(session.user.password_changed_at.timestamp()):
                        return None, "Token invalidated due to password change"
                    
                    return payload, "Valid token"
                except UserSession.DoesNotExist:
                    return None, "Session not found"
            
            return payload, "Valid token"
            
        except jwt.ExpiredSignatureError:
            return None, "Token expired"
        except jwt.InvalidTokenError:
            return None, "Invalid token"

    @staticmethod
    def get_user_sessions(user):
        """
        Get all active sessions for a user
        """
        return UserSession.objects.filter(user=user, status='active').order_by('-last_accessed')


class VerificationService:
    """
    Service for handling email verification and password reset
    """
    
    @staticmethod
    def create_email_verification(user):
        """
        Create email verification token
        """
        # Revoke existing unused tokens
        EmailVerification.objects.filter(user=user, is_used=False).update(is_used=True)
        
        verification = EmailVerification.create_verification_token(user)
        return verification.token

    @staticmethod
    def verify_email(token, ip_address):
        """
        Verify email with token
        """
        try:
            verification = EmailVerification.objects.get(token=token)
            
            if not verification.is_valid():
                return False, "Token is invalid or expired"
            
            # Mark token as used and user as verified
            verification.use_token()
            verification.user.is_verified = True
            verification.user.save()
            
            AuditLog.log_event(
                action='email_verified',
                ip_address=ip_address,
                user=verification.user
            )
            
            return True, "Email verified successfully"
            
        except EmailVerification.DoesNotExist:
            return False, "Invalid verification token"

    @staticmethod
    def create_password_reset_token(email, ip_address):
        """
        Create password reset token
        """
        try:
            user = AuthUser.objects.get(email=email.lower(), is_active=True)
            reset_token = PasswordResetToken.create_reset_token(user)
            
            AuditLog.log_event(
                action='password_reset_requested',
                ip_address=ip_address,
                user=user
            )
            
            return reset_token.token, "Reset token created"
            
        except AuthUser.DoesNotExist:
            # Don't reveal if email exists
            return None, "If the email exists, a reset token has been sent"

    @staticmethod
    def reset_password(token, new_password, ip_address):
        """
        Reset password with token
        """
        try:
            reset_token = PasswordResetToken.objects.get(token=token)
            
            if not reset_token.is_valid():
                return False, "Token is invalid or expired"
            
            # Update password and mark token as used
            user = reset_token.user
            user.set_password(new_password)
            user.save()
            
            reset_token.use_token()
            
            # Revoke all active sessions (force re-login)
            UserSession.objects.filter(user=user, status='active').update(status='revoked')
            
            AuditLog.log_event(
                action='password_reset_completed',
                ip_address=ip_address,
                user=user
            )
            
            return True, "Password reset successfully"
            
        except PasswordResetToken.DoesNotExist:
            return False, "Invalid reset token"


class SecurityService:
    """
    Security-related utilities and checks
    """
    
    @staticmethod
    def check_rate_limit(identifier, action, limit=5, window=300):
        """
        Check rate limiting for actions (using Redis/Cache)
        """
        cache_key = f"rate_limit:{action}:{identifier}"
        current_count = cache.get(cache_key, 0)
        
        if current_count >= limit:
            return False, f"Rate limit exceeded. Try again in {window} seconds."
        
        # Increment counter
        cache.set(cache_key, current_count + 1, window)
        return True, "Within rate limit"

    @staticmethod
    def detect_suspicious_activity(user, ip_address):
        """
        Detect suspicious login patterns
        """
        recent_logs = AuditLog.objects.filter(
            user=user,
            timestamp__gte=timezone.now() - timedelta(hours=1)
        ).order_by('-timestamp')
        
        # Check for multiple IPs
        recent_ips = set(log.ip_address for log in recent_logs[:10])
        if len(recent_ips) > 3:
            return True, "Multiple IP addresses detected"
        
        # Check for rapid login attempts
        login_attempts = recent_logs.filter(action__in=['login_success', 'login_failed'])[:5]
        if len(login_attempts) >= 5:
            return True, "Rapid login attempts detected"
        
        return False, "Normal activity"

    @staticmethod
    def get_security_summary(user):
        """
        Get security summary for user
        """
        now = timezone.now()
        
        return {
            'active_sessions': UserSession.objects.filter(user=user, status='active').count(),
            'last_login': user.last_login,
            'password_changed_at': user.password_changed_at,
            'failed_attempts': user.failed_login_attempts,
            'is_locked': user.is_locked(),
            'is_verified': user.is_verified,
            'recent_logins': AuditLog.objects.filter(
                user=user,
                action='login_success',
                timestamp__gte=now - timedelta(days=30)
            ).count(),
            'recent_devices': UserSession.objects.filter(
                user=user,
                created_at__gte=now - timedelta(days=30)
            ).values('device_type', 'device_name').distinct()
        }