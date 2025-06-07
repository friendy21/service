from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from django.db import DatabaseError, IntegrityError
from django.core.exceptions import ValidationError
import logging
import jwt

logger = logging.getLogger(__name__)

class AuthenticationException(Exception):
    """Base authentication exception"""
    pass

class InvalidCredentialsException(AuthenticationException):
    """Invalid login credentials"""
    pass

class AccountLockedException(AuthenticationException):
    """Account is locked"""
    pass

class AccountInactiveException(AuthenticationException):
    """Account is inactive"""
    pass

class SessionExpiredException(AuthenticationException):
    """Session has expired"""
    pass

class TokenExpiredException(AuthenticationException):
    """Token has expired"""
    pass

class InvalidTokenException(AuthenticationException):
    """Invalid token"""
    pass

class RateLimitExceededException(AuthenticationException):
    """Rate limit exceeded"""
    pass

class ServiceUnavailableException(AuthenticationException):
    """External service unavailable"""
    pass

def custom_exception_handler(exc, context):
    """
    Custom exception handler for authentication service
    """
    response = exception_handler(exc, context)
    
    if response is not None:
        return response

    # Handle authentication-specific exceptions
    if isinstance(exc, InvalidCredentialsException):
        return Response({
            "message": "Invalid credentials",
            "error_code": "INVALID_CREDENTIALS",
            "detail": str(exc)
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    if isinstance(exc, AccountLockedException):
        return Response({
            "message": "Account is temporarily locked",
            "error_code": "ACCOUNT_LOCKED",
            "detail": str(exc)
        }, status=status.HTTP_423_LOCKED)
    
    if isinstance(exc, AccountInactiveException):
        return Response({
            "message": "Account is inactive",
            "error_code": "ACCOUNT_INACTIVE",
            "detail": str(exc)
        }, status=status.HTTP_403_FORBIDDEN)
    
    if isinstance(exc, SessionExpiredException):
        return Response({
            "message": "Session has expired",
            "error_code": "SESSION_EXPIRED",
            "detail": str(exc)
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    if isinstance(exc, TokenExpiredException):
        return Response({
            "message": "Token has expired",
            "error_code": "TOKEN_EXPIRED",
            "detail": str(exc)
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    if isinstance(exc, InvalidTokenException):
        return Response({
            "message": "Invalid token",
            "error_code": "INVALID_TOKEN",
            "detail": str(exc)
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    if isinstance(exc, RateLimitExceededException):
        return Response({
            "message": "Rate limit exceeded",
            "error_code": "RATE_LIMIT_EXCEEDED",
            "detail": str(exc)
        }, status=status.HTTP_429_TOO_MANY_REQUESTS)
    
    if isinstance(exc, ServiceUnavailableException):
        return Response({
            "message": "Service temporarily unavailable",
            "error_code": "SERVICE_UNAVAILABLE",
            "detail": str(exc)
        }, status=status.HTTP_503_SERVICE_UNAVAILABLE)

    # Handle JWT specific exceptions
    if isinstance(exc, jwt.ExpiredSignatureError):
        return Response({
            "message": "Token has expired",
            "error_code": "TOKEN_EXPIRED",
            "detail": "JWT token has expired"
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    if isinstance(exc, jwt.InvalidTokenError):
        return Response({
            "message": "Invalid token",
            "error_code": "INVALID_TOKEN",
            "detail": "JWT token is invalid"
        }, status=status.HTTP_401_UNAUTHORIZED)

    # Handle database errors
    if isinstance(exc, IntegrityError):
        if 'unique_email' in str(exc).lower():
            return Response({
                "message": "User with this email already exists",
                "error_code": "EMAIL_ALREADY_EXISTS",
                "detail": "Email must be unique"
            }, status=status.HTTP_409_CONFLICT)
        
        logger.error(f"Database integrity error: {str(exc)}")
        return Response({
            "message": "Database constraint violation",
            "error_code": "DATABASE_CONSTRAINT_ERROR",
            "detail": "Data integrity constraint violated"
        }, status=status.HTTP_400_BAD_REQUEST)
    
    if isinstance(exc, DatabaseError):
        logger.error(f"Database error: {str(exc)}")
        return Response({
            "message": "Database error",
            "error_code": "DATABASE_ERROR",
            "detail": "Database operation failed"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    # Handle validation errors
    if isinstance(exc, ValidationError):
        logger.error(f"Validation error: {str(exc)}")
        return Response({
            "message": "Validation failed",
            "error_code": "VALIDATION_ERROR",
            "detail": str(exc)
        }, status=status.HTTP_400_BAD_REQUEST)

    # Handle unexpected errors
    logger.error(f"Unexpected error: {str(exc)}", exc_info=True)
    return Response({
        "message": "Internal server error",
        "error_code": "INTERNAL_SERVER_ERROR",
        "detail": "An unexpected error occurred"
    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AuthenticationErrorHandler:
    """
    Helper class for handling authentication errors consistently
    """
    
    @staticmethod
    def handle_login_error(error_type, details=None):
        """
        Handle login-specific errors
        """
        error_responses = {
            'invalid_credentials': {
                'message': 'Invalid email or password',
                'error_code': 'INVALID_CREDENTIALS',
                'status': status.HTTP_401_UNAUTHORIZED
            },
            'account_locked': {
                'message': 'Account is temporarily locked due to multiple failed attempts',
                'error_code': 'ACCOUNT_LOCKED',
                'status': status.HTTP_423_LOCKED
            },
            'account_inactive': {
                'message': 'Account is inactive. Please contact support.',
                'error_code': 'ACCOUNT_INACTIVE',
                'status': status.HTTP_403_FORBIDDEN
            },
            'rate_limit_exceeded': {
                'message': 'Too many login attempts. Please try again later.',
                'error_code': 'RATE_LIMIT_EXCEEDED',
                'status': status.HTTP_429_TOO_MANY_REQUESTS
            },
            'service_unavailable': {
                'message': 'Authentication service is temporarily unavailable',
                'error_code': 'SERVICE_UNAVAILABLE',
                'status': status.HTTP_503_SERVICE_UNAVAILABLE
            }
        }
        
        error_info = error_responses.get(error_type, {
            'message': 'Authentication failed',
            'error_code': 'AUTHENTICATION_FAILED',
            'status': status.HTTP_401_UNAUTHORIZED
        })
        
        if details:
            error_info['details'] = details
        
        return error_info
    
    @staticmethod
    def handle_token_error(error_type, details=None):
        """
        Handle token-specific errors
        """
        error_responses = {
            'expired': {
                'message': 'Token has expired',
                'error_code': 'TOKEN_EXPIRED',
                'status': status.HTTP_401_UNAUTHORIZED
            },
            'invalid': {
                'message': 'Invalid token',
                'error_code': 'INVALID_TOKEN',
                'status': status.HTTP_401_UNAUTHORIZED
            },
            'malformed': {
                'message': 'Malformed token',
                'error_code': 'MALFORMED_TOKEN',
                'status': status.HTTP_400_BAD_REQUEST
            },
            'missing': {
                'message': 'Authentication token required',
                'error_code': 'MISSING_TOKEN',
                'status': status.HTTP_401_UNAUTHORIZED
            }
        }
        
        error_info = error_responses.get(error_type, {
            'message': 'Token validation failed',
            'error_code': 'TOKEN_VALIDATION_FAILED',
            'status': status.HTTP_401_UNAUTHORIZED
        })
        
        if details:
            error_info['details'] = details
        
        return error_info
    
    @staticmethod
    def handle_session_error(error_type, details=None):
        """
        Handle session-specific errors
        """
        error_responses = {
            'expired': {
                'message': 'Session has expired',
                'error_code': 'SESSION_EXPIRED',
                'status': status.HTTP_401_UNAUTHORIZED
            },
            'invalid': {
                'message': 'Invalid session',
                'error_code': 'INVALID_SESSION',
                'status': status.HTTP_401_UNAUTHORIZED
            },
            'revoked': {
                'message': 'Session has been revoked',
                'error_code': 'SESSION_REVOKED',
                'status': status.HTTP_401_UNAUTHORIZED
            },
            'not_found': {
                'message': 'Session not found',
                'error_code': 'SESSION_NOT_FOUND',
                'status': status.HTTP_404_NOT_FOUND
            }
        }
        
        error_info = error_responses.get(error_type, {
            'message': 'Session validation failed',
            'error_code': 'SESSION_VALIDATION_FAILED',
            'status': status.HTTP_401_UNAUTHORIZED
        })
        
        if details:
            error_info['details'] = details
        
        return error_info
    
    @staticmethod
    def handle_permission_error(error_type, details=None):
        """
        Handle permission-specific errors
        """
        error_responses = {
            'insufficient_permissions': {
                'message': 'Insufficient permissions',
                'error_code': 'INSUFFICIENT_PERMISSIONS',
                'status': status.HTTP_403_FORBIDDEN
            },
            'role_required': {
                'message': 'Required role not found',
                'error_code': 'ROLE_REQUIRED',
                'status': status.HTTP_403_FORBIDDEN
            },
            'organization_access_denied': {
                'message': 'Access to organization denied',
                'error_code': 'ORGANIZATION_ACCESS_DENIED',
                'status': status.HTTP_403_FORBIDDEN
            }
        }
        
        error_info = error_responses.get(error_type, {
            'message': 'Permission denied',
            'error_code': 'PERMISSION_DENIED',
            'status': status.HTTP_403_FORBIDDEN
        })
        
        if details:
            error_info['details'] = details
        
        return error_info


class SecurityLogger:
    """
    Security-specific logging helper
    """
    
    @staticmethod
    def log_security_event(event_type, user_email=None, ip_address=None, details=None):
        """
        Log security events with structured format
        """
        security_logger = logging.getLogger('authentication.security')
        
        log_data = {
            'event_type': event_type,
            'user_email': user_email,
            'ip_address': ip_address,
            'timestamp': timezone.now().isoformat(),
            'details': details or {}
        }
        
        security_logger.info(f"SECURITY_EVENT: {log_data}")
    
    @staticmethod
    def log_authentication_attempt(success, user_email, ip_address, details=None):
        """
        Log authentication attempts
        """
        event_type = 'AUTH_SUCCESS' if success else 'AUTH_FAILURE'
        SecurityLogger.log_security_event(
            event_type=event_type,
            user_email=user_email,
            ip_address=ip_address,
            details=details
        )
    
    @staticmethod
    def log_suspicious_activity(activity_type, ip_address, details=None):
        """
        Log suspicious activity
        """
        SecurityLogger.log_security_event(
            event_type=f'SUSPICIOUS_ACTIVITY:{activity_type}',
            ip_address=ip_address,
            details=details
        )
    
    @staticmethod
    def log_rate_limit_exceeded(endpoint, ip_address, details=None):
        """
        Log rate limit violations
        """
        SecurityLogger.log_security_event(
            event_type='RATE_LIMIT_EXCEEDED',
            ip_address=ip_address,
            details={'endpoint': endpoint, **(details or {})}
        )