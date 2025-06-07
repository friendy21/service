import jwt
import logging
from django.conf import settings
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from authentication.services.services import AuthenticationService
from authentication.models.models import AuthUser, UserSession

logger = logging.getLogger(__name__)

class JWTAuthenticationMiddleware(MiddlewareMixin):
    """
    Middleware to handle JWT authentication for protected endpoints
    """
    
    # Endpoints that don't require authentication
    EXEMPT_PATHS = [
        '/auth/login/',
        '/auth/logout/',
        '/auth/refresh/',
        '/auth/password/reset/',
        '/auth/password/reset/confirm/',
        '/auth/email/verify/',
        '/admin/',
        '/swagger/',
        '/redoc/',
        '/internal/',  # Internal service endpoints use different auth
    ]
    
    def process_request(self, request):
        """
        Process incoming request and validate JWT if needed
        """
        # Skip authentication for exempt paths
        if any(request.path.startswith(exempt) for exempt in self.EXEMPT_PATHS):
            return None
        
        # Skip authentication for OPTIONS requests (CORS preflight)
        if request.method == 'OPTIONS':
            return None
            
        # Get Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if not auth_header.startswith('Bearer '):
            # Check if this endpoint requires authentication
            if self._requires_authentication(request.path):
                return JsonResponse({
                    'message': 'Authentication required',
                    'error': 'missing_token'
                }, status=401)
            return None
        
        # Extract JWT token
        jwt_token = auth_header[7:]  # Remove 'Bearer ' prefix
        
        try:
            # Validate JWT token
            payload, message = AuthenticationService.validate_jwt_token(jwt_token)
            
            if not payload:
                return JsonResponse({
                    'message': message,
                    'error': 'invalid_token'
                }, status=401)
            
            # Get user from payload
            try:
                user = AuthUser.objects.get(email=payload['email'])
                request.user = user
                request.jwt_payload = payload
                
                # Update session last accessed time if session_id is present
                session_id = payload.get('session_id')
                if session_id:
                    try:
                        session = UserSession.objects.get(id=session_id, status='active')
                        session.last_accessed = timezone.now()
                        session.save(update_fields=['last_accessed'])
                        request.user_session = session
                    except UserSession.DoesNotExist:
                        logger.warning(f"Session {session_id} not found for user {user.email}")
                
            except AuthUser.DoesNotExist:
                return JsonResponse({
                    'message': 'User not found',
                    'error': 'user_not_found'
                }, status=401)
                
        except Exception as e:
            logger.error(f"JWT validation error: {str(e)}")
            return JsonResponse({
                'message': 'Token validation failed',
                'error': 'token_validation_error'
            }, status=401)
        
        return None
    
    def _requires_authentication(self, path):
        """
        Determine if the given path requires authentication
        """
        # Paths that require authentication
        protected_paths = [
            '/auth/logout-all/',
            '/auth/password/change/',
            '/auth/sessions/',
            '/auth/security/',
            '/orgs/',  # Organization endpoints
        ]
        
        return any(path.startswith(protected) for protected in protected_paths)


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Add security headers to all responses
    """
    
    def process_response(self, request, response):
        # Security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        # HSTS header for HTTPS
        if request.is_secure():
            response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        
        return response


class RateLimitMiddleware(MiddlewareMixin):
    """
    Simple rate limiting middleware
    """
    
    def process_request(self, request):
        from django.core.cache import cache
        from authentication.services.services import SecurityService
        
        # Get client IP
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        
        # Apply rate limiting to sensitive endpoints
        sensitive_endpoints = [
            '/auth/login/',
            '/auth/password/reset/',
            '/auth/email/verify/',
        ]
        
        if any(request.path.startswith(endpoint) for endpoint in sensitive_endpoints):
            # Check rate limit
            rate_check, rate_message = SecurityService.check_rate_limit(
                identifier=ip,
                action=f'endpoint:{request.path}',
                limit=10,
                window=300  # 5 minutes
            )
            
            if not rate_check:
                return JsonResponse({
                    'message': rate_message,
                    'error': 'rate_limit_exceeded'
                }, status=429)
        
        return None