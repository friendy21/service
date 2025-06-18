# org_service/organizations/middleware/auth_middleware.py
import jwt
import logging
from django.conf import settings
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import cache
from organizations.models.models import OrgUser
import time

logger = logging.getLogger(__name__)

class JWTAuthenticationMiddleware(MiddlewareMixin):
    """
    Middleware to handle JWT authentication for protected endpoints
    """
    
    # Endpoints that don't require authentication
    EXEMPT_PATHS = [
        '/admin/',
        '/swagger/',
        '/redoc/',
        '/swagger.json',
        '/internal/',  # Internal service endpoints use different auth
        '/',  # Root swagger endpoint
    ]
    
    # Endpoints that require authentication
    PROTECTED_PATHS = [
        '/orgs/users/',
        '/orgs/organization/',
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
            
        # Check if this endpoint requires authentication
        if not self._requires_authentication(request.path):
            return None
        
        # Get Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if not auth_header.startswith('Bearer '):
            return JsonResponse({
                'message': 'Authentication required',
                'error': 'missing_token'
            }, status=401)
        
        # Extract JWT token
        jwt_token = auth_header[7:]  # Remove 'Bearer ' prefix
        
        try:
            # Validate JWT token
            payload = self._validate_jwt_token(jwt_token)
            
            if not payload:
                return JsonResponse({
                    'message': 'Invalid or expired token',
                    'error': 'invalid_token'
                }, status=401)
            
            # Get user from payload
            try:
                user = OrgUser.objects.get(email=payload['email'], is_active=True)
                request.user = user
                request.jwt_payload = payload
                
            except OrgUser.DoesNotExist:
                return JsonResponse({
                    'message': 'User not found or inactive',
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
        return any(path.startswith(protected) for protected in self.PROTECTED_PATHS)
    
    def _validate_jwt_token(self, token):
        """
        Validate JWT token and return payload
        """
        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=['HS256'])
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid JWT token")
            return None
        except Exception as e:
            logger.error(f"JWT validation error: {str(e)}")
            return None


class RateLimitingMiddleware(MiddlewareMixin):
    """
    Simple rate limiting middleware
    """
    
    def process_request(self, request):
        # Get client IP
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        
        # Apply rate limiting to sensitive endpoints
        sensitive_endpoints = [
            '/orgs/users/',
            '/orgs/organization/',
        ]
        
        if any(request.path.startswith(endpoint) for endpoint in sensitive_endpoints):
            # Check rate limit (100 requests per hour per IP)
            cache_key = f"rate_limit:{ip}:{request.path}"
            current_count = cache.get(cache_key, 0)
            
            if current_count >= 100:
                return JsonResponse({
                    'message': 'Rate limit exceeded. Try again later.',
                    'error': 'rate_limit_exceeded'
                }, status=429)
            
            # Increment counter (1 hour window)
            cache.set(cache_key, current_count + 1, 3600)
        
        return None


class AuditLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log user actions for audit purposes
    """
    
    def process_request(self, request):
        request._start_time = time.time()
        return None
    
    def process_response(self, request, response):
        # Log user actions if authenticated
        if hasattr(request, 'user') and hasattr(request, '_start_time'):
            duration = time.time() - request._start_time
            
            logger.info(f"User action: {request.user.email} "
                       f"{request.method} {request.path} "
                       f"status={response.status_code} "
                       f"duration={duration:.3f}s")
        
        return response


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