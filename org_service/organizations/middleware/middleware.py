import logging
import time
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)

class ServiceLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log internal service API calls for security monitoring
    """
    def process_request(self, request):
        # Only log internal API calls
        if request.path.startswith('/internal/'):
            request._service_call_start_time = time.time()
            
            # Log service call details
            service_id = request.headers.get('X-Service-ID', 'unknown')
            client_ip = self._get_client_ip(request)
            
            logger.info(f"Internal API call: {request.method} {request.path} "
                       f"from service={service_id} ip={client_ip}")
    
    def process_response(self, request, response):
        # Log response time for internal API calls
        if hasattr(request, '_service_call_start_time'):
            duration = time.time() - request._service_call_start_time
            service_id = request.headers.get('X-Service-ID', 'unknown')
            
            logger.info(f"Internal API response: {response.status_code} "
                       f"for service={service_id} duration={duration:.3f}s")
        
        return response
    
    def _get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip