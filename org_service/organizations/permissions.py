import hmac
import hashlib
import time
from rest_framework.permissions import BasePermission
from django.conf import settings

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
            return False
        
        # Check token
        if service_token != settings.SERVICE_TOKEN:
            return False
        
        # Check timestamp (prevent replay attacks)
        try:
            request_time = int(timestamp)
            current_time = int(time.time())
            if abs(current_time - request_time) > 300:  # 5 minutes tolerance
                return False
        except (ValueError, TypeError):
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
        
        return hmac.compare_digest(signature, expected_signature)