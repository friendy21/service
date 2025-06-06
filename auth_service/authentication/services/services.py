import jwt
import requests
import hmac
import hashlib
import time
from datetime import datetime, timedelta
from django.conf import settings
from authentication.models.models import AuthUser
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
    def authenticate_user(email, password):
        """
        Authenticate user credentials against AuthUser model
        """
        try:
            user = AuthUser.objects.get(email=email)
            if user.check_password(password):
                return user
            return None
        except AuthUser.DoesNotExist:
            return None

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
    def generate_jwt_token(email, user_id, org_id, role):
        """
        Generate JWT token with user information
        """
        payload = {
            'sub': user_id,
            'email': email,
            'org_id': org_id,
            'role': role,
            'exp': datetime.utcnow() + timedelta(hours=1),
            'iat': datetime.utcnow(),
            'iss': 'auth-service'  # Token issuer
        }
        
        token = jwt.encode(payload, settings.JWT_SECRET, algorithm='HS256')
        return token