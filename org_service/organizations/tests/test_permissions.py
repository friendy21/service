import time
import hmac
import hashlib
from unittest.mock import Mock
from django.test import TestCase
from django.conf import settings
from organizations.permissions import ServiceTokenPermission

class ServiceTokenPermissionTest(TestCase):
    
    def setUp(self):
        """Set up test data"""
        self.permission = ServiceTokenPermission()
        self.service_id = 'test-service'
        self.service_token = 'test-token'
        self.service_secret = 'test-secret'
        
        # Mock settings
        settings.SERVICE_TOKEN = self.service_token
        settings.SERVICE_SECRET = self.service_secret
    
    def _generate_valid_headers(self, method='GET', path='/test/', body=''):
        """Generate valid service authentication headers"""
        timestamp = str(int(time.time()))
        payload = f"{method}|{path}|{body}|{self.service_id}|{timestamp}"
        signature = hmac.new(
            self.service_secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return {
            'X-Service-Token': self.service_token,
            'X-Service-ID': self.service_id,
            'X-Timestamp': timestamp,
            'X-Signature': signature
        }
    
    def test_has_permission_success(self):
        """Test successful permission check"""
        # Create mock request
        request = Mock()
        request.method = 'GET'
        request.path = '/internal/users/test@example.com/'
        request.body = b''
        request.headers = self._generate_valid_headers(
            method='GET',
            path='/internal/users/test@example.com/',
            body=''
        )
        
        view = Mock()
        
        result = self.permission.has_permission(request, view)
        self.assertTrue(result)
    
    def test_missing_headers(self):
        """Test permission denied when headers are missing"""
        request = Mock()
        request.headers = {}
        view = Mock()
        
        result = self.permission.has_permission(request, view)
        self.assertFalse(result)
    
    def test_invalid_token(self):
        """Test permission denied with invalid token"""
        request = Mock()
        request.method = 'GET'
        request.path = '/test/'
        request.body = b''
        
        headers = self._generate_valid_headers()
        headers['X-Service-Token'] = 'invalid-token'
        request.headers = headers
        
        view = Mock()
        
        result = self.permission.has_permission(request, view)
        self.assertFalse(result)
    
    def test_expired_timestamp(self):
        """Test permission denied with expired timestamp"""
        request = Mock()
        request.method = 'GET'
        request.path = '/test/'
        request.body = b''
        
        # Generate headers with old timestamp
        old_timestamp = str(int(time.time()) - 400)  # 400 seconds ago
        payload = f"GET|/test/||{self.service_id}|{old_timestamp}"
        signature = hmac.new(
            self.service_secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        request.headers = {
            'X-Service-Token': self.service_token,
            'X-Service-ID': self.service_id,
            'X-Timestamp': old_timestamp,
            'X-Signature': signature
        }
        
        view = Mock()
        
        result = self.permission.has_permission(request, view)
        self.assertFalse(result)
    
    def test_invalid_signature(self):
        """Test permission denied with invalid signature"""
        request = Mock()
        request.method = 'GET'
        request.path = '/test/'
        request.body = b''
        
        headers = self._generate_valid_headers()
        headers['X-Signature'] = 'invalid-signature'
        request.headers = headers
        
        view = Mock()
        
        result = self.permission.has_permission(request, view)
        self.assertFalse(result)