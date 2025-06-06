import json
from unittest.mock import patch, Mock
from django.test import TestCase
from django.conf import settings
from authentication.models.models import AuthUser
from authentication.services.services import AuthenticationService
import jwt
from datetime import datetime

class AuthenticationServiceTest(TestCase):
    
    def setUp(self):
        """Set up test data"""
        self.email = "test@example.com"
        self.password = "testpassword123"
        self.user = AuthUser(email=self.email)
        self.user.set_password(self.password)
        self.user.save()
        
        self.auth_service = AuthenticationService()
    
    def test_authenticate_user_success(self):
        """Test successful user authentication"""
        authenticated_user = AuthenticationService.authenticate_user(
            self.email, self.password
        )
        self.assertIsNotNone(authenticated_user)
        self.assertEqual(authenticated_user.email, self.email)
    
    def test_authenticate_user_wrong_password(self):
        """Test authentication fails with wrong password"""
        authenticated_user = AuthenticationService.authenticate_user(
            self.email, "wrongpassword"
        )
        self.assertIsNone(authenticated_user)
    
    def test_authenticate_user_nonexistent_email(self):
        """Test authentication fails with non-existent email"""
        authenticated_user = AuthenticationService.authenticate_user(
            "nonexistent@example.com", self.password
        )
        self.assertIsNone(authenticated_user)
    
    @patch('authentication.services.services.requests')
    def test_get_user_org_info_success(self, mock_requests):
        """Test successful retrieval of user org info"""
        # Mock successful response from org service
        mock_response = Mock()
        mock_response.json.return_value = {
            'user_id': 'user_123',
            'org_id': 'org_456',
            'role': 'member'
        }
        mock_response.raise_for_status.return_value = None
        mock_requests.get.return_value = mock_response
        
        result = self.auth_service.get_user_org_info(self.email)
        
        self.assertEqual(result['user_id'], 'user_123')
        self.assertEqual(result['org_id'], 'org_456')
        self.assertEqual(result['role'], 'member')
    
    @patch('authentication.services.services.requests')
    def test_get_user_org_info_connection_error(self, mock_requests):
        """Test handling of connection error to org service"""
        mock_requests.get.side_effect = Exception("Connection error")
        
        with self.assertRaises(Exception) as context:
            self.auth_service.get_user_org_info(self.email)
        
        self.assertIn("Organization service error", str(context.exception))
    
    @patch('authentication.services.services.requests')
    def test_get_user_org_info_404_error(self, mock_requests):
        """Test handling of 404 error from org service"""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = Exception("404 error")
        mock_response.status_code = 404
        mock_requests.get.return_value = mock_response
        mock_requests.exceptions.HTTPError = Exception
        
        with self.assertRaises(Exception):
            self.auth_service.get_user_org_info(self.email)
    
    def test_generate_jwt_token(self):
        """Test JWT token generation"""
        email = "test@example.com"
        user_id = "user_123"
        org_id = "org_456"
        role = "member"
        
        token = AuthenticationService.generate_jwt_token(
            email, user_id, org_id, role
        )
        
        # Decode and verify token
        decoded = jwt.decode(
            token, 
            settings.JWT_SECRET, 
            algorithms=['HS256']
        )
        
        self.assertEqual(decoded['sub'], user_id)
        self.assertEqual(decoded['email'], email)
        self.assertEqual(decoded['org_id'], org_id)
        self.assertEqual(decoded['role'], role)
        self.assertEqual(decoded['iss'], 'auth-service')
        self.assertIn('exp', decoded)
        self.assertIn('iat', decoded)