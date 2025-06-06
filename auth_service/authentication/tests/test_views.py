import json
from unittest.mock import patch, Mock
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from authentication.models.models import AuthUser

class LoginViewTest(TestCase):
    
    def setUp(self):
        """Set up test data"""
        self.client = APIClient()
        self.login_url = reverse('login')
        
        self.email = "test@example.com"
        self.password = "testpassword123"
        
        # Create test user
        self.user = AuthUser(email=self.email)
        self.user.set_password(self.password)
        self.user.save()
    
    @patch('authentication.views.views.AuthenticationService.get_user_org_info')
    def test_successful_login(self, mock_get_org_info):
        """Test successful login"""
        # Mock org service response
        mock_get_org_info.return_value = {
            'user_id': 'user_123',
            'org_id': 'org_456',
            'role': 'member'
        }
        
        data = {
            'email': self.email,
            'password': self.password
        }
        
        response = self.client.post(
            self.login_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)
        self.assertEqual(response.data['message'], 'Login successful')
    
    def test_invalid_credentials(self):
        """Test login with invalid credentials"""
        data = {
            'email': self.email,
            'password': 'wrongpassword'
        }
        
        response = self.client.post(
            self.login_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['message'], 'Invalid credentials')
    
    def test_missing_email(self):
        """Test login with missing email"""
        data = {'password': self.password}
        
        response = self.client.post(
            self.login_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_missing_password(self):
        """Test login with missing password"""
        data = {'email': self.email}
        
        response = self.client.post(
            self.login_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    @patch('authentication.views.views.AuthenticationService.get_user_org_info')
    def test_org_service_unavailable(self, mock_get_org_info):
        """Test handling when org service is unavailable"""
        mock_get_org_info.side_effect = Exception("Organization service unavailable")
        
        data = {
            'email': self.email,
            'password': self.password
        }
        
        response = self.client.post(
            self.login_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_503_SERVICE_UNAVAILABLE)
        self.assertEqual(response.data['message'], 'Service unavailable')