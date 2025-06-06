import json
import uuid
from unittest.mock import patch
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from organizations.models.models import Organization, OrgUser

class UserCreateViewTest(TestCase):
    
    def setUp(self):
        """Set up test data"""
        self.client = APIClient()
        self.org = Organization.objects.create(name="Test Organization")
        self.create_user_url = reverse('create-user', kwargs={'org_id': self.org.id})
    
    def test_create_user_success(self):
        """Test successful user creation"""
        data = {
            'email': 'test@example.com',
            'name': 'Test User',
            'role': 'member'
        }
        
        response = self.client.post(
            self.create_user_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['message'], 'User account created successfully')
        self.assertEqual(response.data['email'], 'test@example.com')
        self.assertEqual(response.data['role'], 'member')
        self.assertEqual(response.data['org_id'], str(self.org.id))
        
        # Verify user was created in database
        user = OrgUser.objects.get(email='test@example.com')
        self.assertEqual(user.name, 'Test User')
        self.assertEqual(user.org, self.org)
    
    def test_create_user_invalid_org(self):
        """Test user creation with invalid organization ID"""
        invalid_org_id = uuid.uuid4()
        url = reverse('create-user', kwargs={'org_id': invalid_org_id})
        
        data = {
            'email': 'test@example.com',
            'name': 'Test User',
            'role': 'member'
        }
        
        response = self.client.post(
            url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
    
    def test_create_user_duplicate_email(self):
        """Test user creation with duplicate email"""
        # Create first user
        OrgUser.objects.create(
            email='test@example.com',
            name='First User',
            role='member',
            org=self.org
        )
        
        # Try to create second user with same email
        data = {
            'email': 'test@example.com',
            'name': 'Second User',
            'role': 'admin'
        }
        
        response = self.client.post(
            self.create_user_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertIn('already exists', response.data['message'])
    
    def test_create_user_invalid_data(self):
        """Test user creation with invalid data"""
        data = {
            'email': 'invalid-email',
            'name': '',
            'role': 'invalid_role'
        }
        
        response = self.client.post(
            self.create_user_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_create_user_missing_fields(self):
        """Test user creation with missing required fields"""
        data = {'email': 'test@example.com'}  # Missing name and role
        
        response = self.client.post(
            self.create_user_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

class InternalUserViewTest(TestCase):
    
    def setUp(self):
        """Set up test data"""
        self.client = APIClient()
        self.org = Organization.objects.create(name="Test Organization")
        self.user = OrgUser.objects.create(
            email='test@example.com',
            name='Test User',
            role='member',
            org=self.org
        )
        self.internal_user_url = reverse('internal-user', kwargs={'email': 'test@example.com'})
    
    @patch('organizations.permissions.ServiceTokenPermission.has_permission')
    def test_get_user_success(self, mock_permission):
        """Test successful retrieval of user info"""
        mock_permission.return_value = True
        
        response = self.client.get(self.internal_user_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['role'], 'member')
        self.assertEqual(response.data['user_id'], str(self.user.id))
        self.assertEqual(response.data['org_id'], str(self.org.id))
    
    def test_get_user_unauthorized(self):
        """Test unauthorized access to internal API"""
        response = self.client.get(self.internal_user_url)
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
    
    @patch('organizations.permissions.ServiceTokenPermission.has_permission')
    def test_get_nonexistent_user(self, mock_permission):
        """Test retrieval of non-existent user"""
        mock_permission.return_value = True
        
        url = reverse('internal-user', kwargs={'email': 'nonexistent@example.com'})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)