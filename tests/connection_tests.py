import json
from unittest.mock import patch, MagicMock
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model
from organization.models.data_source_model import DataSourceConfig
from organization.models.organization_model import Organization
from organization.config.service_config import SERVICE_CONFIGS, SERVICE_API_ENDPOINTS
import requests

class ConnectionTests(APITestCase):
    def setUp(self):
        # Create and authenticate a test user
        User = get_user_model()
        self.user = User.objects.create_user(username="testuser", password="testpass123")
        self.client.force_authenticate(user=self.user)
        
        # Create test organization
        self.organization = Organization.objects.create(
            name="Test Org",
            email="test@org.com",
            phone="+123456789",
            address="123 Test St",
            website="http://test.org",
            industry="Testing",
            size=50
        )
        
        # Create test Microsoft 365 data source
        self.ms365_source = DataSourceConfig.objects.create(
            service_name='microsoft_365',
            connection_id='ms365-test-1',
            tenant_id='test-tenant',
            description='Test Microsoft 365 connection',
            api_endpoint=SERVICE_API_ENDPOINTS['microsoft_365'],
            auth_type=SERVICE_CONFIGS['microsoft_365']['auth_type'],
            client_id='test-client-id',
            client_secret='test-client-secret',
            scopes=','.join(SERVICE_CONFIGS['microsoft_365']['default_scopes']),
            status='not_connected',
            organisation=self.organization
        )
        
        # Create test Dropbox data source
        self.dropbox_source = DataSourceConfig.objects.create(
            service_name='dropbox',
            connection_id='dropbox-test-1',
            description='Test Dropbox connection',
            api_endpoint=SERVICE_API_ENDPOINTS['dropbox'],
            auth_type=SERVICE_CONFIGS['dropbox']['auth_type'],
            api_key='test-api-key',
            status='not_connected',
            organisation=self.organization
        )

    @patch('organization.services.connection_service.requests.post')
    def test_connect_microsoft365_valid_credentials(self, mock_post):
        """Test connecting with valid Microsoft 365 credentials."""
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        url = reverse('datasource-connect', kwargs={'pk': self.ms365_source.id})
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'success')
        self.assertEqual(response.data['connection_id'], 'ms365-test-1')
        
        # Verify status was updated in database
        self.ms365_source.refresh_from_db()
        self.assertEqual(self.ms365_source.status, 'connected')

    @patch('organization.services.connection_service.requests.post')
    def test_connect_microsoft365_invalid_credentials(self, mock_post):
        """Test connecting with invalid Microsoft 365 credentials."""
        # Mock unauthorized response
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_post.return_value = mock_response
        
        url = reverse('datasource-connect', kwargs={'pk': self.ms365_source.id})
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['status'], 'error')
        self.assertEqual(response.data['error_code'], 'invalid_credentials')
        
        # Verify status was updated in database
        self.ms365_source.refresh_from_db()
        self.assertEqual(self.ms365_source.status, 'invalid_credentials')

    @patch('organization.services.connection_service.requests.post')
    def test_connect_dropbox_valid_credentials(self, mock_post):
        """Test connecting with valid Dropbox credentials."""
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        url = reverse('datasource-connect', kwargs={'pk': self.dropbox_source.id})
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'success')
        self.assertEqual(response.data['connection_id'], 'dropbox-test-1')
        
        # Verify status was updated in database
        self.dropbox_source.refresh_from_db()
        self.assertEqual(self.dropbox_source.status, 'connected')

    @patch('organization.services.connection_service.requests.post')
    def test_connect_dropbox_invalid_credentials(self, mock_post):
        """Test connecting with invalid Dropbox credentials."""
        # Mock unauthorized response
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_post.return_value = mock_response
        
        url = reverse('datasource-connect', kwargs={'pk': self.dropbox_source.id})
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['status'], 'error')
        self.assertEqual(response.data['error_code'], 'invalid_credentials')
        
        # Verify status was updated in database
        self.dropbox_source.refresh_from_db()
        self.assertEqual(self.dropbox_source.status, 'invalid_credentials')

    def test_connect_nonexistent_source(self):
        """Test connecting to a non-existent data source."""
        url = reverse('datasource-connect', kwargs={'pk': 99999})
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data['status'], 'error')
        self.assertEqual(response.data['message'], 'Data source configuration not found')

    @patch('organization.services.connection_service.requests.post')
    def test_connect_insufficient_permissions(self, mock_post):
        """Test connecting with insufficient permissions."""
        # Mock forbidden response
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_post.return_value = mock_response
        
        url = reverse('datasource-connect', kwargs={'pk': self.ms365_source.id})
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['status'], 'error')
        self.assertEqual(response.data['error_code'], 'insufficient_permissions')
        
        # Verify status was updated in database
        self.ms365_source.refresh_from_db()
        self.assertEqual(self.ms365_source.status, 'insufficient_permissions')

    @patch('organization.services.connection_service.requests.post')
    def test_connect_connection_error(self, mock_post):
        """Test connecting when there's a connection error."""
        # Mock connection error
        mock_post.side_effect = requests.exceptions.RequestException()
        
        url = reverse('datasource-connect', kwargs={'pk': self.ms365_source.id})
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['status'], 'error')
        self.assertEqual(response.data['error_code'], 'connection_error')
        
        # Verify status was updated in database
        self.ms365_source.refresh_from_db()
        self.assertEqual(self.ms365_source.status, 'connection_error') 