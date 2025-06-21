import json
import uuid
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model
from organization.models.data_source_model import DataSourceConfig
from organization.models.organization_model import Organization
from organization.config.service_config import SERVICE_CONFIGS, SERVICE_API_ENDPOINTS

LOG_FILE = "data_source_tests.log"

def make_json_safe(obj):
    if isinstance(obj, dict):
        return {k: make_json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_json_safe(i) for i in obj]
    elif isinstance(obj, uuid.UUID):
        return str(obj)
    return obj

def write_log_block(title, url, method, payload, expected, response):
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write("\n------------------------------------------------------------\n")
        log.write(f"URL: {url}\n")
        log.write(f"Test: {title}\n")
        log.write(f"Method: {method}\n")
        if payload:
            safe_payload = make_json_safe(payload)
            log.write(f"Payload: {json.dumps(safe_payload)}\n")
        log.write(f"Expected Status: {expected}\n")
        log.write(f"Actual Status:   {response.status_code}\n")
        log.write(f"Response: {response.data}\n")
        result = "PASSED" if response.status_code == expected else "FAILED"
        log.write(f"Result: {result}\n")
        log.write("------------------------------------------------------------\n")

class DataSourceConfigTests(APITestCase):
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
        
        # Create test data source config
        self.data_source = DataSourceConfig.objects.create(
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

    def test_create_microsoft365_connection(self):
        """Test creating a Microsoft 365 connection with valid data."""
        url = reverse('microsoft365-connection')
        payload = {
            'tenant_id': 'test-tenant-2',
            'client_id': 'test-client-id-2',
            'client_secret': 'test-client-secret-2',
            'description': 'Test Microsoft 365 connection 2',
            'organisation': self.organization.id
        }
        response = self.client.post(url, data=payload, format='json')
        write_log_block("Create Microsoft 365 Connection", url, "POST", payload, status.HTTP_201_CREATED, response)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('connection_id', response.data)
        self.assertEqual(response.data['status'], 'not_connected')

    def test_create_microsoft365_connection_missing_required_fields(self):
        """Test creating a Microsoft 365 connection with missing required fields."""
        url = reverse('microsoft365-connection')
        payload = {
            'description': 'Test Microsoft 365 connection',
            'organisation': self.organization.id
        }
        response = self.client.post(url, data=payload, format='json')
        write_log_block("Create Microsoft 365 Connection Missing Fields", url, "POST", payload, status.HTTP_400_BAD_REQUEST, response)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_dropbox_connection(self):
        """Test creating a Dropbox connection with valid data."""
        url = reverse('dropbox-connection')
        payload = {
            'api_key': 'test-dropbox-api-key',
            'description': 'Test Dropbox connection',
            'organisation': self.organization.id
        }
        response = self.client.post(url, data=payload, format='json')
        write_log_block("Create Dropbox Connection", url, "POST", payload, status.HTTP_201_CREATED, response)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('connection_id', response.data)

    def test_retrieve_data_source(self):
        """Test retrieving a data source configuration."""
        url = reverse('datasource-retrieve', kwargs={'pk': self.data_source.id})
        response = self.client.get(url)
        write_log_block("Retrieve Data Source", url, "GET", None, status.HTTP_200_OK, response)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['service_name'], 'Microsoft 365')
        self.assertEqual(response.data['connection_id'], 'ms365-test-1')

    def test_list_data_sources(self):
        """Test listing all data source configurations."""
        url = reverse('datasource-list')
        response = self.client.get(url)
        write_log_block("List Data Sources", url, "GET", None, status.HTTP_200_OK, response)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_update_data_source(self):
        """Test updating a data source configuration."""
        url = reverse('datasource-update', kwargs={'pk': self.data_source.id})
        payload = {
            'description': 'Updated description',
            'status': 'connected'
        }
        response = self.client.put(url, data=payload, format='json')
        write_log_block("Update Data Source", url, "PUT", payload, status.HTTP_200_OK, response)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['description'], 'Updated description')
        self.assertEqual(response.data['status'], 'connected')

    def test_delete_data_source(self):
        """Test deleting a data source configuration."""
        url = reverse('datasource-delete', kwargs={'pk': self.data_source.id})
        response = self.client.delete(url)
        write_log_block("Delete Data Source", url, "DELETE", None, status.HTTP_204_NO_CONTENT, response)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        
        # Verify deletion
        url = reverse('datasource-retrieve', kwargs={'pk': self.data_source.id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_model_validation_microsoft365(self):
        """Test DataSourceConfig model validation for Microsoft 365."""
        # Test with valid data
        valid_data = {
            'service_name': 'microsoft_365',
            'connection_id': 'ms365-test-2',
            'tenant_id': 'test-tenant',
            'client_id': 'test-client-id',
            'client_secret': 'test-client-secret',
            'api_endpoint': SERVICE_API_ENDPOINTS['microsoft_365'],
            'auth_type': SERVICE_CONFIGS['microsoft_365']['auth_type'],
            'organisation': self.organization
        }
        data_source = DataSourceConfig(**valid_data)
        data_source.full_clean()  # Should not raise any validation errors
        
        # Test with missing required field
        invalid_data = valid_data.copy()
        del invalid_data['client_id']
        data_source = DataSourceConfig(**invalid_data)
        with self.assertRaises(Exception):
            data_source.full_clean()

    def test_model_validation_dropbox(self):
        """Test DataSourceConfig model validation for Dropbox."""
        # Test with valid data
        valid_data = {
            'service_name': 'dropbox',
            'connection_id': 'dropbox-test-1',
            'api_key': 'test-api-key',
            'api_endpoint': SERVICE_API_ENDPOINTS['dropbox'],
            'auth_type': SERVICE_CONFIGS['dropbox']['auth_type'],
            'organisation': self.organization
        }
        data_source = DataSourceConfig(**valid_data)
        data_source.full_clean()  # Should not raise any validation errors
        
        # Test with missing required field
        invalid_data = valid_data.copy()
        del invalid_data['api_key']
        data_source = DataSourceConfig(**invalid_data)
        with self.assertRaises(Exception):
            data_source.full_clean()

    def test_default_scopes(self):
        """Test that default scopes are applied when not provided."""
        url = reverse('microsoft365-connection')
        payload = {
            'tenant_id': 'test-tenant-3',
            'client_id': 'test-client-id-3',
            'client_secret': 'test-client-secret-3',
            'organisation': self.organization.id
        }
        response = self.client.post(url, data=payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Verify default scopes were applied
        data_source = DataSourceConfig.objects.get(connection_id=response.data['connection_id'])
        expected_scopes = ','.join(SERVICE_CONFIGS['microsoft_365']['default_scopes'])
        self.assertEqual(data_source.scopes, expected_scopes)

    def test_invalid_service_name(self):
        """Test creating a connection with an invalid service name."""
        url = reverse('datasource-create')
        payload = {
            'service_name': 'invalid_service',
            'connection_id': 'test-1',
            'organisation': self.organization.id
        }
        response = self.client.post(url, data=payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('service_name', response.data) 