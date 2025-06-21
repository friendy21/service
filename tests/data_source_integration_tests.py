import json
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model
from organization.models.data_source_model import DataSourceConfig
from organization.models.organization_model import Organization
from organization.config.service_config import SERVICE_CONFIGS, SERVICE_API_ENDPOINTS

class DataSourceConfigIntegrationTests(APITestCase):
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

    def test_create_and_update_flow(self):
        """Test the complete flow of creating and updating a data source configuration."""
        # Step 1: Create Microsoft 365 connection
        url = reverse('microsoft365-connection')
        create_payload = {
            'tenant_id': 'test-tenant',
            'client_id': 'test-client-id',
            'client_secret': 'test-client-secret',
            'description': 'Test Microsoft 365 connection',
            'organisation': self.organization.id
        }
        create_response = self.client.post(url, data=create_payload, format='json')
        self.assertEqual(create_response.status_code, status.HTTP_201_CREATED)
        connection_id = create_response.data['connection_id']

        # Step 2: Retrieve the created configuration
        retrieve_url = reverse('datasource-retrieve', kwargs={'pk': create_response.data['id']})
        retrieve_response = self.client.get(retrieve_url)
        self.assertEqual(retrieve_response.status_code, status.HTTP_200_OK)
        self.assertEqual(retrieve_response.data['connection_id'], connection_id)
        self.assertEqual(retrieve_response.data['status'], 'not_connected')

        # Step 3: Update the configuration
        update_url = reverse('datasource-update', kwargs={'pk': create_response.data['id']})
        update_payload = {
            'description': 'Updated description',
            'status': 'connected'
        }
        update_response = self.client.put(update_url, data=update_payload, format='json')
        self.assertEqual(update_response.status_code, status.HTTP_200_OK)
        self.assertEqual(update_response.data['description'], 'Updated description')
        self.assertEqual(update_response.data['status'], 'connected')

        # Step 4: Verify the update in the list view
        list_url = reverse('datasource-list')
        list_response = self.client.get(list_url)
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(list_response.data), 1)
        self.assertEqual(list_response.data[0]['status'], 'connected')

    def test_multiple_connections_same_service(self):
        """Test creating multiple connections for the same service."""
        # Create first Microsoft 365 connection
        url = reverse('microsoft365-connection')
        payload1 = {
            'tenant_id': 'test-tenant-1',
            'client_id': 'test-client-id-1',
            'client_secret': 'test-client-secret-1',
            'description': 'First Microsoft 365 connection',
            'organisation': self.organization.id
        }
        response1 = self.client.post(url, data=payload1, format='json')
        self.assertEqual(response1.status_code, status.HTTP_201_CREATED)

        # Create second Microsoft 365 connection
        payload2 = {
            'tenant_id': 'test-tenant-2',
            'client_id': 'test-client-id-2',
            'client_secret': 'test-client-secret-2',
            'description': 'Second Microsoft 365 connection',
            'organisation': self.organization.id
        }
        response2 = self.client.post(url, data=payload2, format='json')
        self.assertEqual(response2.status_code, status.HTTP_201_CREATED)

        # Verify both connections exist and are different
        self.assertNotEqual(response1.data['connection_id'], response2.data['connection_id'])
        
        # Verify in list view
        list_url = reverse('datasource-list')
        list_response = self.client.get(list_url)
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(list_response.data), 2)

    def test_cross_service_validation(self):
        """Test validation across different service types."""
        # Create Microsoft 365 connection
        ms365_url = reverse('microsoft365-connection')
        ms365_payload = {
            'tenant_id': 'test-tenant',
            'client_id': 'test-client-id',
            'client_secret': 'test-client-secret',
            'organisation': self.organization.id
        }
        ms365_response = self.client.post(ms365_url, data=ms365_payload, format='json')
        self.assertEqual(ms365_response.status_code, status.HTTP_201_CREATED)

        # Create Dropbox connection
        dropbox_url = reverse('dropbox-connection')
        dropbox_payload = {
            'api_key': 'test-dropbox-api-key',
            'organisation': self.organization.id
        }
        dropbox_response = self.client.post(dropbox_url, data=dropbox_payload, format='json')
        self.assertEqual(dropbox_response.status_code, status.HTTP_201_CREATED)

        # Verify both connections have correct auth types and endpoints
        list_url = reverse('datasource-list')
        list_response = self.client.get(list_url)
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        
        connections = {conn['service_name']: conn for conn in list_response.data}
        
        # Verify Microsoft 365 connection
        self.assertEqual(
            connections['Microsoft 365']['auth_type'],
            SERVICE_CONFIGS['microsoft_365']['auth_type']
        )
        self.assertEqual(
            connections['Microsoft 365']['api_endpoint'],
            SERVICE_API_ENDPOINTS['microsoft_365']
        )

        # Verify Dropbox connection
        self.assertEqual(
            connections['DropBox']['auth_type'],
            SERVICE_CONFIGS['dropbox']['auth_type']
        )
        self.assertEqual(
            connections['DropBox']['api_endpoint'],
            SERVICE_API_ENDPOINTS['dropbox']
        )

    def test_connection_id_uniqueness(self):
        """Test that connection IDs are unique across services."""
        # Create Microsoft 365 connection
        ms365_url = reverse('microsoft365-connection')
        ms365_payload = {
            'tenant_id': 'test-tenant',
            'client_id': 'test-client-id',
            'client_secret': 'test-client-secret',
            'organisation': self.organization.id
        }
        ms365_response = self.client.post(ms365_url, data=ms365_payload, format='json')
        self.assertEqual(ms365_response.status_code, status.HTTP_201_CREATED)
        ms365_connection_id = ms365_response.data['connection_id']

        # Create Dropbox connection
        dropbox_url = reverse('dropbox-connection')
        dropbox_payload = {
            'api_key': 'test-dropbox-api-key',
            'organisation': self.organization.id
        }
        dropbox_response = self.client.post(dropbox_url, data=dropbox_payload, format='json')
        self.assertEqual(dropbox_response.status_code, status.HTTP_201_CREATED)
        dropbox_connection_id = dropbox_response.data['connection_id']

        # Verify connection IDs are different
        self.assertNotEqual(ms365_connection_id, dropbox_connection_id)

        # Verify both connection IDs are unique in the database
        connection_ids = DataSourceConfig.objects.values_list('connection_id', flat=True)
        self.assertEqual(len(connection_ids), 2)
        self.assertEqual(len(set(connection_ids)), 2)  # All IDs should be unique 