import json
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from organization.models.organization_model import Organization

LOG_FILE = "organization_tests.log"

def write_log_block(title, url, method, payload, expected, response):
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write("\n------------------------------------------------------------\n")
        log.write(f"URL: {url}\n")
        log.write(f"Test: {title}\n")
        log.write(f"Method: {method}\n")
        if payload:
            log.write(f"Payload: {json.dumps(payload)}\n")
        log.write(f"Expected Status: {expected}\n")
        log.write(f"Actual Status:   {response.status_code}\n")
        log.write(f"Response: {response.data}\n")
        result = "PASSED" if response.status_code == expected else "FAILED"
        log.write(f"Result: {result}\n")
        log.write("------------------------------------------------------------\n")

class OrganizationTests(APITestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Test Org",
            email="test@org.com",
            phone="+123456789",
            address="123 Test St",
            website="http://test.org",
            industry="Testing",
            size=50
        )

    def test_create_organization(self):
        url = "/api/organization/"
        payload = {
            "name": "Acme Corp",
            "email": "info@acme.com",
            "phone": "+1234567890",
            "address": "100 Main St",
            "website": "http://acme.com",
            "industry": "Tech",
            "size": "200",
            "owner_id": None,
        }
        response = self.client.post(url, data=payload, format='json')
        write_log_block("Create Organization", url, "POST", payload, status.HTTP_201_CREATED, response)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_retrieve_organization(self):
        url = f"/api/organization/{self.organization.id}/"
        response = self.client.get(url)
        write_log_block("Retrieve Organization", url, "GET", None, status.HTTP_200_OK, response)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_list_organization(self):
        url = "/api/organization/list/"
        response = self.client.get(url)
        write_log_block("List Organizations", url, "GET", None, status.HTTP_200_OK, response)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_update_organization(self):
        url = f"/api/organization/{self.organization.id}/update/"
        payload = {"name": "Updated Org"}
        response = self.client.put(url, data=payload, format='json')
        write_log_block("Update Organization", url, "PUT", payload, status.HTTP_200_OK, response)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_delete_organization(self):
        url = f"/api/organization/{self.organization.id}/delete/"
        response = self.client.delete(url)
        write_log_block("Delete Organization", url, "DELETE", None, status.HTTP_204_NO_CONTENT, response)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
