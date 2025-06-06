import uuid
from django.test import TestCase
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from organizations.models.models import Organization, OrgUser

class OrganizationModelTest(TestCase):
    
    def test_create_organization(self):
        """Test creating an organization"""
        org = Organization.objects.create(name="Test Organization")
        
        self.assertEqual(org.name, "Test Organization")
        self.assertIsInstance(org.id, uuid.UUID)
        self.assertIsNotNone(org.created_at)
        self.assertIsNotNone(org.updated_at)
    
    def test_organization_str_representation(self):
        """Test string representation of Organization"""
        org = Organization.objects.create(name="Test Organization")
        self.assertEqual(str(org), "Test Organization")

class OrgUserModelTest(TestCase):
    
    def setUp(self):
        """Set up test data"""
        self.org = Organization.objects.create(name="Test Organization")
        self.valid_email = "test@example.com"
        self.valid_name = "Test User"
        self.valid_role = "member"
    
    def test_create_org_user(self):
        """Test creating an OrgUser"""
        user = OrgUser.objects.create(
            email=self.valid_email,
            name=self.valid_name,
            role=self.valid_role,
            org=self.org
        )
        
        self.assertEqual(user.email, self.valid_email)
        self.assertEqual(user.name, self.valid_name)
        self.assertEqual(user.role, self.valid_role)
        self.assertEqual(user.org, self.org)
        self.assertIsInstance(user.id, uuid.UUID)
        self.assertIsNotNone(user.created_at)
        self.assertIsNotNone(user.updated_at)
    
    def test_email_uniqueness(self):
        """Test that email must be unique across all users"""
        # Create first user
        OrgUser.objects.create(
            email=self.valid_email,
            name=self.valid_name,
            role=self.valid_role,
            org=self.org
        )
        
        # Create second organization
        org2 = Organization.objects.create(name="Another Organization")
        
        # Try to create second user with same email in different org
        with self.assertRaises(IntegrityError):
            OrgUser.objects.create(
                email=self.valid_email,
                name="Another User",
                role="admin",
                org=org2
            )
    
    def test_valid_role_choices(self):
        """Test that only valid roles are accepted"""
        valid_roles = ['admin', 'member', 'viewer']
        
        for role in valid_roles:
            user = OrgUser(
                email=f"test_{role}@example.com",
                name=f"Test {role}",
                role=role,
                org=self.org
            )
            user.clean()  # Should not raise ValidationError
    
    def test_invalid_role_choice(self):
        """Test that invalid role raises ValidationError"""
        user = OrgUser(
            email=self.valid_email,
            name=self.valid_name,
            role="invalid_role",
            org=self.org
        )
        
        with self.assertRaises(ValidationError):
            user.clean()
    
    def test_org_user_str_representation(self):
        """Test string representation of OrgUser"""
        user = OrgUser.objects.create(
            email=self.valid_email,
            name=self.valid_name,
            role=self.valid_role,
            org=self.org
        )
        
        expected = f"{self.valid_email} ({self.org.name})"
        self.assertEqual(str(user), expected)