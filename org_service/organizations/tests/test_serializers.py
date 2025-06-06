from django.test import TestCase
from organizations.models.models import Organization, OrgUser
from organizations.serializers.serializers import (
    UserCreateSerializer, UserResponseSerializer, InternalUserSerializer
)

class UserCreateSerializerTest(TestCase):
    
    def test_valid_data(self):
        """Test serializer with valid data"""
        data = {
            'email': 'test@example.com',
            'name': 'Test User',
            'role': 'member'
        }
        serializer = UserCreateSerializer(data=data)
        self.assertTrue(serializer.is_valid())
    
    def test_email_normalization(self):
        """Test that email is normalized"""
        data = {
            'email': '  TEST@EXAMPLE.COM  ',
            'name': 'Test User',
            'role': 'member'
        }
        serializer = UserCreateSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['email'], 'test@example.com')
    
    def test_name_stripping(self):
        """Test that name is stripped of whitespace"""
        data = {
            'email': 'test@example.com',
            'name': '  Test User  ',
            'role': 'member'
        }
        serializer = UserCreateSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['name'], 'Test User')
    
    def test_missing_required_fields(self):
        """Test validation fails when required fields are missing"""
        # Missing email
        data = {'name': 'Test User', 'role': 'member'}
        serializer = UserCreateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)
        
        # Missing name
        data = {'email': 'test@example.com', 'role': 'member'}
        serializer = UserCreateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('name', serializer.errors)
        
        # Missing role
        data = {'email': 'test@example.com', 'name': 'Test User'}
        serializer = UserCreateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('role', serializer.errors)
    
    def test_invalid_role(self):
        """Test validation fails with invalid role"""
        data = {
            'email': 'test@example.com',
            'name': 'Test User',
            'role': 'invalid_role'
        }
        serializer = UserCreateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('role', serializer.errors)

class UserResponseSerializerTest(TestCase):
    
    def setUp(self):
        """Set up test data"""
        self.org = Organization.objects.create(name="Test Organization")
        self.user = OrgUser.objects.create(
            email="test@example.com",
            name="Test User",
            role="member",
            org=self.org
        )
    
    def test_serialization(self):
        """Test serializing a user for response"""
        serializer = UserResponseSerializer(self.user)
        data = serializer.data
        
        self.assertEqual(data['email'], 'test@example.com')
        self.assertEqual(data['role'], 'member')
        self.assertEqual(data['user_id'], str(self.user.id))
        self.assertEqual(data['org_id'], str(self.org.id))

class InternalUserSerializerTest(TestCase):
    
    def setUp(self):
        """Set up test data"""
        self.org = Organization.objects.create(name="Test Organization")
        self.user = OrgUser.objects.create(
            email="test@example.com",
            name="Test User",
            role="admin",
            org=self.org
        )
    
    def test_serialization(self):
        """Test serializing a user for internal API"""
        serializer = InternalUserSerializer(self.user)
        data = serializer.data
        
        self.assertEqual(data['role'], 'admin')
        self.assertEqual(data['user_id'], str(self.user.id))
        self.assertEqual(data['org_id'], str(self.org.id))
        # Should not include email or name for internal API
        self.assertNotIn('email', data)
        self.assertNotIn('name', data)