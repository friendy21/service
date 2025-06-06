from django.test import TestCase
from rest_framework.exceptions import ValidationError
from authentication.serializers.serializers import LoginSerializer

class LoginSerializerTest(TestCase):
    
    def test_valid_data(self):
        """Test serializer with valid data"""
        data = {
            'email': 'test@example.com',
            'password': 'testpassword123'
        }
        serializer = LoginSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['email'], 'test@example.com')
    
    def test_email_normalization(self):
        """Test that email is normalized (lowercase, stripped)"""
        data = {
            'email': '  TEST@EXAMPLE.COM  ',
            'password': 'testpassword123'
        }
        serializer = LoginSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['email'], 'test@example.com')
    
    def test_missing_email(self):
        """Test validation fails when email is missing"""
        data = {'password': 'testpassword123'}
        serializer = LoginSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)
    
    def test_missing_password(self):
        """Test validation fails when password is missing"""
        data = {'email': 'test@example.com'}
        serializer = LoginSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)
    
    def test_empty_email(self):
        """Test validation fails with empty email"""
        data = {
            'email': '',
            'password': 'testpassword123'
        }
        serializer = LoginSerializer(data=data)
        self.assertFalse(serializer.is_valid())
    
    def test_invalid_email_format(self):
        """Test validation fails with invalid email format"""
        data = {
            'email': 'invalid-email',
            'password': 'testpassword123'
        }
        serializer = LoginSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)