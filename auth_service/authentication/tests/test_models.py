from django.test import TestCase
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from authentication.models.models import AuthUser

class AuthUserModelTest(TestCase):
    
    def setUp(self):
        """Set up test data"""
        self.valid_email = "test@example.com"
        self.valid_password = "testpassword123"
    
    def test_create_auth_user(self):
        """Test creating a valid AuthUser"""
        user = AuthUser(email=self.valid_email)
        user.set_password(self.valid_password)
        user.save()
        
        self.assertEqual(user.email, self.valid_email)
        self.assertTrue(user.check_password(self.valid_password))
        self.assertFalse(user.check_password("wrongpassword"))
        self.assertIsNotNone(user.created_at)
    
    def test_email_uniqueness(self):
        """Test that email must be unique"""
        # Create first user
        user1 = AuthUser(email=self.valid_email)
        user1.set_password(self.valid_password)
        user1.save()
        
        # Try to create second user with same email
        user2 = AuthUser(email=self.valid_email)
        user2.set_password("anotherpassword")
        
        with self.assertRaises(IntegrityError):
            user2.save()
    
    def test_password_hashing(self):
        """Test that passwords are properly hashed"""
        user = AuthUser(email=self.valid_email)
        user.set_password(self.valid_password)
        user.save()
        
        # Password should be hashed, not stored in plain text
        self.assertNotEqual(user.password, self.valid_password)
        self.assertTrue(user.password.startswith('pbkdf2_sha256$'))
    
    def test_str_representation(self):
        """Test string representation of AuthUser"""
        user = AuthUser(email=self.valid_email)
        user.set_password(self.valid_password)
        user.save()
        
        self.assertEqual(str(user), self.valid_email)