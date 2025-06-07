import json
import uuid
from unittest.mock import patch, Mock
from django.test import TestCase, TransactionTestCase
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from rest_framework.test import APIClient
from rest_framework import status
from authentication.models.models import AuthUser, UserSession, EmailVerification, PasswordResetToken, AuditLog
from authentication.services.services import AuthenticationService, VerificationService, SecurityService

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
        self.assertFalse(user.is_locked())
    
    def test_password_hashing(self):
        """Test that passwords are properly hashed"""
        user = AuthUser(email=self.valid_email)
        user.set_password(self.valid_password)
        user.save()
        
        # Password should be hashed, not stored in plain text
        self.assertNotEqual(user.password, self.valid_password)
        self.assertTrue(user.password.startswith('pbkdf2_sha256$'))
    
    def test_account_locking(self):
        """Test account locking mechanism"""
        user = AuthUser.objects.create(email=self.valid_email)
        user.set_password(self.valid_password)
        user.save()
        
        # Test failed attempts increment
        for i in range(4):
            user.increment_failed_attempts()
            self.assertFalse(user.is_locked())
        
        # Fifth attempt should lock the account
        user.increment_failed_attempts()
        self.assertTrue(user.is_locked())
        
        # Reset should unlock
        user.reset_failed_attempts()
        self.assertFalse(user.is_locked())


class UserSessionModelTest(TestCase):
    
    def setUp(self):
        """Set up test data"""
        self.user = AuthUser.objects.create(email="test@example.com")
        self.user.set_password("testpass123")
        self.user.save()
    
    def test_create_session(self):
        """Test creating a user session"""
        session_token, refresh_token = UserSession.generate_tokens()
        
        session = UserSession.objects.create(
            user=self.user,
            session_token=session_token,
            refresh_token=refresh_token,
            ip_address="127.0.0.1",
            device_type="web",
            expires_at=timezone.now() + timedelta(hours=24)
        )
        
        self.assertEqual(session.user, self.user)
        self.assertTrue(session.is_active())
        self.assertFalse(session.is_expired())
    
    def test_session_expiry(self):
        """Test session expiry"""
        session_token, refresh_token = UserSession.generate_tokens()
        
        session = UserSession.objects.create(
            user=self.user,
            session_token=session_token,
            refresh_token=refresh_token,
            ip_address="127.0.0.1",
            expires_at=timezone.now() - timedelta(hours=1)  # Expired
        )
        
        self.assertTrue(session.is_expired())
        self.assertFalse(session.is_active())
    
    def test_session_revocation(self):
        """Test session revocation"""
        session_token, refresh_token = UserSession.generate_tokens()
        
        session = UserSession.objects.create(
            user=self.user,
            session_token=session_token,
            refresh_token=refresh_token,
            ip_address="127.0.0.1",
            expires_at=timezone.now() + timedelta(hours=24)
        )
        
        session.revoke()
        self.assertEqual(session.status, 'revoked')
        self.assertFalse(session.is_active())


class AuthenticationServiceTest(TransactionTestCase):
    
    def setUp(self):
        """Set up test data"""
        self.email = "test@example.com"
        self.password = "testpassword123"
        self.ip_address = "127.0.0.1"
        self.user_agent = "Mozilla/5.0 Test Browser"
        
        self.user = AuthUser(email=self.email)
        self.user.set_password(self.password)
        self.user.save()
    
    def test_authenticate_user_success(self):
        """Test successful user authentication"""
        authenticated_user, message = AuthenticationService.authenticate_user(
            self.email, self.password, self.ip_address, self.user_agent
        )
        
        self.assertIsNotNone(authenticated_user)
        self.assertEqual(authenticated_user.email, self.email)
        self.assertEqual(message, "Login successful")
        
        # Check audit log
        audit_log = AuditLog.objects.filter(
            user=self.user,
            action='login_success'
        ).first()
        self.assertIsNotNone(audit_log)
    
    def test_authenticate_user_wrong_password(self):
        """Test authentication fails with wrong password"""
        authenticated_user, message = AuthenticationService.authenticate_user(
            self.email, "wrongpassword", self.ip_address, self.user_agent
        )
        
        self.assertIsN