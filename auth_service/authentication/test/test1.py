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
        self.assertIsNone(authenticated_user)
        self.assertEqual(message, "Invalid credentials")
        
        # Check that failed attempts were incremented
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 1)
        
        # Check audit log
        audit_log = AuditLog.objects.filter(
            user=self.user,
            action='login_failed'
        ).first()
        self.assertIsNotNone(audit_log)
    
    def test_authenticate_user_account_locked(self):
        """Test authentication fails when account is locked"""
        # Lock the account
        self.user.locked_until = timezone.now() + timedelta(minutes=30)
        self.user.save()
        
        authenticated_user, message = AuthenticationService.authenticate_user(
            self.email, self.password, self.ip_address, self.user_agent
        )
        
        self.assertIsNone(authenticated_user)
        self.assertIn("locked", message.lower())
    
    def test_authenticate_user_inactive_account(self):
        """Test authentication fails for inactive account"""
        self.user.is_active = False
        self.user.save()
        
        authenticated_user, message = AuthenticationService.authenticate_user(
            self.email, self.password, self.ip_address, self.user_agent
        )
        
        self.assertIsNone(authenticated_user)
        self.assertEqual(message, "Account is inactive")
    
    def test_create_user_session(self):
        """Test creating user session"""
        session = AuthenticationService.create_user_session(
            user=self.user,
            ip_address=self.ip_address,
            user_agent=self.user_agent,
            device_type='web'
        )
        
        self.assertEqual(session.user, self.user)
        self.assertEqual(session.ip_address, self.ip_address)
        self.assertEqual(session.device_type, 'web')
        self.assertTrue(session.is_active())
    
    def test_logout_user(self):
        """Test user logout"""
        # Create session
        session = AuthenticationService.create_user_session(
            user=self.user,
            ip_address=self.ip_address,
            user_agent=self.user_agent
        )
        
        # Logout
        success, message = AuthenticationService.logout_user(
            session.session_token, self.ip_address, self.user_agent
        )
        
        self.assertTrue(success)
        self.assertEqual(message, "Logged out successfully")
        
        # Check session is revoked
        session.refresh_from_db()
        self.assertEqual(session.status, 'revoked')
    
    def test_logout_all_devices(self):
        """Test logout from all devices"""
        # Create multiple sessions
        session1 = AuthenticationService.create_user_session(
            user=self.user, ip_address="127.0.0.1", device_type='web'
        )
        session2 = AuthenticationService.create_user_session(
            user=self.user, ip_address="192.168.1.1", device_type='mobile'
        )
        
        # Logout from all devices
        revoked_count = AuthenticationService.logout_all_devices(
            self.user, self.ip_address, self.user_agent
        )
        
        self.assertEqual(revoked_count, 2)
        
        # Check sessions are revoked
        session1.refresh_from_db()
        session2.refresh_from_db()
        self.assertEqual(session1.status, 'revoked')
        self.assertEqual(session2.status, 'revoked')


class VerificationServiceTest(TestCase):
    
    def setUp(self):
        """Set up test data"""
        self.email = "test@example.com"
        self.ip_address = "127.0.0.1"
        self.user = AuthUser.objects.create(email=self.email)
        self.user.set_password("testpass123")
        self.user.save()
    
    def test_create_email_verification(self):
        """Test creating email verification token"""
        token = VerificationService.create_email_verification(self.user)
        
        self.assertIsNotNone(token)
        
        # Check verification record
        verification = EmailVerification.objects.get(token=token)
        self.assertEqual(verification.user, self.user)
        self.assertFalse(verification.is_used)
        self.assertTrue(verification.is_valid())
    
    def test_verify_email(self):
        """Test email verification"""
        token = VerificationService.create_email_verification(self.user)
        
        success, message = VerificationService.verify_email(token, self.ip_address)
        
        self.assertTrue(success)
        self.assertEqual(message, "Email verified successfully")
        
        # Check user is marked as verified
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_verified)
        
        # Check token is marked as used
        verification = EmailVerification.objects.get(token=token)
        self.assertTrue(verification.is_used)
    
    def test_create_password_reset_token(self):
        """Test creating password reset token"""
        token, message = VerificationService.create_password_reset_token(
            self.email, self.ip_address
        )
        
        self.assertIsNotNone(token)
        
        # Check reset record
        reset_token = PasswordResetToken.objects.get(token=token)
        self.assertEqual(reset_token.user, self.user)
        self.assertFalse(reset_token.is_used)
        self.assertTrue(reset_token.is_valid())
    
    def test_reset_password(self):
        """Test password reset"""
        token, _ = VerificationService.create_password_reset_token(
            self.email, self.ip_address
        )
        
        new_password = "newpassword123"
        success, message = VerificationService.reset_password(
            token, new_password, self.ip_address
        )
        
        self.assertTrue(success)
        self.assertEqual(message, "Password reset successfully")
        
        # Check password was changed
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))
        
        # Check token is marked as used
        reset_token = PasswordResetToken.objects.get(token=token)
        self.assertTrue(reset_token.is_used)
        
        # Check all sessions were revoked
        active_sessions = UserSession.objects.filter(user=self.user, status='active')
        self.assertEqual(active_sessions.count(), 0)


class LoginViewTest(TestCase):
    
    def setUp(self):
        """Set up test data"""
        self.client = APIClient()
        self.login_url = reverse('login')
        
        self.email = "test@example.com"
        self.password = "testpassword123"
        
        # Create test user
        self.user = AuthUser(email=self.email)
        self.user.set_password(self.password)
        self.user.save()
    
    @patch('authentication.services.services.AuthenticationService.get_user_org_info')
    def test_successful_login(self, mock_get_org_info):
        """Test successful login"""
        # Mock org service response
        mock_get_org_info.return_value = {
            'user_id': 'user_123',
            'org_id': 'org_456',
            'role': 'member'
        }
        
        data = {
            'email': self.email,
            'password': self.password
        }
        
        response = self.client.post(
            self.login_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)
        self.assertIn('session_id', response.data)
        self.assertEqual(response.data['message'], 'Login successful')
        
        # Check session was created
        session = UserSession.objects.filter(user=self.user, status='active').first()
        self.assertIsNotNone(session)
    
    def test_invalid_credentials(self):
        """Test login with invalid credentials"""
        data = {
            'email': self.email,
            'password': 'wrongpassword'
        }
        
        response = self.client.post(
            self.login_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['message'], 'Invalid credentials')
    
    def test_missing_fields(self):
        """Test login with missing fields"""
        data = {'email': self.email}  # Missing password
        
        response = self.client.post(
            self.login_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_account_locked_login(self):
        """Test login with locked account"""
        # Lock the account
        self.user.locked_until = timezone.now() + timedelta(minutes=30)
        self.user.save()
        
        data = {
            'email': self.email,
            'password': self.password
        }
        
        response = self.client.post(
            self.login_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('locked', response.data['message'].lower())


class LogoutViewTest(TestCase):
    
    def setUp(self):
        """Set up test data"""
        self.client = APIClient()
        self.logout_url = reverse('logout')
        
        self.user = AuthUser.objects.create(email="test@example.com")
        self.user.set_password("testpass123")
        self.user.save()
        
        # Create session
        self.session = AuthenticationService.create_user_session(
            user=self.user,
            ip_address="127.0.0.1",
            device_type='web'
        )
    
    def test_successful_logout(self):
        """Test successful logout"""
        data = {
            'session_token': self.session.session_token
        }
        
        response = self.client.post(
            self.logout_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Logged out successfully')
        
        # Check session is revoked
        self.session.refresh_from_db()
        self.assertEqual(self.session.status, 'revoked')
    
    def test_logout_invalid_session(self):
        """Test logout with invalid session token"""
        data = {
            'session_token': 'invalid-token'
        }
        
        response = self.client.post(
            self.logout_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['message'], 'Invalid session')


class RefreshTokenViewTest(TestCase):
    
    def setUp(self):
        """Set up test data"""
        self.client = APIClient()
        self.refresh_url = reverse('refresh-token')
        
        self.user = AuthUser.objects.create(email="test@example.com")
        self.user.set_password("testpass123")
        self.user.save()
        
        # Create session
        self.session = AuthenticationService.create_user_session(
            user=self.user,
            ip_address="127.0.0.1",
            device_type='web'
        )
    
    @patch('authentication.services.services.AuthenticationService.get_user_org_info')
    def test_successful_refresh(self, mock_get_org_info):
        """Test successful token refresh"""
        # Mock org service response
        mock_get_org_info.return_value = {
            'user_id': 'user_123',
            'org_id': 'org_456',
            'role': 'member'
        }
        
        data = {
            'refresh_token': self.session.refresh_token
        }
        
        response = self.client.post(
            self.refresh_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)
    
    def test_refresh_invalid_token(self):
        """Test refresh with invalid token"""
        data = {
            'refresh_token': 'invalid-token'
        }
        
        response = self.client.post(
            self.refresh_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class SecurityServiceTest(TestCase):
    
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        identifier = "127.0.0.1"
        action = "test_action"
        
        # Should allow requests within limit
        for i in range(5):
            allowed, message = SecurityService.check_rate_limit(
                identifier, action, limit=5, window=300
            )
            self.assertTrue(allowed)
        
        # Should block when limit exceeded
        allowed, message = SecurityService.check_rate_limit(
            identifier, action, limit=5, window=300
        )
        self.assertFalse(allowed)
        self.assertIn("Rate limit exceeded", message)
    
    def test_detect_suspicious_activity(self):
        """Test suspicious activity detection"""
        user = AuthUser.objects.create(email="test@example.com")
        
        # Create multiple recent logs from different IPs
        for i in range(5):
            AuditLog.objects.create(
                user=user,
                action='login_success',
                ip_address=f"192.168.1.{i}",
                timestamp=timezone.now()
            )
        
        is_suspicious, reason = SecurityService.detect_suspicious_activity(
            user, "192.168.1.1"
        )
        
        self.assertTrue(is_suspicious)
        self.assertIn("Multiple IP addresses", reason)
    
    def test_security_summary(self):
        """Test security summary generation"""
        user = AuthUser.objects.create(email="test@example.com")
        
        # Create some test data
        session = UserSession.objects.create(
            user=user,
            session_token="test-token",
            refresh_token="test-refresh",
            ip_address="127.0.0.1",
            expires_at=timezone.now() + timedelta(hours=24)
        )
        
        AuditLog.objects.create(
            user=user,
            action='login_success',
            ip_address="127.0.0.1",
            timestamp=timezone.now()
        )
        
        summary = SecurityService.get_security_summary(user)
        
        self.assertIn('active_sessions', summary)
        self.assertIn('recent_logins', summary)
        self.assertIn('is_verified', summary)
        self.assertEqual(summary['active_sessions'], 1)


class AuditLogTest(TestCase):
    
    def test_log_event(self):
        """Test audit log creation"""
        user = AuthUser.objects.create(email="test@example.com")
        
        log = AuditLog.log_event(
            action='login_success',
            ip_address='127.0.0.1',
            user=user,
            user_agent='Test Browser',
            details={'test': 'data'}
        )
        
        self.assertEqual(log.action, 'login_success')
        self.assertEqual(log.ip_address, '127.0.0.1')
        self.assertEqual(log.user, user)
        self.assertEqual(log.details['test'], 'data')


class IntegrationTest(TransactionTestCase):
    """
    Integration tests for complete authentication flows
    """
    
    def setUp(self):
        """Set up test data"""
        self.client = APIClient()
        self.email = "integration@example.com"
        self.password = "integrationpass123"
        
        # Create user
        self.user = AuthUser(email=self.email)
        self.user.set_password(self.password)
        self.user.save()
    
    @patch('authentication.services.services.AuthenticationService.get_user_org_info')
    def test_complete_authentication_flow(self, mock_get_org_info):
        """Test complete login -> use token -> logout flow"""
        # Mock org service
        mock_get_org_info.return_value = {
            'user_id': 'user_123',
            'org_id': 'org_456',
            'role': 'member'
        }
        
        # Step 1: Login
        login_data = {
            'email': self.email,
            'password': self.password
        }
        
        login_response = self.client.post(
            reverse('login'),
            data=json.dumps(login_data),
            content_type='application/json'
        )
        
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        access_token = login_response.data['access_token']
        session_id = login_response.data['session_id']
        
        # Step 2: Use token to access protected endpoint
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        sessions_response = self.client.get(reverse('user-sessions'))
        self.assertEqual(sessions_response.status_code, status.HTTP_200_OK)
        
        # Step 3: Logout
        logout_response = self.client.post(reverse('logout-all'))
        self.assertEqual(logout_response.status_code, status.HTTP_200_OK)
        
        # Step 4: Verify token no longer works
        sessions_response_after_logout = self.client.get(reverse('user-sessions'))
        self.assertEqual(sessions_response_after_logout.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_password_reset_flow(self):
        """Test complete password reset flow"""
        # Step 1: Request password reset
        reset_request_data = {
            'email': self.email
        }
        
        reset_request_response = self.client.post(
            reverse('password-reset-request'),
            data=json.dumps(reset_request_data),
            content_type='application/json'
        )
        
        self.assertEqual(reset_request_response.status_code, status.HTTP_200_OK)
        
        # Get the reset token from database (in real app, this would be sent via email)
        reset_token = PasswordResetToken.objects.filter(user=self.user).first()
        self.assertIsNotNone(reset_token)
        
        # Step 2: Reset password with token
        new_password = "newpassword123"
        reset_confirm_data = {
            'token': reset_token.token,
            'new_password': new_password,
            'confirm_password': new_password
        }
        
        reset_confirm_response = self.client.post(
            reverse('password-reset-confirm'),
            data=json.dumps(reset_confirm_data),
            content_type='application/json'
        )
        
        self.assertEqual(reset_confirm_response.status_code, status.HTTP_200_OK)
        
        # Step 3: Verify new password works
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))
        self.assertFalse(self.user.check_password(self.password))otNone(user.created_at)
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