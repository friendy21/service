from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone
import uuid
import secrets

class AuthUser(models.Model):
    email = models.EmailField(unique=True, db_index=True)
    password = models.CharField(max_length=128)  # bcrypt hashed
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    password_changed_at = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(null=True, blank=True)
    failed_login_attempts = models.IntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'auth_users'
        constraints = [
            models.UniqueConstraint(fields=['email'], name='unique_email_auth_user')
        ]
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['is_active']),
            models.Index(fields=['last_login']),
        ]

    def set_password(self, raw_password):
        """Hash and set the password using Django's built-in bcrypt hashing"""
        self.password = make_password(raw_password)
        self.password_changed_at = timezone.now()

    def check_password(self, raw_password):
        """Check the provided password against the stored hash"""
        return check_password(raw_password, self.password)

    def is_locked(self):
        """Check if account is locked"""
        if self.locked_until and self.locked_until > timezone.now():
            return True
        return False

    def increment_failed_attempts(self):
        """Increment failed login attempts and lock if necessary"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:  # Lock after 5 failed attempts
            self.locked_until = timezone.now() + timezone.timedelta(minutes=30)
        self.save()

    def reset_failed_attempts(self):
        """Reset failed login attempts on successful login"""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login = timezone.now()
        self.save()

    def __str__(self):
        return self.email


class UserSession(models.Model):
    """Track user sessions for logout functionality"""
    SESSION_STATUS_CHOICES = [
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('revoked', 'Revoked'),
    ]

    DEVICE_TYPE_CHOICES = [
        ('web', 'Web Browser'),
        ('mobile', 'Mobile App'),
        ('api', 'API Client'),
        ('unknown', 'Unknown'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(AuthUser, on_delete=models.CASCADE, related_name='sessions')
    session_token = models.CharField(max_length=128, unique=True, db_index=True)
    refresh_token = models.CharField(max_length=128, unique=True, db_index=True)
    device_id = models.CharField(max_length=255, null=True, blank=True)
    device_type = models.CharField(max_length=20, choices=DEVICE_TYPE_CHOICES, default='unknown')
    device_name = models.CharField(max_length=255, null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=SESSION_STATUS_CHOICES, default='active')
    created_at = models.DateTimeField(auto_now_add=True)
    last_accessed = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField()

    class Meta:
        db_table = 'user_sessions'
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['session_token']),
            models.Index(fields=['refresh_token']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['created_at']),
        ]
        ordering = ['-last_accessed']

    @classmethod
    def generate_tokens(cls):
        """Generate secure session and refresh tokens"""
        session_token = secrets.token_urlsafe(64)
        refresh_token = secrets.token_urlsafe(64)
        return session_token, refresh_token

    def is_expired(self):
        """Check if session is expired"""
        return timezone.now() > self.expires_at

    def is_active(self):
        """Check if session is active and not expired"""
        return self.status == 'active' and not self.is_expired()

    def revoke(self):
        """Revoke the session"""
        self.status = 'revoked'
        self.save()

    def refresh(self, new_expires_at=None):
        """Refresh the session with new tokens"""
        if new_expires_at is None:
            new_expires_at = timezone.now() + timezone.timedelta(hours=24)
        
        self.session_token, self.refresh_token = self.generate_tokens()
        self.expires_at = new_expires_at
        self.last_accessed = timezone.now()
        self.save()
        return self.session_token, self.refresh_token

    def __str__(self):
        return f"{self.user.email} - {self.device_type} ({self.status})"


class EmailVerification(models.Model):
    """Email verification tokens"""
    user = models.ForeignKey(AuthUser, on_delete=models.CASCADE, related_name='verification_tokens')
    token = models.CharField(max_length=128, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)

    class Meta:
        db_table = 'email_verifications'
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['expires_at']),
        ]

    @classmethod
    def create_verification_token(cls, user):
        """Create a new verification token for user"""
        token = secrets.token_urlsafe(32)
        expires_at = timezone.now() + timezone.timedelta(hours=24)
        return cls.objects.create(
            user=user,
            token=token,
            expires_at=expires_at
        )

    def is_expired(self):
        """Check if verification token is expired"""
        return timezone.now() > self.expires_at

    def is_valid(self):
        """Check if token is valid (not used and not expired)"""
        return not self.is_used and not self.is_expired()

    def use_token(self):
        """Mark token as used"""
        self.is_used = True
        self.save()

    def __str__(self):
        return f"Verification for {self.user.email}"


class PasswordResetToken(models.Model):
    """Password reset tokens"""
    user = models.ForeignKey(AuthUser, on_delete=models.CASCADE, related_name='reset_tokens')
    token = models.CharField(max_length=128, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)

    class Meta:
        db_table = 'password_reset_tokens'
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['expires_at']),
        ]

    @classmethod
    def create_reset_token(cls, user):
        """Create a new password reset token"""
        # Revoke existing tokens
        cls.objects.filter(user=user, is_used=False).update(is_used=True)
        
        token = secrets.token_urlsafe(32)
        expires_at = timezone.now() + timezone.timedelta(hours=1)  # 1 hour expiry
        return cls.objects.create(
            user=user,
            token=token,
            expires_at=expires_at
        )

    def is_expired(self):
        """Check if reset token is expired"""
        return timezone.now() > self.expires_at

    def is_valid(self):
        """Check if token is valid"""
        return not self.is_used and not self.is_expired()

    def use_token(self):
        """Mark token as used"""
        self.is_used = True
        self.save()

    def __str__(self):
        return f"Reset token for {self.user.email}"


class AuditLog(models.Model):
    """Audit log for security events"""
    ACTION_CHOICES = [
        ('login_success', 'Login Success'),
        ('login_failed', 'Login Failed'),
        ('logout', 'Logout'),
        ('logout_all', 'Logout All Devices'),
        ('password_changed', 'Password Changed'),
        ('password_reset_requested', 'Password Reset Requested'),
        ('password_reset_completed', 'Password Reset Completed'),
        ('email_verified', 'Email Verified'),
        ('account_locked', 'Account Locked'),
        ('session_revoked', 'Session Revoked'),
    ]

    user = models.ForeignKey(AuthUser, on_delete=models.CASCADE, related_name='audit_logs', null=True, blank=True)
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(null=True, blank=True)
    details = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'audit_logs'
        indexes = [
            models.Index(fields=['user', 'action']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['ip_address']),
        ]
        ordering = ['-timestamp']

    @classmethod
    def log_event(cls, action, ip_address, user=None, user_agent=None, details=None):
        """Log a security event"""
        return cls.objects.create(
            user=user,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details or {}
        )

    def __str__(self):
        user_email = self.user.email if self.user else 'Anonymous'
        return f"{user_email} - {self.get_action_display()} at {self.timestamp}"