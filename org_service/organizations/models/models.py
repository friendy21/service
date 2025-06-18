# org_service/organizations/models/models.py
import uuid
from django.db import models
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import make_password, check_password

class Organization(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    email = models.EmailField()
    phone = models.CharField(max_length=20, null=True, blank=True)
    address = models.CharField(max_length=255, null=True, blank=True)
    website = models.URLField(null=True, blank=True)
    industry = models.CharField(max_length=100, null=True, blank=True)
    size = models.IntegerField(null=True, blank=True)
    owner_id = models.UUIDField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    def to_dict(self):
        return {
            "id": str(self.id),
            "name": self.name,
            "email": self.email,
            "phone": self.phone,
            "address": self.address,
            "website": self.website,
            "industry": self.industry,
            "size": self.size,
            "owner_id": str(self.owner_id) if self.owner_id else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "is_active": self.is_active,
        }

    def __str__(self):
        return self.name
    
    class Meta: 
        verbose_name = "Organization"
        verbose_name_plural = "Organizations"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["name"]),
            models.Index(fields=["email"]),
            models.Index(fields=["created_at"]),
        ]

class OrgUser(models.Model):
    ROLE_CHOICES = [
        ('admin', 'Administrator'),
        ('member', 'Member'),
        ('viewer', 'Viewer'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, db_index=True)
    name = models.CharField(max_length=255)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='member')
    org = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='users')
    
    # Enhanced user fields
    password = models.CharField(max_length=128, null=True, blank=True)  # For local password management
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    last_login = models.DateTimeField(null=True, blank=True)
    password_changed_at = models.DateTimeField(null=True, blank=True)
    
    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='created_users')
    deactivated_at = models.DateTimeField(null=True, blank=True)
    deactivated_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='deactivated_users')

    class Meta:
        db_table = 'org_users'
        constraints = [
            models.UniqueConstraint(fields=['email'], name='unique_email_org_user')
        ]
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['org', 'role']),
            models.Index(fields=['created_at']),
            models.Index(fields=['is_active']),
            models.Index(fields=['org', 'is_active']),
        ]

    def clean(self):
        if self.role not in dict(self.ROLE_CHOICES):
            raise ValidationError({'role': 'Invalid role choice'})

    def set_password(self, raw_password):
        """Hash and set the password"""
        self.password = make_password(raw_password)
        self.password_changed_at = timezone.now()

    def check_password(self, raw_password):
        """Check the provided password against the stored hash"""
        if not self.password:
            return False
        return check_password(raw_password, self.password)

    def deactivate(self, deactivated_by=None):
        """Deactivate the user account"""
        self.is_active = False
        self.deactivated_at = timezone.now()
        self.deactivated_by = deactivated_by
        self.save()

    def reactivate(self):
        """Reactivate the user account"""
        self.is_active = True
        self.deactivated_at = None
        self.deactivated_by = None
        self.save()

    def can_manage_user(self, target_user):
        """Check if this user can manage the target user"""
        # Admin can manage anyone in the same org
        if self.role == 'admin' and self.org == target_user.org:
            return True
        # Users can only manage themselves
        return self == target_user

    def can_access_organization(self, org):
        """Check if user can access the organization"""
        return self.org == org

    def to_dict(self):
        return {
            "id": str(self.id),
            "email": self.email,
            "name": self.name,
            "role": self.role,
            "org_id": str(self.org.id),
            "is_active": self.is_active,
            "is_verified": self.is_verified,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    def __str__(self):
        return f"{self.email} ({self.org.name})"