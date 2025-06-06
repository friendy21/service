import uuid
from django.db import models
from django.utils import timezone
from django.core.exceptions import ValidationError

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
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'org_users'
        constraints = [
            models.UniqueConstraint(fields=['email'], name='unique_email_org_user')
        ]
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['org', 'role']),
            models.Index(fields=['created_at']),
        ]

    def clean(self):
        if self.role not in dict(self.ROLE_CHOICES):
            raise ValidationError({'role': 'Invalid role choice'})

    def __str__(self):
        return f"{self.email} ({self.org.name})"