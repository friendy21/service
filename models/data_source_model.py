import uuid
from django.db import models
from django.utils import timezone
from django.core.exceptions import ValidationError

class DataSourceConfig(models.Model):
    SERVICE_CHOICES = [
        ('microsoft_365', 'Microsoft 365'),
        ('google_workspace', 'Google Workspace'),
        ('dropbox', 'DropBox'),
        ('slack', 'Slack'),
        ('zoom', 'Zoom'),
        ('jira', 'Jira'),
    ]

    STATUS_CHOICES = [
        ('not_connected', 'Not Connected'),
        ('connected', 'Connected'),
        ('invalid_credentials', 'Invalid Credentials'),
        ('insufficient_permissions', 'Insufficient Permissions'),
        ('connection_error', 'Connection Error'),
    ]

    EXTRACTION_STATUS_CHOICES = [
        ('not_started', 'Not Started'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    service_name = models.CharField(max_length=100, choices=SERVICE_CHOICES)
    tenant_id = models.CharField(max_length=255, blank=True, null=True)

    description = models.TextField(blank=True, null=True)
    api_endpoint = models.CharField(max_length=255)
    auth_type = models.CharField(max_length=50)

    client_id = models.CharField(max_length=255, blank=True, null=True)
    client_secret = models.CharField(max_length=255, blank=True, null=True)
    api_key = models.CharField(max_length=255, blank=True, null=True)
    scopes = models.TextField(blank=True, null=True)

    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='not_connected')
    extraction_status = models.CharField(
        max_length=50,
        choices=EXTRACTION_STATUS_CHOICES,
        default='not_started'
    )
    last_extracted_at = models.DateTimeField(blank=True, null=True)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    organisation = models.ForeignKey(
        'Organization',
        on_delete=models.CASCADE,
        related_name='data_source_configs'
    )

    def __str__(self):
        return f"{self.get_service_name_display()} ({self.id})"

    class Meta:
        db_table = 'data_source_config'
        indexes = [
            models.Index(fields=['service_name']),
            models.Index(fields=['status']),
        ]
        ordering = ['-created_at']

    def to_dict(self):
        return {
            "id": str(self.id),
            "service_name": self.get_service_name_display(),
            "tenant_id": self.tenant_id,
            "description": self.description,
            "api_endpoint": self.api_endpoint,
            "auth_type": self.auth_type,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "api_key": self.api_key,
            "scopes": self.scopes,
            "status": self.status,
            "extraction_status": self.extraction_status,
            "last_extracted_at": self.last_extracted_at.isoformat() if self.last_extracted_at else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    def clean(self):
        # Conditional required fields based on service
        if self.service_name in ['microsoft_365', 'google_workspace']:
            if not self.client_id:
                raise ValidationError({'client_id': 'This field is required for OAuth-based services.'})
            if not self.client_secret:
                raise ValidationError({'client_secret': 'This field is required for OAuth-based services.'})
            if not self.tenant_id:
                raise ValidationError({'tenant_id': 'This field is required for Microsoft 365 and Google Workspace.'})
        elif self.service_name in ['dropbox', 'slack', 'zoom', 'jira']:
            if not self.api_key:
                raise ValidationError({'api_key': f'API key is required for {self.get_service_name_display()}.'})

    def save(self, *args, **kwargs):
        self.full_clean()  # Enforce validation before saving
        super().save(*args, **kwargs)

    def update_extraction_status(self, status: str):
        if status not in dict(self.EXTRACTION_STATUS_CHOICES):
            raise ValueError(f"Invalid extraction status: {status}")
        self.extraction_status = status
        self.updated_at = timezone.now()
        self.save(update_fields=['extraction_status', 'updated_at'])
