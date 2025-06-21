from rest_framework import serializers; from ..models.organization_model import Organization

class OrganizationSerializer(serializers.ModelSerializer):
    class Meta: model = Organization; fields = "__all__"

class CreateOrganizationSerializer(serializers.ModelSerializer):
    name = serializers.CharField(help_text="e.g. Acme Corporation", default="Acme Corporation")
    email = serializers.EmailField(help_text="e.g. contact@acme.com", default="contact@acme.com")
    phone = serializers.CharField(help_text="e.g. +1-555-123-4567", default="+1-555-123-4567")
    address = serializers.CharField(help_text="e.g. 123 Market Street, San Francisco, CA", default="123 Market Street, San Francisco, CA")
    website = serializers.URLField(help_text="e.g. https://www.acme.com", default="https://www.acme.com")
    industry = serializers.CharField(help_text="e.g. Technology", default="Technology")
    size = serializers.CharField(help_text="e.g. 200", default="200")
    owner_id = serializers.UUIDField(help_text="UUID of the organization owner", required=False, allow_null=True)
    class Meta: model = Organization; fields = ["name","email","phone","address","website","industry","size","owner_id"]

class UpdateOrganizationSerializer(serializers.ModelSerializer):
    name = serializers.CharField(help_text="e.g. Acme Corporation", required=False)
    email = serializers.EmailField(help_text="e.g. contact@acme.com", required=False)
    phone = serializers.CharField(help_text="e.g. +1-555-123-4567", required=False)
    address = serializers.CharField(help_text="e.g. 123 Market Street, San Francisco, CA", required=False)
    website = serializers.URLField(help_text="e.g. https://www.acme.com", required=False)
    industry = serializers.CharField(help_text="e.g. Technology", required=False)
    size = serializers.CharField(help_text="e.g. 200", required=False)
    is_active = serializers.BooleanField(help_text="Set to false to deactivate the organization", required=False)
    class Meta: model = Organization; fields = ["name","email","phone","address","website","industry","size","is_active"]
