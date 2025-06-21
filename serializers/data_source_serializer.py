import uuid
from rest_framework import serializers
from organization.models.data_source_model import DataSourceConfig
from organization.config.service_config import get_service_config, get_api_endpoint, validate_service_config

class DataSourceConfigSerializer(serializers.ModelSerializer):
    service_name = serializers.CharField(source='get_service_name_display')
    
    class Meta:
        model = DataSourceConfig
        fields = [
            'id',
            'service_name',
            'tenant_id',
            'description',
            'client_id',
            'client_secret',
            'api_key',
            'api_endpoint',
            'auth_type',
            'scopes',
            'status',
            'organisation'
        ]
        read_only_fields = ['id',  'api_endpoint', 'auth_type']

class CreateDataSourceConfigSerializer(serializers.ModelSerializer):
    service_name = serializers.ChoiceField(choices=DataSourceConfig.SERVICE_CHOICES)
    tenant_id = serializers.CharField(max_length=255, required=False, allow_null=True)
    description = serializers.CharField(required=False, allow_null=True)
    client_id = serializers.CharField(max_length=255, required=False, allow_null=True)
    client_secret = serializers.CharField(max_length=255, required=False, allow_null=True)
    api_key = serializers.CharField(max_length=255, required=False, allow_null=True)
    scopes = serializers.CharField(required=False, allow_null=True)

    class Meta:
        model = DataSourceConfig
        fields = [
            "service_name",  "tenant_id", "description",
            "client_id", "client_secret", "api_key", "scopes", "organisation"
        ]
        read_only_fields = ["connection_id"]

    def validate(self, data):
        service_name = data.get('service_name')
        service_config = get_service_config(service_name)

        # Set auth_type and api_endpoint from service config
        data['auth_type'] = service_config['auth_type']
        data['api_endpoint'] = get_api_endpoint(service_name)


        # Validate required fields
        if not validate_service_config(service_name, data):
            required_fields = service_config['required_fields']
            raise serializers.ValidationError(
                f"Missing required fields for {service_name}: {', '.join(required_fields)}"
            )

        # Set default scopes if not provided
        if 'scopes' in service_config.get('optional_fields', []) and not data.get('scopes'):
            data['scopes'] = ','.join(service_config.get('default_scopes', []))

        return data
    
class UpdateDataSourceConfigSerializer(serializers.ModelSerializer):
    description = serializers.CharField(required=False)
    client_id = serializers.CharField(max_length=255, required=False)
    client_secret = serializers.CharField(max_length=255, required=False)
    api_key = serializers.CharField(max_length=255, required=False)
    scopes = serializers.CharField(required=False)
    status = serializers.ChoiceField(choices=DataSourceConfig.STATUS_CHOICES, required=False)

    class Meta:
        model = DataSourceConfig
        fields = ["description", "client_id", "client_secret", "api_key", "scopes", "status"]


class DataSourceConfigInputSerializer(serializers.ModelSerializer):
    class Meta:
        model = DataSourceConfig
        fields = [
            'service_name',
            'tenant_id',
            'client_id',
            'client_secret',
            'api_key',
            'description',
            'auth_type',
            'scopes'
        ]
        extra_kwargs = {
            'service_name': {'required': True},
            'tenant_id': {'required': False},
            'client_id': {'required': False},
            'client_secret': {'required': False},
            'api_key': {'required': False},
            'description': {'required': False},
            'auth_type': {'required': False},
            'scopes': {'required': False}
        }

class DataSourceConfigOutputSerializer(serializers.ModelSerializer):
    service_name = serializers.CharField(source='get_service_name_display')
    
    class Meta:
        model = DataSourceConfig
        fields = [
            'connection_id',
            'status'
        ] 