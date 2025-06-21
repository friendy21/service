from rest_framework import status
import requests
from typing import Dict, Tuple
from organization.config.service_config import SERVICE_CONFIGS, SERVICE_API_ENDPOINTS
from organization.serializers.connection_serializer import ConnectionValidationResponseSerializer
from organization.models.data_source_model import DataSourceConfig

class ConnectionValidationError(Exception):
    def __init__(self, message: str, status: str):
        self.message = message
        self.status = status
        super().__init__(self.message)

class ConnectionService:
    @staticmethod
    def validate_microsoft365_connection(tenant_id: str, client_id: str, client_secret: str) -> Tuple[bool, str]:
        """Validate Microsoft 365 connection credentials."""
        try:
            # Microsoft Graph API token endpoint
            token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            token_data = {
                'client_id': client_id,
                'client_secret': client_secret,
                'scope': 'https://graph.microsoft.com/.default',
                'grant_type': 'client_credentials'
            }
            
            response = requests.post(token_url, data=token_data)
            
            if response.status_code == 200:
                return True, "connected"
            elif response.status_code == 401:
                return False, "invalid_credentials"
            elif response.status_code == 403:
                return False, "insufficient_permissions"
            else:
                return False, "connection_error"
                
        except requests.exceptions.RequestException:
            return False, "connection_error"

    @staticmethod
    def validate_dropbox_connection(api_key: str) -> Tuple[bool, str]:
        """Validate Dropbox connection credentials."""
        try:
            headers = {'Authorization': f'Bearer {api_key}'}
            response = requests.post(
                'https://api.dropboxapi.com/2/users/get_current_account',
                headers=headers
            )
            
            if response.status_code == 200:
                return True, "connected"
            elif response.status_code == 401:
                return False, "invalid_credentials"
            elif response.status_code == 403:
                return False, "insufficient_permissions"
            else:
                return False, "connection_error"
                
        except requests.exceptions.RequestException:
            return False, "connection_error"

    @staticmethod
    def validate_connection(data_source_config: Dict) -> Tuple[bool, str]:
        """Validate connection based on service type."""
        service_name = data_source_config.get('service_name', '').lower()
        
        if service_name == 'microsoft_365':
            return ConnectionService.validate_microsoft365_connection(
                data_source_config.get('tenant_id'),
                data_source_config.get('client_id'),
                data_source_config.get('client_secret')
            )
        elif service_name == 'dropbox':
            return ConnectionService.validate_dropbox_connection(
                data_source_config.get('api_key')
            )
        else:
            raise ConnectionValidationError(
                f"Unsupported service: {service_name}",
                "unsupported_service"
            ) 
        
    @staticmethod
    def check_connection_and_prepare_response(data_source : DataSourceConfig):
        try:
            is_valid, connection_status = ConnectionService.validate_connection({
                "service_name": data_source.service_name,
                "tenant_id": data_source.tenant_id,
                "client_id": data_source.client_id,
                "client_secret": data_source.client_secret,
                "api_key": data_source.api_key
            })

            # Update status in DB
            data_source.status = connection_status
            data_source.save()

            response_data = {
                "status": "success" if is_valid else "error",
                "message": "Connection validated successfully" if is_valid else ConnectionService.get_error_message(connection_status),
                "connection_id": data_source.connection_id,
            }
            if not is_valid:
                response_data["error_code"] = connection_status

            serializer = ConnectionValidationResponseSerializer(data=response_data)
            serializer.is_valid(raise_exception=True)
            return serializer.data, status.HTTP_200_OK if is_valid else status.HTTP_400_BAD_REQUEST

        except Exception as e:
            response_data = {
                "status": "error",
                "message": str(e) or "An unexpected error occurred",
                "error_code": "internal_error",
                "connection_id": data_source.connection_id
            }
            serializer = ConnectionValidationResponseSerializer(data=response_data)
            serializer.is_valid(raise_exception=True)
            return serializer.data, status.HTTP_500_INTERNAL_SERVER_ERROR