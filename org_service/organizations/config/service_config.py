from typing import Dict, Any

# Base API endpoints for each service
SERVICE_API_ENDPOINTS = {
    'microsoft_365': 'https://graph.microsoft.com/v1.0',
    'google_workspace': 'https://www.googleapis.com/auth',
    'dropbox': 'https://api.dropboxapi.com/2',
    'slack': 'https://slack.com/api',
    'zoom': 'https://api.zoom.us/v2',
    'jira': 'https://your-jira-instance.atlassian.net/rest/api/3',
}

# Service-specific configurations
SERVICE_CONFIGS = {
    'microsoft_365': {
        'auth_type': 'OAuth 2.0',
        'required_fields': ['client_id', 'client_secret', 'tenant_id'],
        'optional_fields': ['scopes'],
        'default_scopes': ['User.Read', 'Mail.Read', 'Calendars.Read'],
    },
    'google_workspace': {
        'auth_type': 'OAuth 2.0',
        'required_fields': ['client_id', 'client_secret', 'tenant_id'],
        'optional_fields': ['scopes'],
        'default_scopes': ['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/calendar'],
    },
    'dropbox': {
        'auth_type': 'OAuth Token',
        'required_fields': ['api_key'],
        'optional_fields': [],
    },
    'slack': {
        'auth_type': 'Bearer Token',
        'required_fields': ['api_key'],
        'optional_fields': ['scopes'],
        'default_scopes': ['channels:read', 'chat:write', 'users:read'],
    },
    'zoom': {
        'auth_type': 'JWT',  # Can be either JWT or OAuth Token
        'required_fields': ['api_key'],
        'optional_fields': ['client_id', 'client_secret'],  # Required for OAuth
    },
    'jira': {
        'auth_type': 'API Token',
        'required_fields': ['api_key', 'client_id'],  # client_id stores username
        'optional_fields': [],
    },
}

def get_service_config(service_name: str) -> Dict[str, Any]:
    """
    Get configuration for a specific service.
    
    Args:
        service_name: Name of the service (e.g., 'microsoft_365')
        
    Returns:
        Dict containing service configuration
        
    Raises:
        ValueError: If service_name is not supported
    """
    if service_name not in SERVICE_CONFIGS:
        raise ValueError(f"Unsupported service: {service_name}")
    return SERVICE_CONFIGS[service_name]

def get_api_endpoint(service_name: str) -> str:
    """
    Get API endpoint for a specific service.
    
    Args:
        service_name: Name of the service (e.g., 'microsoft_365')
        
    Returns:
        API endpoint URL
        
    Raises:
        ValueError: If service_name is not supported
    """
    if service_name not in SERVICE_API_ENDPOINTS:
        raise ValueError(f"Unsupported service: {service_name}")
    return SERVICE_API_ENDPOINTS[service_name]

def validate_service_config(service_name: str, config_data: Dict[str, Any]) -> bool:
    """
    Validate if the provided configuration data meets the service requirements.
    
    Args:
        service_name: Name of the service
        config_data: Configuration data to validate
        
    Returns:
        bool: True if valid, False otherwise
        
    Raises:
        ValueError: If service_name is not supported
    """
    service_config = get_service_config(service_name)
    
    # Check required fields
    for field in service_config['required_fields']:
        if field not in config_data or not config_data[field]:
            return False
            
    return True 