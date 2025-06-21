from django.conf import settings

EXTRACTION_SERVICE_BASE_URL = "http://localhost:3005/api/extract"  # Default URL for the extraction service

EXTRACTION_ENDPOINTS = {
    "start": lambda connection_id: f"{EXTRACTION_SERVICE_BASE_URL}/start/{connection_id}",
    "status": lambda connection_id: f"{EXTRACTION_SERVICE_BASE_URL}/status/{connection_id}",
    "result": lambda connection_id: f"{EXTRACTION_SERVICE_BASE_URL}/result/{connection_id}",
}

# Service endpoint configurations
SERVICE_ENDPOINTS = {
    "microsoft_365": {
        "api_endpoint": getattr(
            settings, "MICROSOFT_365_API_ENDPOINT", "https://graph.microsoft.com/v1.0"
        ),
        "auth_type": "OAuth2",
        "prefix": "ms365",
    },
    "google_workspace": {
        "api_endpoint": getattr(
            settings, "GOOGLE_WORKSPACE_API_ENDPOINT", "https://www.googleapis.com"
        ),
        "auth_type": "OAuth2",
        "prefix": "gw",
    },
    "dropbox": {
        "api_endpoint": getattr(
            settings, "DROPBOX_API_ENDPOINT", "https://api.dropboxapi.com/2"
        ),
        "auth_type": "OAuth Token",
        "prefix": "db",
    },
    "slack": {
        "api_endpoint": getattr(
            settings, "SLACK_API_ENDPOINT", "https://slack.com/api"
        ),
        "auth_type": "Bearer Token",
        "prefix": "sl",
    },
    "zoom": {
        "api_endpoint": getattr(
            settings, "ZOOM_API_ENDPOINT", "https://api.zoom.us/v2"
        ),
        "auth_type": "JWT",
        "prefix": "zm",
    },
    "jira": {
        "api_endpoint": getattr(
            settings,
            "JIRA_API_ENDPOINT",
            "https://your-domain.atlassian.net/rest/api/3",
        ),
        "auth_type": "API Token",
        "prefix": "jr",
    },
}


