"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

# Enhanced Swagger schema view
schema_view = get_schema_view(
    openapi.Info(
        title="Organization Service API",
        default_version='v1',
        description="""
        Organization management microservice for handling organizations, users, and data source configurations.
        
        ## Features
        - Organization CRUD operations
        - User management with role-based access
        - Data source configuration for external services
        - Service-to-service authentication for internal APIs
        
        ## Authentication
        - Public APIs: No authentication required
        - Internal APIs: Require service token and HMAC signature
        
        ## User Roles
        - **admin**: Full administrative access
        - **member**: Standard user access  
        - **viewer**: Read-only access
        
        ## Supported Data Sources
        - Microsoft 365
        - Google Workspace
        - Dropbox
        - Slack
        - Zoom
        - Jira
        """,
        terms_of_service="https://www.example.com/terms/",
        contact=openapi.Contact(email="support@example.com"),
        license=openapi.License(name="MIT License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('orgs/', include('organizations.urls')),
    path('internal/', include('organizations.internal_urls')),

    # Enhanced Swagger documentation
    path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui-alt'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    path('swagger.json', schema_view.without_ui(cache_timeout=0), name='schema-json'),
]