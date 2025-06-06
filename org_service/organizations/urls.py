from django.urls import path
from .views.views import UserCreateView

from .views.organization_views import (
    OrganizationCreateAPIView, OrganizationDeleteAPIView, OrganizationListAPIView,
    OrganizationRetrieveAPIView, OrganizationUpdateAPIView,
)
from .views.data_source_views import (
    DataSourceConfigCreateAPIView,
    DataSourceConfigRetrieveAPIView,
    DataSourceConfigListAPIView,
    DataSourceConfigUpdateAPIView,
    DataSourceConfigDeleteAPIView,
)
from .views.connection_views import DataSourceConnectAPIView

urlpatterns = [
    path('<uuid:org_id>/users/', UserCreateView.as_view(), name='create-user'),

    # Added Endpoints
    path("organization/", OrganizationCreateAPIView.as_view(), name="create-organization"),
    path("organization/<uuid:pk>/", OrganizationRetrieveAPIView.as_view(), name="retrieve-organization"),
    path("organization/list/", OrganizationListAPIView.as_view(), name="list-organization"),
    path("organization/<uuid:pk>/update/", OrganizationUpdateAPIView.as_view(), name="update-organization"),
    path("organization/<uuid:pk>/delete/", OrganizationDeleteAPIView.as_view(), name="delete-organization"),
    
    # Data Source Configuration URLs
    path('datasource/', DataSourceConfigCreateAPIView.as_view(), name='datasource-create'),
    path('datasource/<int:pk>/', DataSourceConfigRetrieveAPIView.as_view(), name='datasource-retrieve'),
    path('datasource/list/', DataSourceConfigListAPIView.as_view(), name='datasource-list'),
    path('datasource/<int:pk>/update/', DataSourceConfigUpdateAPIView.as_view(), name='datasource-update'),
    path('datasource/<int:pk>/delete/', DataSourceConfigDeleteAPIView.as_view(), name='datasource-delete'),
    path('datasource/<int:pk>/connect/', DataSourceConnectAPIView.as_view(), name='datasource-connect'),
]