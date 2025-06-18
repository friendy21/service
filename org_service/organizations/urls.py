# org_service/organizations/urls.py
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
from .views.user_management_views import (
    UserListView, UserRetrieveView, UserUpdateView, UserDeleteView,
    UserDeactivateView, UserReactivateView, UserChangePasswordView,
    UserRoleUpdateView, OrganizationUsersView
)

urlpatterns = [
    # Legacy user creation endpoint
    path('<uuid:org_id>/users/', UserCreateView.as_view(), name='create-user'),

    # Organization Management
    path("organization/", OrganizationCreateAPIView.as_view(), name="create-organization"),
    path("organization/<uuid:pk>/", OrganizationRetrieveAPIView.as_view(), name="retrieve-organization"),
    path("organization/list/", OrganizationListAPIView.as_view(), name="list-organization"),
    path("organization/<uuid:pk>/update/", OrganizationUpdateAPIView.as_view(), name="update-organization"),
    path("organization/<uuid:pk>/delete/", OrganizationDeleteAPIView.as_view(), name="delete-organization"),
    
    # Enhanced User Management
    path('users/', UserListView.as_view(), name='user-list'),
    path('users/<uuid:user_id>/', UserRetrieveView.as_view(), name='user-retrieve'),
    path('users/<uuid:user_id>/update/', UserUpdateView.as_view(), name='user-update'),
    path('users/<uuid:user_id>/delete/', UserDeleteView.as_view(), name='user-delete'),
    path('users/<uuid:user_id>/deactivate/', UserDeactivateView.as_view(), name='user-deactivate'),
    path('users/<uuid:user_id>/reactivate/', UserReactivateView.as_view(), name='user-reactivate'),
    path('users/<uuid:user_id>/change-password/', UserChangePasswordView.as_view(), name='user-change-password'),
    path('users/<uuid:user_id>/role/', UserRoleUpdateView.as_view(), name='user-role-update'),
    
    # Organization-specific user management
    path('organization/<uuid:org_id>/users/', OrganizationUsersView.as_view(), name='organization-users'),
    path('organization/<uuid:org_id>/users/create/', UserCreateView.as_view(), name='organization-create-user'),
    
    # Data Source Configuration URLs
    path('datasource/', DataSourceConfigCreateAPIView.as_view(), name='datasource-create'),
    path('datasource/<int:pk>/', DataSourceConfigRetrieveAPIView.as_view(), name='datasource-retrieve'),
    path('datasource/list/', DataSourceConfigListAPIView.as_view(), name='datasource-list'),
    path('datasource/<int:pk>/update/', DataSourceConfigUpdateAPIView.as_view(), name='datasource-update'),
    path('datasource/<int:pk>/delete/', DataSourceConfigDeleteAPIView.as_view(), name='datasource-delete'),
    path('datasource/<int:pk>/connect/', DataSourceConnectAPIView.as_view(), name='datasource-connect'),
]