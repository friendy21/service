from django.urls import path
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
from .views.extraction_views import (
    ExtractStartAPIView,
    ExtractStatusAPIView,
    ExtractResultAPIView,
)
from .views.email_extraction_views import (
    StartEmailExtractionView,
    EmailExtractionStatusView,
    EmailExtractionResultView,
    StartBatchEmailExtractionView,
    BatchEmailExtractionStatusView,
    BatchEmailExtractionResultView,
    PauseEmailExtractionView,
    ContinueEmailExtractionView,
    CancelEmailExtractionView,
    PauseBatchEmailExtractionView,
    ContinueBatchEmailExtractionView,
    CancelBatchEmailExtractionView,
)

urlpatterns = [
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

    path("extract/<uuid:pk>/start/", ExtractStartAPIView.as_view(), name="extract-start"),
    path("extract/<uuid:pk>/status/", ExtractStatusAPIView.as_view(), name="extract-status"),
    path("extract/<uuid:pk>/result/", ExtractResultAPIView.as_view(), name="extract-result"),

    # Email Extraction URLs
    path('email-extract/start/<str:connection_id>/', StartEmailExtractionView.as_view(), name='email_extract_start'),
    path('email-extract/status/<str:connection_id>/', EmailExtractionStatusView.as_view(), name='email_extract_status'),
    path('email-extract/result/<str:connection_id>/', EmailExtractionResultView.as_view(), name='email_extract_result'),
    path('email-extract/batch/start/', StartBatchEmailExtractionView.as_view(), name='email_extract_batch_start'),
    path('email-extract/batch/status/<str:batch_id>/', BatchEmailExtractionStatusView.as_view(), name='email_extract_batch_status'),
    path('email-extract/batch/result/<str:batch_id>/', BatchEmailExtractionResultView.as_view(), name='email_extract_batch_result'),
    path('email-extract/pause/<str:connection_id>/', PauseEmailExtractionView.as_view(), name='email_extract_pause'),
    path('email-extract/continue/<str:connection_id>/', ContinueEmailExtractionView.as_view(), name='email_extract_continue'),
    path('email-extract/cancel/<str:connection_id>/', CancelEmailExtractionView.as_view(), name='email_extract_cancel'),
    path('email-extract/batch/pause/<str:batch_id>/', PauseBatchEmailExtractionView.as_view(), name='email_extract_batch_pause'),
    path('email-extract/batch/continue/<str:batch_id>/', ContinueBatchEmailExtractionView.as_view(), name='email_extract_batch_continue'),
    path('email-extract/batch/cancel/<str:batch_id>/', CancelBatchEmailExtractionView.as_view(), name='email_extract_batch_cancel'),
]
