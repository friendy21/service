from django.urls import path
from .views.views import (
    LoginView, LogoutView, LogoutAllView, RefreshTokenView,
    PasswordResetRequestView, PasswordResetConfirmView,
    EmailVerificationView, ChangePasswordView,
    UserSessionsView, RevokeSessionView, SecuritySummaryView
)

urlpatterns = [
    # Authentication endpoints
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('logout-all/', LogoutAllView.as_view(), name='logout-all'),
    path('refresh/', RefreshTokenView.as_view(), name='refresh-token'),
    
    # Password management
    path('password/reset/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('password/change/', ChangePasswordView.as_view(), name='change-password'),
    
    # Email verification
    path('email/verify/', EmailVerificationView.as_view(), name='email-verify'),
    
    # Session management
    path('sessions/', UserSessionsView.as_view(), name='user-sessions'),
    path('sessions/<uuid:session_id>/revoke/', RevokeSessionView.as_view(), name='revoke-session'),
    
    # Security
    path('security/summary/', SecuritySummaryView.as_view(), name='security-summary'),
]