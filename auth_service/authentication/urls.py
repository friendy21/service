from django.urls import path
from .views.views import LoginView

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
]