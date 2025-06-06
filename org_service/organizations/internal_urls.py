from django.urls import path
from .views.views import InternalUserView

urlpatterns = [
    path('users/<str:email>/', InternalUserView.as_view(), name='internal-user'),
]