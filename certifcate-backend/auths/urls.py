from django.urls import path
from auths.mongodb_views import (
    UserLoginView, UserRegistrationView, UserProfileView, 
    UserLogoutView, UserListView, change_user_role, toggle_user_status
)
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('logout/', UserLogoutView.as_view(), name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('users/', UserListView.as_view(), name='user-list'),
    path('users/<uuid:user_id>/role/', change_user_role, name='change-user-role'),
    path('users/<uuid:user_id>/toggle-status/', toggle_user_status, name='toggle-user-status'),
]