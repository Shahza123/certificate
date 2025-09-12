"""
MongoDB API URLs

Clean URLs for MongoDB-based API endpoints.
"""

from django.urls import path
from . import mongodb_api

app_name = 'api'

urlpatterns = [
    # Health check
    path('health/', mongodb_api.health_check, name='health'),
    
    # Authentication
    path('auth/register/', mongodb_api.register_user, name='register'),
    path('auth/login/', mongodb_api.login_user, name='login'),
    path('auth/profile/', mongodb_api.get_user_profile, name='profile'),
    
    # Certificate services and statistics (MUST come before certificates/<id>/)
    path('certificates/services/', mongodb_api.get_step_ca_services, name='get_step_ca_services'),
    path('certificates/statistics/', mongodb_api.get_certificate_statistics, name='get_certificate_statistics'),
    
    # Certificate management
    path('certificates/', mongodb_api.certificates_view, name='certificates'),
    path('certificates/<str:certificate_id>/', mongodb_api.get_certificate, name='get_certificate'),
    path('certificates/<str:certificate_id>/download/', mongodb_api.download_certificate, name='download_certificate'),
]
