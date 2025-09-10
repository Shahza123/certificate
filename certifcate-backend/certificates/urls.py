from django.urls import path
from . import views

app_name = 'certificates'

urlpatterns = [
    # Certificate CRUD operations
    path('', views.CertificateListCreateView.as_view(), name='certificate-list-create'),
    path('<uuid:id>/', views.CertificateDetailView.as_view(), name='certificate-detail'),
    
    # Certificate operations
    path('validate/', views.CertificateValidationView.as_view(), name='certificate-validate'),
    path('<uuid:certificate_id>/download/', views.CertificateDownloadView.as_view(), name='certificate-download'),
    path('<uuid:certificate_id>/revoke/', views.revoke_certificate, name='certificate-revoke'),
    
    # Certificate requests
    path('requests/', views.CertificateRequestListView.as_view(), name='certificate-request-list'),
    
    # Step-CA service management
    path('services/', views.StepCAServiceListView.as_view(), name='stepca-service-list'),
    path('services/health/', views.StepCAHealthCheckView.as_view(), name='stepca-health-check'),
    
    # Statistics and reporting
    path('statistics/', views.certificate_statistics, name='certificate-statistics'),
]
