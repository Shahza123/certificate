from django.urls import path
from . import views, enhanced_views

app_name = 'certificates'

urlpatterns = [
    # Certificate CRUD operations
    path('', views.CertificateListCreateView.as_view(), name='certificate-list-create'),
    path('<uuid:id>/', views.CertificateDetailView.as_view(), name='certificate-detail'),
    
    # Certificate operations
    path('validate/', views.CertificateValidationView.as_view(), name='certificate-validate'),
    path('<uuid:certificate_id>/download/', views.CertificateDownloadView.as_view(), name='certificate-download'),
    path('<uuid:certificate_id>/revoke/', views.revoke_certificate, name='certificate-revoke'),
    path('<uuid:certificate_id>/renew/', enhanced_views.renew_certificate, name='certificate-renew'),
    path('<uuid:certificate_id>/deploy/', enhanced_views.deploy_certificate, name='certificate-deploy'),
    
    # Certificate requests
    path('requests/', views.CertificateRequestListView.as_view(), name='certificate-request-list'),
    
    # CSR Management
    path('csr/templates/', enhanced_views.CSRTemplateListCreateView.as_view(), name='csr-template-list-create'),
    path('csr/templates/<uuid:pk>/', enhanced_views.CSRTemplateDetailView.as_view(), name='csr-template-detail'),
    path('csr/generate/', enhanced_views.CSRGenerationView.as_view(), name='csr-generate'),
    path('csr/', enhanced_views.CertificateSigningRequestListCreateView.as_view(), name='csr-list-create'),
    path('csr/<uuid:pk>/', enhanced_views.CertificateSigningRequestDetailView.as_view(), name='csr-detail'),
    path('csr/<uuid:csr_id>/approve/', enhanced_views.approve_csr, name='csr-approve'),
    path('csr/<uuid:csr_id>/reject/', enhanced_views.reject_csr, name='csr-reject'),
    
    # Deployment Management
    path('deployment/targets/', enhanced_views.DeploymentTargetListCreateView.as_view(), name='deployment-target-list-create'),
    path('deployment/targets/<uuid:pk>/', enhanced_views.DeploymentTargetDetailView.as_view(), name='deployment-target-detail'),
    path('deployment/targets/<uuid:target_id>/test/', enhanced_views.test_deployment_target, name='deployment-target-test'),
    path('deployment/history/', enhanced_views.CertificateDeploymentListView.as_view(), name='deployment-history'),
    
    # Notification Management
    path('notifications/rules/', enhanced_views.NotificationRuleListCreateView.as_view(), name='notification-rule-list-create'),
    path('notifications/rules/<uuid:pk>/', enhanced_views.NotificationRuleDetailView.as_view(), name='notification-rule-detail'),
    
    # Step-CA service management
    path('services/', views.StepCAServiceListView.as_view(), name='stepca-service-list'),
    path('services/health/', views.StepCAHealthCheckView.as_view(), name='stepca-health-check'),
    
    # Analytics and reporting
    path('statistics/', views.certificate_statistics, name='certificate-statistics'),
    path('analytics/', enhanced_views.certificate_analytics, name='certificate-analytics'),
    path('audit-logs/', enhanced_views.audit_logs, name='audit-logs'),
]
