"""
Enhanced Views for Certificate Management

This module provides additional views for CSR management, certificate deployment,
renewal, and advanced certificate operations.
"""

from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.http import HttpResponse
from django.db.models import Q, Count
from django.db import transaction
import logging
import json
from datetime import datetime, timedelta

from .models import (
    Certificate, CertificateRequest, StepCAService, CSRTemplate,
    CertificateSigningRequest, DeploymentTarget, CertificateDeployment,
    NotificationRule
)
from .serializers import (
    CSRTemplateSerializer, CertificateSigningRequestSerializer,
    CertificateSigningRequestCreateSerializer, DeploymentTargetSerializer,
    CertificateDeploymentSerializer, CertificateDeploymentCreateSerializer,
    NotificationRuleSerializer, CSRGenerationSerializer,
    CertificateRenewalSerializer
)
from .csr_service import get_csr_service, CSRGenerationError
from .deployment_service import get_deployment_service, DeploymentError
from auths.models import AuditLog

logger = logging.getLogger(__name__)


class CSRTemplateListCreateView(generics.ListCreateAPIView):
    """List all CSR templates or create a new template"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CSRTemplateSerializer
    
    def get_queryset(self):
        return CSRTemplate.objects.filter(is_active=True)
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)
        
        # Log the action
        AuditLog.objects.create(
            user=self.request.user,
            action='template_create',
            resource_type='csr_template',
            resource_id=str(serializer.instance.id),
            details={'template_name': serializer.instance.name},
            ip_address=self.request.META.get('REMOTE_ADDR')
        )


class CSRTemplateDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update or delete a CSR template"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CSRTemplateSerializer
    
    def get_queryset(self):
        if self.request.user.can_manage_users():
            return CSRTemplate.objects.all()
        return CSRTemplate.objects.filter(created_by=self.request.user)


class CSRGenerationView(APIView):
    """Generate a new Certificate Signing Request"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        serializer = CSRGenerationSerializer(data=request.data)
        if serializer.is_valid():
            try:
                csr_service = get_csr_service()
                result = csr_service.generate_csr(serializer.validated_data)
                
                # Log the action
                AuditLog.objects.create(
                    user=request.user,
                    action='csr_generate',
                    resource_type='csr',
                    details={
                        'common_name': serializer.validated_data['common_name'],
                        'key_type': serializer.validated_data.get('key_type', 'RSA'),
                        'key_size': serializer.validated_data.get('key_size', '2048')
                    },
                    ip_address=request.META.get('REMOTE_ADDR')
                )
                
                return Response(result, status=status.HTTP_201_CREATED)
            
            except CSRGenerationError as e:
                logger.error(f"CSR generation failed: {str(e)}")
                return Response({
                    'error': f'CSR generation failed: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CertificateSigningRequestListCreateView(generics.ListCreateAPIView):
    """List all CSRs or create a new CSR"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return CertificateSigningRequestCreateSerializer
        return CertificateSigningRequestSerializer
    
    def get_queryset(self):
        queryset = CertificateSigningRequest.objects.all()
        
        # Filter based on user role
        if self.request.user.role == 'regular_user':
            queryset = queryset.filter(requested_by=self.request.user)
        
        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        return queryset.order_by('-created_at')
    
    def perform_create(self, serializer):
        csr = serializer.save()
        
        # Log the action
        AuditLog.objects.create(
            user=self.request.user,
            action='csr_create',
            resource_type='certificate_signing_request',
            resource_id=str(csr.id),
            details={'common_name': csr.common_name},
            ip_address=self.request.META.get('REMOTE_ADDR')
        )


class CertificateSigningRequestDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update or delete a CSR"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CertificateSigningRequestSerializer
    
    def get_queryset(self):
        if self.request.user.can_manage_certificates():
            return CertificateSigningRequest.objects.all()
        return CertificateSigningRequest.objects.filter(requested_by=self.request.user)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def approve_csr(request, csr_id):
    """Approve a Certificate Signing Request"""
    if not request.user.can_manage_certificates():
        return Response({
            'error': 'Insufficient permissions to approve CSRs'
        }, status=status.HTTP_403_FORBIDDEN)
    
    csr = get_object_or_404(CertificateSigningRequest, id=csr_id)
    
    if csr.status != 'pending':
        return Response({
            'error': 'CSR is not in pending status'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    with transaction.atomic():
        csr.status = 'approved'
        csr.approved_by = request.user
        csr.approved_at = timezone.now()
        csr.save()
        
        # Create certificate from CSR
        certificate = Certificate.objects.create(
            hostname=csr.common_name,
            certificate_type='csr_based',
            common_name=csr.common_name,
            organization=csr.organization,
            organizational_unit=csr.organizational_unit,
            country=csr.country,
            state=csr.state,
            locality=csr.locality,
            email=csr.email,
            key_type=csr.key_type,
            key_size=csr.key_size,
            validity_period=csr.requested_validity,
            subject_alternative_names=csr.subject_alternative_names,
            csr_content=csr.csr_content,
            created_by=csr.requested_by,
            status='pending'
        )
        
        csr.certificate = certificate
        csr.save()
        
        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='csr_approve',
            resource_type='certificate_signing_request',
            resource_id=str(csr.id),
            details={'certificate_id': str(certificate.id)},
            ip_address=request.META.get('REMOTE_ADDR')
        )
    
    return Response({
        'message': 'CSR approved successfully',
        'certificate_id': str(certificate.id)
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def reject_csr(request, csr_id):
    """Reject a Certificate Signing Request"""
    if not request.user.can_manage_certificates():
        return Response({
            'error': 'Insufficient permissions to reject CSRs'
        }, status=status.HTTP_403_FORBIDDEN)
    
    csr = get_object_or_404(CertificateSigningRequest, id=csr_id)
    
    if csr.status != 'pending':
        return Response({
            'error': 'CSR is not in pending status'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    rejection_reason = request.data.get('reason', 'No reason provided')
    
    csr.status = 'rejected'
    csr.approved_by = request.user
    csr.approved_at = timezone.now()
    csr.rejection_reason = rejection_reason
    csr.save()
    
    # Log the action
    AuditLog.objects.create(
        user=request.user,
        action='csr_reject',
        resource_type='certificate_signing_request',
        resource_id=str(csr.id),
        details={'reason': rejection_reason},
        ip_address=request.META.get('REMOTE_ADDR')
    )
    
    return Response({
        'message': 'CSR rejected successfully'
    }, status=status.HTTP_200_OK)


class DeploymentTargetListCreateView(generics.ListCreateAPIView):
    """List all deployment targets or create a new target"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = DeploymentTargetSerializer
    
    def get_queryset(self):
        if self.request.user.can_deploy_certificates():
            return DeploymentTarget.objects.filter(is_active=True)
        return DeploymentTarget.objects.filter(
            created_by=self.request.user,
            is_active=True
        )
    
    def perform_create(self, serializer):
        if not self.request.user.can_deploy_certificates():
            raise permissions.PermissionDenied("Insufficient permissions to create deployment targets")
        
        target = serializer.save(created_by=self.request.user)
        
        # Log the action
        AuditLog.objects.create(
            user=self.request.user,
            action='target_create',
            resource_type='deployment_target',
            resource_id=str(target.id),
            details={'target_name': target.name, 'target_type': target.target_type},
            ip_address=self.request.META.get('REMOTE_ADDR')
        )


class DeploymentTargetDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update or delete a deployment target"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = DeploymentTargetSerializer
    
    def get_queryset(self):
        if self.request.user.can_deploy_certificates():
            return DeploymentTarget.objects.all()
        return DeploymentTarget.objects.filter(created_by=self.request.user)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def test_deployment_target(request, target_id):
    """Test connectivity to a deployment target"""
    if not request.user.can_deploy_certificates():
        return Response({
            'error': 'Insufficient permissions to test deployment targets'
        }, status=status.HTTP_403_FORBIDDEN)
    
    target = get_object_or_404(
        DeploymentTarget,
        id=target_id,
        created_by=request.user if not request.user.can_manage_certificates() else None
    )
    
    try:
        deployment_service = get_deployment_service()
        result = deployment_service.test_deployment_target(target)
        
        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='target_test',
            resource_type='deployment_target',
            resource_id=str(target.id),
            details={'test_result': result['success']},
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        return Response(result, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Deployment target test failed: {str(e)}")
        return Response({
            'success': False,
            'error': f'Test failed: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def deploy_certificate(request, certificate_id):
    """Deploy a certificate to specified targets"""
    if not request.user.can_deploy_certificates():
        return Response({
            'error': 'Insufficient permissions to deploy certificates'
        }, status=status.HTTP_403_FORBIDDEN)
    
    certificate = get_object_or_404(
        Certificate,
        id=certificate_id,
        created_by=request.user if not request.user.can_manage_certificates() else None
    )
    
    if certificate.status != 'active':
        return Response({
            'error': 'Only active certificates can be deployed'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    serializer = CertificateDeploymentCreateSerializer(
        data=request.data,
        context={'request': request}
    )
    
    if serializer.is_valid():
        try:
            deployment_config = {
                'user': request.user,
                'backup_existing': serializer.validated_data.get('backup_existing', True),
                'restart_services': serializer.validated_data.get('restart_services', False),
                'services_to_restart': serializer.validated_data.get('services_to_restart', []),
                'deployment_id': str(timezone.now().timestamp())
            }
            
            target = DeploymentTarget.objects.get(
                id=serializer.validated_data['target_id'],
                created_by=request.user if not request.user.can_manage_certificates() else None
            )
            
            deployment_service = get_deployment_service()
            deployment = deployment_service.deploy_certificate(
                certificate, target, deployment_config
            )
            
            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='certificate_deploy',
                resource_type='certificate',
                resource_id=str(certificate.id),
                details={
                    'target_id': str(target.id),
                    'target_name': target.name,
                    'deployment_id': str(deployment.id)
                },
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            deployment_serializer = CertificateDeploymentSerializer(deployment)
            return Response(deployment_serializer.data, status=status.HTTP_201_CREATED)
        
        except DeploymentError as e:
            logger.error(f"Certificate deployment failed: {str(e)}")
            return Response({
                'error': f'Deployment failed: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except DeploymentTarget.DoesNotExist:
            return Response({
                'error': 'Deployment target not found'
            }, status=status.HTTP_404_NOT_FOUND)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CertificateDeploymentListView(generics.ListAPIView):
    """List certificate deployments"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CertificateDeploymentSerializer
    
    def get_queryset(self):
        queryset = CertificateDeployment.objects.all()
        
        # Filter based on user role
        if not self.request.user.can_manage_certificates():
            queryset = queryset.filter(initiated_by=self.request.user)
        
        # Filter by certificate
        certificate_id = self.request.query_params.get('certificate_id')
        if certificate_id:
            queryset = queryset.filter(certificate_id=certificate_id)
        
        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        return queryset.order_by('-started_at')


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def renew_certificate(request, certificate_id):
    """Renew a certificate"""
    certificate = get_object_or_404(
        Certificate,
        id=certificate_id,
        created_by=request.user if not request.user.can_manage_certificates() else None
    )
    
    if certificate.status not in ['active', 'expired']:
        return Response({
            'error': 'Only active or expired certificates can be renewed'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    serializer = CertificateRenewalSerializer(data=request.data)
    if serializer.is_valid():
        try:
            # Create new certificate with same parameters
            new_certificate = Certificate.objects.create(
                hostname=certificate.hostname,
                certificate_type=certificate.certificate_type,
                key_size=certificate.key_size,
                key_type=certificate.key_type,
                validity_period=serializer.validated_data.get('validity_period', certificate.validity_period),
                email=certificate.email,
                common_name=certificate.common_name,
                organization=certificate.organization,
                organizational_unit=certificate.organizational_unit,
                country=certificate.country,
                state=certificate.state,
                locality=certificate.locality,
                subject_alternative_names=certificate.subject_alternative_names,
                auto_renewal=serializer.validated_data.get('auto_renewal', certificate.auto_renewal),
                renewal_threshold_days=serializer.validated_data.get('renewal_threshold_days', certificate.renewal_threshold_days),
                step_ca_service=certificate.step_ca_service,
                created_by=request.user,
                previous_certificate=certificate,
                status='renewal_pending'
            )
            
            # Mark old certificate as superseded
            certificate.status = 'expired'
            certificate.save()
            
            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='certificate_renew',
                resource_type='certificate',
                resource_id=str(certificate.id),
                details={
                    'new_certificate_id': str(new_certificate.id),
                    'validity_period': new_certificate.validity_period
                },
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            return Response({
                'message': 'Certificate renewal initiated successfully',
                'new_certificate_id': str(new_certificate.id),
                'status': new_certificate.status
            }, status=status.HTTP_201_CREATED)
        
        except Exception as e:
            logger.error(f"Certificate renewal failed: {str(e)}")
            return Response({
                'error': f'Renewal failed: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class NotificationRuleListCreateView(generics.ListCreateAPIView):
    """List all notification rules or create a new rule"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = NotificationRuleSerializer
    
    def get_queryset(self):
        if self.request.user.can_manage_certificates():
            return NotificationRule.objects.filter(is_active=True)
        return NotificationRule.objects.filter(
            created_by=self.request.user,
            is_active=True
        )
    
    def perform_create(self, serializer):
        if not self.request.user.can_manage_certificates():
            raise permissions.PermissionDenied("Insufficient permissions to create notification rules")
        
        rule = serializer.save(created_by=self.request.user)
        
        # Log the action
        AuditLog.objects.create(
            user=self.request.user,
            action='notification_rule_create',
            resource_type='notification_rule',
            resource_id=str(rule.id),
            details={'rule_name': rule.name, 'event_type': rule.event_type},
            ip_address=self.request.META.get('REMOTE_ADDR')
        )


class NotificationRuleDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update or delete a notification rule"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = NotificationRuleSerializer
    
    def get_queryset(self):
        if self.request.user.can_manage_certificates():
            return NotificationRule.objects.all()
        return NotificationRule.objects.filter(created_by=self.request.user)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def certificate_analytics(request):
    """Get certificate analytics and statistics"""
    user_certificates = Certificate.objects.filter(
        created_by=request.user if not request.user.can_manage_certificates() else None
    )
    
    # Basic statistics
    total_certificates = user_certificates.count()
    active_certificates = user_certificates.filter(status='active').count()
    expired_certificates = user_certificates.filter(status='expired').count()
    revoked_certificates = user_certificates.filter(status='revoked').count()
    
    # Expiring soon (within 30 days)
    thirty_days_from_now = timezone.now() + timedelta(days=30)
    expiring_soon = user_certificates.filter(
        status='active',
        expiry_date__lte=thirty_days_from_now,
        expiry_date__gte=timezone.now()
    ).count()
    
    # Certificate types
    certificate_types = {}
    for cert_type, _ in Certificate.CERTIFICATE_TYPES:
        count = user_certificates.filter(certificate_type=cert_type).count()
        certificate_types[cert_type] = count
    
    # Deployment statistics
    deployments = CertificateDeployment.objects.filter(
        certificate__created_by=request.user if not request.user.can_manage_certificates() else None
    )
    deployment_stats = {
        'total_deployments': deployments.count(),
        'successful_deployments': deployments.filter(status='success').count(),
        'failed_deployments': deployments.filter(status='failed').count(),
        'pending_deployments': deployments.filter(status__in=['pending', 'in_progress']).count()
    }
    
    # Monthly issuance (last 12 months)
    monthly_issuance = []
    for i in range(12):
        start_date = timezone.now().replace(day=1) - timedelta(days=i*30)
        end_date = start_date + timedelta(days=30)
        count = user_certificates.filter(
            created_at__range=[start_date, end_date]
        ).count()
        monthly_issuance.append({
            'month': start_date.strftime('%Y-%m'),
            'count': count
        })
    
    # Top hostnames
    top_hostnames = user_certificates.values('hostname').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    return Response({
        'total_certificates': total_certificates,
        'active_certificates': active_certificates,
        'expired_certificates': expired_certificates,
        'revoked_certificates': revoked_certificates,
        'expiring_soon': expiring_soon,
        'certificate_types': certificate_types,
        'deployment_statistics': deployment_stats,
        'monthly_issuance': list(reversed(monthly_issuance)),
        'top_hostnames': list(top_hostnames),
        'generated_at': timezone.now().isoformat()
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def audit_logs(request):
    """Get audit logs"""
    if not request.user.can_manage_certificates():
        # Regular users can only see their own logs
        logs = AuditLog.objects.filter(user=request.user)
    else:
        logs = AuditLog.objects.all()
    
    # Filter by action
    action = request.query_params.get('action')
    if action:
        logs = logs.filter(action=action)
    
    # Filter by date range
    start_date = request.query_params.get('start_date')
    end_date = request.query_params.get('end_date')
    if start_date:
        logs = logs.filter(timestamp__gte=start_date)
    if end_date:
        logs = logs.filter(timestamp__lte=end_date)
    
    # Pagination
    from rest_framework.pagination import PageNumberPagination
    paginator = PageNumberPagination()
    paginator.page_size = 50
    page = paginator.paginate_queryset(logs.order_by('-timestamp'), request)
    
    log_data = []
    for log in page:
        log_data.append({
            'id': str(log.id),
            'user': log.user.email if log.user else 'System',
            'action': log.get_action_display(),
            'resource_type': log.resource_type,
            'resource_id': log.resource_id,
            'details': log.details,
            'ip_address': log.ip_address,
            'timestamp': log.timestamp.isoformat()
        })
    
    return paginator.get_paginated_response(log_data)
