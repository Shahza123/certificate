from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.http import HttpResponse
from django.db.models import Q
import logging
import json
from datetime import datetime, timedelta

from .models import Certificate, CertificateRequest, StepCAService
from .serializers import (
    CertificateSerializer, CertificateDetailSerializer, CertificateCreateSerializer,
    CertificateRequestSerializer, StepCAServiceSerializer, CertificateValidationSerializer,
    CertificateDownloadSerializer
)
from .step_ca_service import get_step_ca_service, convert_validity_period, StepCAServiceError

logger = logging.getLogger(__name__)


class CertificateListCreateView(generics.ListCreateAPIView):
    """List all certificates or create a new certificate"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return CertificateCreateSerializer
        return CertificateSerializer
    
    def get_queryset(self):
        """Return certificates for the current user"""
        queryset = Certificate.objects.filter(created_by=self.request.user)
        
        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Filter by hostname
        hostname = self.request.query_params.get('hostname')
        if hostname:
            queryset = queryset.filter(hostname__icontains=hostname)
        
        # Filter by certificate type
        cert_type = self.request.query_params.get('type')
        if cert_type:
            queryset = queryset.filter(certificate_type=cert_type)
        
        # Filter by expiring soon
        expiring_soon = self.request.query_params.get('expiring_soon')
        if expiring_soon == 'true':
            thirty_days_from_now = timezone.now() + timedelta(days=30)
            queryset = queryset.filter(
                expiry_date__lte=thirty_days_from_now,
                expiry_date__gte=timezone.now()
            )
        
        return queryset.order_by('-created_at')
    
    def perform_create(self, serializer):
        """Create a new certificate request and initiate generation"""
        certificate = serializer.save()
        
        # Create a certificate request for tracking
        cert_request = CertificateRequest.objects.create(
            certificate=certificate,
            requested_by=self.request.user,
            hostname=certificate.hostname,
            email=certificate.email,
            validity_period=certificate.validity_period,
            step_ca_service=certificate.step_ca_service,
            status='processing'
        )
        
        # Initiate certificate generation asynchronously
        try:
            self._generate_certificate_async(certificate, cert_request)
        except Exception as e:
            logger.error(f"Failed to initiate certificate generation: {str(e)}")
            certificate.status = 'failed'
            certificate.save()
            cert_request.status = 'failed'
            cert_request.error_message = str(e)
            cert_request.save()
    
    def _generate_certificate_async(self, certificate, cert_request):
        """Generate certificate using Step-CA service"""
        try:
            # Get Step-CA service instance
            step_ca = get_step_ca_service(certificate.step_ca_service)
            
            # Convert validity period
            validity = convert_validity_period(certificate.validity_period)
            
            # Generate certificate
            result = step_ca.generate_certificate(
                hostname=certificate.hostname,
                validity_period=validity,
                email=certificate.email,
                key_size=int(certificate.key_size)
            )
            
            if result['status'] == 'success':
                # Update certificate with generated content
                certificate.certificate_content = result['certificate']
                certificate.private_key = result['private_key']
                certificate.status = 'active'
                certificate.issued_date = timezone.now()
                
                # Parse certificate info to get expiry date
                cert_info = result.get('certificate_info', {})
                if 'not_after' in cert_info and cert_info['not_after']:
                    try:
                        # Parse the not_after date
                        expiry_date_str = cert_info['not_after'].replace('Z', '+00:00')
                        expiry_date = datetime.fromisoformat(expiry_date_str)
                        
                        # Ensure timezone awareness
                        if timezone.is_naive(expiry_date):
                            expiry_date = timezone.make_aware(expiry_date)
                        
                        certificate.expiry_date = expiry_date
                    except (ValueError, TypeError):
                        # Fallback: calculate based on validity period
                        if validity.endswith('d'):
                            days = int(validity[:-1])
                            certificate.expiry_date = timezone.now() + timedelta(days=days)
                        elif validity.endswith('y'):
                            years = int(validity[:-1])
                            certificate.expiry_date = timezone.now() + timedelta(days=years*365)
                
                certificate.save()
                
                # Update certificate request
                cert_request.status = 'completed'
                cert_request.completed_at = timezone.now()
                cert_request.save()
                
                logger.info(f"Certificate generated successfully for {certificate.hostname}")
            
            else:
                raise StepCAServiceError("Certificate generation failed")
        
        except Exception as e:
            logger.error(f"Certificate generation failed: {str(e)}")
            certificate.status = 'failed'
            certificate.save()
            
            cert_request.status = 'failed'
            cert_request.error_message = str(e)
            cert_request.save()


class CertificateDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update or delete a certificate"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CertificateDetailSerializer
    lookup_field = 'id'
    
    def get_queryset(self):
        return Certificate.objects.filter(created_by=self.request.user)


class CertificateValidationView(APIView):
    """Validate a certificate by connecting to the host"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        serializer = CertificateValidationSerializer(data=request.data)
        if serializer.is_valid():
            hostname = serializer.validated_data['hostname']
            port = serializer.validated_data['port']
            
            try:
                # Get Step-CA service instance
                step_ca = get_step_ca_service()
                
                # Validate certificate
                result = step_ca.validate_certificate(hostname, port)
                
                # Update certificate validation status if it exists
                try:
                    certificate = Certificate.objects.get(
                        hostname=hostname,
                        created_by=request.user
                    )
                    certificate.last_validation_check = timezone.now()
                    certificate.validation_status = result['status']
                    certificate.save()
                except Certificate.DoesNotExist:
                    pass
                
                return Response(result, status=status.HTTP_200_OK)
            
            except Exception as e:
                logger.error(f"Certificate validation failed: {str(e)}")
                return Response({
                    'status': 'error',
                    'error': str(e),
                    'hostname': hostname,
                    'port': port
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CertificateDownloadView(APIView):
    """Download certificate in various formats"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, certificate_id):
        certificate = get_object_or_404(
            Certificate,
            id=certificate_id,
            created_by=request.user
        )
        
        serializer = CertificateDownloadSerializer(data=request.data)
        if serializer.is_valid():
            format_type = serializer.validated_data['format']
            include_private_key = serializer.validated_data['include_private_key']
            include_chain = serializer.validated_data['include_chain']
            password = serializer.validated_data.get('password', '')
            
            try:
                # Generate download content based on format
                content, filename, content_type = self._generate_download_content(
                    certificate, format_type, include_private_key, include_chain, password
                )
                
                response = HttpResponse(content, content_type=content_type)
                response['Content-Disposition'] = f'attachment; filename="{filename}"'
                return response
            
            except Exception as e:
                logger.error(f"Certificate download failed: {str(e)}")
                return Response({
                    'error': f'Download failed: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def _generate_download_content(self, certificate, format_type, include_private_key, 
                                 include_chain, password):
        """Generate download content based on format"""
        
        if format_type == 'pem':
            # PEM format
            content = certificate.certificate_content or ""
            
            if include_private_key and certificate.private_key:
                content += "\n" + certificate.private_key
            
            if include_chain and certificate.certificate_chain:
                content += "\n" + certificate.certificate_chain
            
            filename = f"{certificate.hostname}.pem"
            content_type = "application/x-pem-file"
        
        elif format_type == 'der':
            # DER format (would require conversion from PEM)
            # For now, return PEM with different content type
            content = certificate.certificate_content or ""
            filename = f"{certificate.hostname}.der"
            content_type = "application/x-x509-ca-cert"
        
        elif format_type == 'p12':
            # PKCS#12 format (would require OpenSSL conversion)
            # For now, return PEM with different content type
            content = certificate.certificate_content or ""
            if include_private_key and certificate.private_key:
                content += "\n" + certificate.private_key
            filename = f"{certificate.hostname}.p12"
            content_type = "application/x-pkcs12"
        
        elif format_type == 'jks':
            # Java KeyStore format (would require Java keytool)
            # For now, return PEM with different content type
            content = certificate.certificate_content or ""
            filename = f"{certificate.hostname}.jks"
            content_type = "application/x-java-keystore"
        
        else:
            raise ValueError(f"Unsupported format: {format_type}")
        
        return content.encode('utf-8'), filename, content_type


class CertificateRequestListView(generics.ListAPIView):
    """List certificate requests for the current user"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CertificateRequestSerializer
    
    def get_queryset(self):
        return CertificateRequest.objects.filter(
            requested_by=self.request.user
        ).order_by('-created_at')


class StepCAServiceListView(generics.ListAPIView):
    """List available Step-CA services"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = StepCAServiceSerializer
    
    def get_queryset(self):
        return StepCAService.objects.filter(is_active=True)


class StepCAHealthCheckView(APIView):
    """Check health of Step-CA service"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        service_url = request.query_params.get('service_url', 'localhost:9000')
        
        try:
            step_ca = get_step_ca_service(f"https://{service_url}")
            health_info = step_ca.get_ca_info()
            
            return Response(health_info, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Step-CA health check failed: {str(e)}")
            return Response({
                'status': 'error',
                'error': str(e),
                'service_url': service_url
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def revoke_certificate(request, certificate_id):
    """Revoke a certificate"""
    certificate = get_object_or_404(
        Certificate,
        id=certificate_id,
        created_by=request.user
    )
    
    if certificate.status != 'active':
        return Response({
            'error': 'Only active certificates can be revoked'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    reason = request.data.get('reason', 'unspecified')
    
    try:
        # Create temporary certificate file for revocation
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as cert_file:
            cert_file.write(certificate.certificate_content)
            cert_path = cert_file.name
        
        try:
            step_ca = get_step_ca_service(certificate.step_ca_service)
            result = step_ca.revoke_certificate(cert_path, reason)
            
            if result['status'] == 'success':
                certificate.status = 'revoked'
                certificate.save()
                
                return Response({
                    'message': 'Certificate revoked successfully',
                    'revoked_at': result['revoked_at']
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'error': 'Certificate revocation failed'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        finally:
            # Clean up temporary file
            try:
                os.unlink(cert_path)
            except OSError:
                pass
    
    except Exception as e:
        logger.error(f"Certificate revocation failed: {str(e)}")
        return Response({
            'error': f'Revocation failed: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def certificate_statistics(request):
    """Get certificate statistics for the current user"""
    user_certificates = Certificate.objects.filter(created_by=request.user)
    
    # Calculate statistics
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
    
    return Response({
        'total_certificates': total_certificates,
        'active_certificates': active_certificates,
        'expired_certificates': expired_certificates,
        'revoked_certificates': revoked_certificates,
        'expiring_soon': expiring_soon,
        'certificate_types': certificate_types,
        'generated_at': timezone.now().isoformat()
    }, status=status.HTTP_200_OK)
