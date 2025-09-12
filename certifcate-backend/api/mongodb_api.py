"""
Pure MongoDB API Views

Clean MongoDB API that doesn't conflict with Django ORM.
"""

from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json
import logging
import uuid
import subprocess
import ssl
import socket
from datetime import datetime, timedelta
from auths.mongodb_models import User, AuditLog
# from certificates.mongodb_models import Certificate, StepCAService
from rest_framework_simplejwt.tokens import RefreshToken
import mongoengine as me

# Define Certificate model inline to avoid import conflicts
class Certificate(me.Document):
    common_name = me.StringField(required=True, max_length=255)
    organization = me.StringField(max_length=255)
    organizational_unit = me.StringField(max_length=255)
    country = me.StringField(max_length=2)
    state = me.StringField(max_length=255)
    city = me.StringField(max_length=255)
    email = me.EmailField()
    
    certificate_type = me.StringField(choices=['self_signed', 'ca_signed', 'step_ca'], default='self_signed')
    key_type = me.StringField(choices=['RSA', 'ECDSA', 'Ed25519'], default='RSA')
    key_size = me.IntField(default=2048)
    
    status = me.StringField(choices=['pending', 'active', 'expired', 'revoked'], default='pending')
    serial_number = me.StringField(max_length=40)
    fingerprint = me.StringField(max_length=64)
    
    certificate_pem = me.StringField()
    private_key_pem = me.StringField()
    
    issued_at = me.DateTimeField()
    expires_at = me.DateTimeField()
    
    subject_alternative_names = me.ListField(me.StringField())
    created_at = me.DateTimeField(default=datetime.utcnow)
    created_by = me.ReferenceField('User', required=False)  # Added missing field
    
    meta = {
        'collection': 'certificates',
        'indexes': ['common_name', 'status', 'expires_at']
    }

logger = logging.getLogger(__name__)


def create_tokens_for_user(user):
    """Create JWT tokens for MongoDB user"""
    refresh = RefreshToken()
    refresh['user_id'] = str(user.id)
    refresh['email'] = user.email
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


@csrf_exempt
@require_http_methods(["POST"])
def register_user(request):
    """Register a new user in MongoDB"""
    try:
        data = json.loads(request.body)
        
        # Validate required fields
        required_fields = ['email', 'first_name', 'last_name', 'password', 'password2']
        for field in required_fields:
            if field not in data or not data[field]:
                return JsonResponse({
                    'error': f'{field} is required'
                }, status=400)
        
        # Validate passwords match
        if data['password'] != data['password2']:
            return JsonResponse({
                'error': 'Passwords do not match'
            }, status=400)
        
        # Check if user already exists
        if User.objects(email=data['email']).first():
            return JsonResponse({
                'error': 'User with this email already exists'
            }, status=400)
        
        # Create user
        user = User(
            email=data['email'],
            first_name=data['first_name'],
            last_name=data['last_name'],
            role=data.get('role', 'regular_user')
        )
        user.set_password(data['password'])
        user.save()
        
        # Create tokens
        tokens = create_tokens_for_user(user)
        
        # Log registration
        AuditLog(
            user=user,
            action='user_create',
            resource_type='user',
            resource_id=str(user.id),
            details={'email': user.email, 'role': user.role},
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        ).save()
        
        return JsonResponse({
            'success': True,
            'message': 'User registered successfully',
            'token': tokens,
            'user': {
                'id': str(user.id),
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'role': user.role
            }
        }, status=201)
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return JsonResponse({'error': 'Registration failed'}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def login_user(request):
    """Login user with MongoDB"""
    try:
        data = json.loads(request.body)
        
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return JsonResponse({
                'error': 'Email and password are required'
            }, status=400)
        
        # Get client info
        ip_address = request.META.get('REMOTE_ADDR')
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Find user
        user = User.objects(email=email).first()
        
        if user:
            # Check if account is locked
            if user.account_locked_until and user.account_locked_until > datetime.utcnow():
                return JsonResponse({
                    'error': 'Account is temporarily locked. Please try again later.'
                }, status=423)
            
            # Check password
            if user.check_password(password) and user.is_active:
                # Reset failed attempts
                user.failed_login_attempts = 0
                user.account_locked_until = None
                user.last_login = datetime.utcnow()
                user.last_login_ip = ip_address
                user.save()
                
                # Create tokens
                tokens = create_tokens_for_user(user)
                
                # Log successful login
                AuditLog(
                    user=user,
                    action='login',
                    resource_type='user',
                    resource_id=str(user.id),
                    details={'login_method': 'password'},
                    ip_address=ip_address,
                    user_agent=user_agent
                ).save()
                
                return JsonResponse({
                    'token': tokens,
                    'user': {
                        'id': str(user.id),
                        'email': user.email,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'role': user.role,
                        'permissions': {
                            'can_manage_certificates': user.can_manage_certificates(),
                            'can_deploy_certificates': user.can_deploy_certificates(),
                            'can_revoke_certificates': user.can_revoke_certificates(),
                            'can_manage_users': user.can_manage_users()
                        }
                    },
                    'msg': 'Login Success'
                }, status=200)
            else:
                # Increment failed attempts
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.account_locked_until = datetime.utcnow() + timedelta(minutes=30)
                user.save()
                
                # Log failed login
                AuditLog(
                    user=user,
                    action='login',
                    resource_type='user',
                    resource_id=str(user.id),
                    details={'login_method': 'password', 'success': False, 'attempts': user.failed_login_attempts},
                    ip_address=ip_address,
                    user_agent=user_agent
                ).save()
        
        # Generic error for security
        return JsonResponse({
            'error': 'Invalid email or password'
        }, status=401)
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        # Check if it's a MongoDB connection error
        if 'SSL handshake failed' in str(e) or 'TLSV1_ALERT_INTERNAL_ERROR' in str(e):
            return JsonResponse({
                'error': 'Database connection error. Please try again later.',
                'details': 'SSL handshake failed with MongoDB'
            }, status=503)
        return JsonResponse({'error': 'Login failed'}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_user_profile(request):
    """Get user profile from MongoDB"""
    try:
        # Simple token validation (you can enhance this)
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Authentication required'}, status=401)
        
        # For simplicity, we'll extract email from token manually
        # In production, you'd want proper JWT validation
        token = auth_header.split(' ')[1]
        
        # This is a simplified approach - you'd want proper JWT decoding
        return JsonResponse({
            'message': 'Profile endpoint - implement JWT validation',
            'note': 'Use the login endpoint to get user data'
        })
        
    except Exception as e:
        logger.error(f"Profile error: {str(e)}")
        return JsonResponse({'error': 'Failed to get profile'}, status=500)


def generate_mock_certificate(common_name, certificate_type='self_signed'):
    """Generate a mock certificate for development"""
    return {
        'common_name': common_name,
        'serial_number': str(uuid.uuid4().hex[:16]),
        'fingerprint': str(uuid.uuid4().hex[:32]),
        'certificate_pem': f"""-----BEGIN CERTIFICATE-----
MOCK_CERTIFICATE_FOR_DEVELOPMENT_{common_name.upper().replace('.', '_')}
-----END CERTIFICATE-----""",
        'private_key_pem': f"""-----BEGIN PRIVATE KEY-----
MOCK_PRIVATE_KEY_FOR_DEVELOPMENT_{common_name.upper().replace('.', '_')}
-----END PRIVATE KEY-----""",
        'issued_at': datetime.utcnow(),
        'expires_at': datetime.utcnow() + timedelta(days=365),
        'certificate_type': certificate_type,
        'key_type': 'RSA',
        'key_size': 2048,
        'status': 'active'
    }


@csrf_exempt
def certificates_view(request):
    """Handle both GET and POST for certificates"""
    if request.method == 'GET':
        return get_certificates_list(request)
    elif request.method == 'POST':
        return create_certificate(request)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)


def get_certificates_list(request):
    """Get all certificates"""
    try:
        # Get all certificates from MongoDB
        certificates = Certificate.objects.all().order_by('-created_at')
        
        result = []
        for cert in certificates:
            result.append({
                'id': str(cert.id),
                'common_name': cert.common_name,
                'organization': cert.organization,
                'status': cert.status,
                'certificate_type': cert.certificate_type,
                'issued_at': cert.issued_at.isoformat() if cert.issued_at else None,
                'expires_at': cert.expires_at.isoformat() if cert.expires_at else None,
                'created_at': cert.created_at.isoformat(),
                'created_by': {
                    'id': str(cert.created_by.id) if cert.created_by else None,
                    'email': cert.created_by.email if cert.created_by else None
                } if cert.created_by else None,
                'subject_alternative_names': cert.subject_alternative_names,
                'key_type': cert.key_type,
                'key_size': cert.key_size,
                'serial_number': cert.serial_number,
                'fingerprint': cert.fingerprint
            })
        
        return JsonResponse({
            'success': True,
            'certificates': result,
            'count': len(result)
        })
        
    except Exception as e:
        logger.error(f"Error getting certificates: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


def create_certificate(request):
    """Create a new certificate"""
    try:
        data = json.loads(request.body)
        
        # Map frontend fields to backend fields
        common_name = data.get('hostname') or data.get('common_name')
        
        # Validate required fields
        if not common_name:
            return JsonResponse({
                'error': 'hostname or common_name is required'
            }, status=400)
        
        # Generate mock certificate data
        mock_cert = generate_mock_certificate(
            common_name, 
            data.get('certificate_type', 'self_signed')
        )
        
        # Create certificate in MongoDB
        certificate = Certificate(
            common_name=common_name,
            organization=data.get('organization', ''),
            organizational_unit=data.get('organizational_unit', ''),
            country=data.get('country', ''),
            state=data.get('state', ''),
            city=data.get('city', ''),
            email=data.get('email', ''),
            
            certificate_type=data.get('certificate_type', 'self_signed'),
            key_type=data.get('key_type', 'RSA'),
            key_size=int(data.get('key_size', 2048)),
            
            status=mock_cert['status'],
            serial_number=mock_cert['serial_number'],
            fingerprint=mock_cert['fingerprint'],
            
            certificate_pem=mock_cert['certificate_pem'],
            private_key_pem=mock_cert['private_key_pem'],
            
            issued_at=mock_cert['issued_at'],
            expires_at=mock_cert['expires_at'],
            
            subject_alternative_names=data.get('subject_alternative_names', []),
            created_at=datetime.utcnow()
        )
        
        certificate.save()
        
        # Create audit log
        AuditLog(
            action='certificate_create',
            resource_type='certificate',
            resource_id=str(certificate.id),
            details={
                'common_name': certificate.common_name,
                'certificate_type': certificate.certificate_type,
                'status': certificate.status
            },
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        ).save()
        
        return JsonResponse({
            'success': True,
            'message': 'Certificate created successfully',
            'certificate': {
                'id': str(certificate.id),
                'common_name': certificate.common_name,
                'organization': certificate.organization,
                'status': certificate.status,
                'certificate_type': certificate.certificate_type,
                'issued_at': certificate.issued_at.isoformat(),
                'expires_at': certificate.expires_at.isoformat(),
                'created_at': certificate.created_at.isoformat(),
                'serial_number': certificate.serial_number,
                'fingerprint': certificate.fingerprint,
                'key_type': certificate.key_type,
                'key_size': certificate.key_size
            }
        }, status=201)
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error creating certificate: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
def get_certificate(request, certificate_id):
    """Get a specific certificate or delete it"""
    if request.method == 'GET':
        return get_certificate_details(request, certificate_id)
    elif request.method == 'DELETE':
        return delete_certificate(request, certificate_id)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)


def get_certificate_details(request, certificate_id):
    """Get a specific certificate"""
    try:
        certificate = Certificate.objects(id=certificate_id).first()
        if not certificate:
            return JsonResponse({'error': 'Certificate not found'}, status=404)
        
        return JsonResponse({
            'success': True,
            'certificate': {
                'id': str(certificate.id),
                'common_name': certificate.common_name,
                'organization': certificate.organization,
                'organizational_unit': certificate.organizational_unit,
                'country': certificate.country,
                'state': certificate.state,
                'city': certificate.city,
                'email': certificate.email,
                'status': certificate.status,
                'certificate_type': certificate.certificate_type,
                'issued_at': certificate.issued_at.isoformat() if certificate.issued_at else None,
                'expires_at': certificate.expires_at.isoformat() if certificate.expires_at else None,
                'created_at': certificate.created_at.isoformat(),
                'subject_alternative_names': certificate.subject_alternative_names,
                'key_type': certificate.key_type,
                'key_size': certificate.key_size,
                'serial_number': certificate.serial_number,
                'fingerprint': certificate.fingerprint,
                'certificate_pem': certificate.certificate_pem[:100] + '...' if certificate.certificate_pem else None  # Truncated for security
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting certificate: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


def delete_certificate(request, certificate_id):
    """Delete a specific certificate"""
    try:
        certificate = Certificate.objects(id=certificate_id).first()
        if not certificate:
            return JsonResponse({'error': 'Certificate not found'}, status=404)
        
        # Store certificate info for audit log before deletion
        cert_info = {
            'id': str(certificate.id),
            'common_name': certificate.common_name,
            'status': certificate.status,
            'certificate_type': certificate.certificate_type
        }
        
        # Delete the certificate
        certificate.delete()
        
        # Log deletion action
        AuditLog(
            action='certificate_delete',
            resource_type='certificate',
            resource_id=certificate_id,
            details=cert_info,
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        ).save()
        
        return JsonResponse({
            'success': True,
            'message': 'Certificate deleted successfully',
            'deleted_certificate': cert_info
        })
        
    except Exception as e:
        logger.error(f"Error deleting certificate: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_step_ca_services(request):
    """Get Step-CA services"""
    try:
        # Return mock Step-CA service for development
        return JsonResponse({
            'success': True,
            'services': [{
                'id': 'step-ca-dev',
                'name': 'Step-CA Development',
                'url': 'localhost:9000',
                'status': 'step-cli-unavailable',
                'message': 'Development Mode Active',
                'description': 'Step-CA CLI is not installed. Mock certificates will be generated for development.',
                'note': 'To use real Step-CA: Install Step-CA CLI and configure the service.',
                'type': 'Mock Certificate (Development)',
                'purpose': 'Mock certificates for development and testing purposes'
            }]
        })
        
    except Exception as e:
        logger.error(f"Error getting Step-CA services: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def step_ca_health_check(request):
    """Check Step-CA service health"""
    try:
        from certificates.step_ca_service import get_step_ca_service
        
        service_url = request.GET.get('service_url', 'localhost:9000')
        
        # Get Step-CA service instance
        step_ca = get_step_ca_service(f"https://{service_url}")
        health_info = step_ca.get_ca_info()
        
        return JsonResponse({
            'success': True,
            'health': health_info
        })
        
    except Exception as e:
        logger.error(f"Step-CA health check failed: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e),
            'service_url': service_url
        }, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_certificate_statistics(request):
    """Get certificate statistics"""
    try:
        total_certificates = Certificate.objects.count()
        active_certificates = Certificate.objects(status='active').count()
        expired_certificates = Certificate.objects(status='expired').count()
        revoked_certificates = Certificate.objects(status='revoked').count()
        pending_certificates = Certificate.objects(status='pending').count()
        
        return JsonResponse({
            'success': True,
            'statistics': {
                'total_certificates': total_certificates,
                'active_certificates': active_certificates,
                'expired_certificates': expired_certificates,
                'revoked_certificates': revoked_certificates,
                'pending_certificates': pending_certificates,
                'certificate_types': {
                    'self_signed': Certificate.objects(certificate_type='self_signed').count(),
                    'ca_signed': Certificate.objects(certificate_type='ca_signed').count(),
                    'step_ca': Certificate.objects(certificate_type='step_ca').count()
                }
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting statistics: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def download_certificate(request, certificate_id):
    """Download certificate in various formats"""
    try:
        # Get certificate from MongoDB
        certificate = Certificate.objects(id=certificate_id).first()
        if not certificate:
            return JsonResponse({'error': 'Certificate not found'}, status=404)
        
        # Parse request data
        data = json.loads(request.body) if request.body else {}
        format_type = data.get('format', 'pem')
        include_private_key = data.get('include_private_key', False)
        include_chain = data.get('include_chain', False)
        password = data.get('password', '')
        
        # Generate download content based on format
        content, filename, content_type = generate_download_content(
            certificate, format_type, include_private_key, include_chain, password
        )
        
        # Create HTTP response with file download
        response = HttpResponse(content, content_type=content_type)
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        response['Content-Length'] = len(content)
        
        # Log download action
        AuditLog(
            action='certificate_download',
            resource_type='certificate',
            resource_id=str(certificate.id),
            details={
                'common_name': certificate.common_name,
                'format': format_type,
                'include_private_key': include_private_key,
                'include_chain': include_chain
            },
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        ).save()
        
        return response
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Certificate download failed: {str(e)}")
        return JsonResponse({'error': f'Download failed: {str(e)}'}, status=500)


def generate_download_content(certificate, format_type, include_private_key, include_chain, password):
    """Generate download content based on format"""
    
    if format_type == 'pem':
        # PEM format
        content = certificate.certificate_pem or ""
        
        if include_private_key and certificate.private_key_pem:
            content += "\n" + certificate.private_key_pem
        
        if include_chain:
            # Add certificate chain if available
            content += "\n# Certificate chain not available in mock data"
        
        filename = f"{certificate.common_name}.pem"
        content_type = "application/x-pem-file"
    
    elif format_type == 'der':
        # DER format (would require conversion from PEM)
        # For now, return PEM with different content type
        content = certificate.certificate_pem or ""
        filename = f"{certificate.common_name}.der"
        content_type = "application/x-x509-ca-cert"
    
    elif format_type == 'p12':
        # PKCS#12 format (would require OpenSSL conversion)
        # For now, return PEM with different content type
        content = certificate.certificate_pem or ""
        if include_private_key and certificate.private_key_pem:
            content += "\n" + certificate.private_key_pem
        filename = f"{certificate.common_name}.p12"
        content_type = "application/x-pkcs12"
    
    elif format_type == 'jks':
        # Java KeyStore format (would require Java keytool)
        # For now, return PEM with different content type
        content = certificate.certificate_pem or ""
        filename = f"{certificate.common_name}.jks"
        content_type = "application/x-java-keystore"
    
    else:
        raise ValueError(f"Unsupported format: {format_type}")
    
    return content.encode('utf-8'), filename, content_type


@csrf_exempt
@require_http_methods(["GET"])
def health_check(request):
    """Health check endpoint"""
    try:
        # Test MongoDB connection
        user_count = User.objects.count()
        cert_count = Certificate.objects.count()
        
        return JsonResponse({
            'status': 'healthy',
            'database': 'MongoDB',
            'users_count': user_count,
            'certificates_count': cert_count,
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'error': str(e)
        }, status=500)
