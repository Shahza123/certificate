from rest_framework.response import Response
from rest_framework import status, generics, permissions
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from django.contrib.auth import authenticate
from django.utils import timezone
from django.db.models import Q
from auths.serializers import (
    UserRegistrationSerializer, UserLoginSerializer
)
from auths.models import AuditLog, User
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
import logging

logger = logging.getLogger(__name__)


# Generate Token Manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class UserRegistrationView(APIView):
    def post(self, request, format=None):
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = get_tokens_for_user(user)
        
        # Log the registration
        AuditLog.objects.create(
            user=user,
            action='user_create',
            resource_type='user',
            resource_id=str(user.id),
            details={'email': user.email, 'role': user.role},
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        return Response({
            'token': token,
            'user': {
                'id': str(user.id),
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'role': user.role
            },
            'msg': 'Registration Successful'
        }, status=status.HTTP_201_CREATED)


class UserLoginView(APIView):
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        password = serializer.data.get('password')
        
        # Get client IP
        ip_address = request.META.get('REMOTE_ADDR')
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        try:
            user = User.objects.get(email=email)
            
            # Check if account is locked
            if user.account_locked_until and user.account_locked_until > timezone.now():
                return Response({
                    'errors': {'non_field_errors': ['Account is temporarily locked. Please try again later.']}
                }, status=status.HTTP_423_LOCKED)
            
            # Authenticate user
            auth_user = authenticate(email=email, password=password)
            if auth_user is not None:
                # Reset failed login attempts on successful login
                user.failed_login_attempts = 0
                user.account_locked_until = None
                user.last_login_ip = ip_address
                user.save()
                
                token = get_tokens_for_user(user)
                
                # Log successful login
                AuditLog.objects.create(
                    user=user,
                    action='login',
                    resource_type='user',
                    resource_id=str(user.id),
                    details={'login_method': 'password'},
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                return Response({
                    'token': token,
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
                }, status=status.HTTP_200_OK)
            else:
                # Increment failed login attempts
                user.failed_login_attempts += 1
                
                # Lock account after 5 failed attempts
                if user.failed_login_attempts >= 5:
                    user.account_locked_until = timezone.now() + timezone.timedelta(minutes=30)
                
                user.save()
                
                # Log failed login
                AuditLog.objects.create(
                    user=user,
                    action='login',
                    resource_type='user',
                    resource_id=str(user.id),
                    details={'login_method': 'password', 'success': False, 'attempts': user.failed_login_attempts},
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                return Response({
                    'errors': {'non_field_errors': ['Email or Password is not Valid']}
                }, status=status.HTTP_401_UNAUTHORIZED)
        
        except User.DoesNotExist:
            # Log failed login attempt for non-existent user
            AuditLog.objects.create(
                action='login',
                resource_type='user',
                details={'email': email, 'success': False, 'reason': 'user_not_found'},
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            return Response({
                'errors': {'non_field_errors': ['Email or Password is not Valid']}
            }, status=status.HTTP_401_UNAUTHORIZED)


class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request, format=None):
        return Response({
            'user': {
                'id': str(request.user.id),
                'email': request.user.email,
                'first_name': request.user.first_name,
                'last_name': request.user.last_name,
                'role': request.user.role,
                'department': request.user.department,
                'phone_number': request.user.phone_number,
                'two_factor_enabled': request.user.two_factor_enabled,
                'created_at': request.user.created_at.isoformat(),
                'permissions': {
                    'can_manage_certificates': request.user.can_manage_certificates(),
                    'can_deploy_certificates': request.user.can_deploy_certificates(),
                    'can_revoke_certificates': request.user.can_revoke_certificates(),
                    'can_manage_users': request.user.can_manage_users()
                }
            },
            'msg': 'Profile fetched successfully'
        }, status=status.HTTP_200_OK)


class UserLogoutView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request, format=None):
        try:
            refresh_token = request.data.get("refresh")
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
            
            # Log logout
            AuditLog.objects.create(
                user=request.user,
                action='logout',
                resource_type='user',
                resource_id=str(request.user.id),
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            return Response({'msg': 'Logout successful'}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class UserListView(generics.ListAPIView):
    """List all users (Admin only)"""
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        if not self.request.user.can_manage_users():
            return User.objects.none()
        
        queryset = User.objects.all()
        
        # Filter by role
        role = self.request.query_params.get('role')
        if role:
            queryset = queryset.filter(role=role)
        
        # Filter by active status
        is_active = self.request.query_params.get('is_active')
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        
        # Search by email or name
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(email__icontains=search) |
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search)
            )
        
        return queryset.order_by('-created_at')
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        users = []
        for user in queryset:
            users.append({
                'id': str(user.id),
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'role': user.role,
                'department': user.department,
                'is_active': user.is_active,
                'created_at': user.created_at.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None
            })
        
        return Response(users, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_user_role(request, user_id):
    """Change user role (Admin only)"""
    if not request.user.can_manage_users():
        return Response({
            'error': 'Insufficient permissions'
        }, status=status.HTTP_403_FORBIDDEN)
    
    try:
        user = User.objects.get(id=user_id)
        new_role = request.data.get('role')
        
        if new_role not in ['admin', 'certificate_manager', 'regular_user']:
            return Response({
                'error': 'Invalid role'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        old_role = user.role
        user.role = new_role
        user.save()
        
        # Log role change
        AuditLog.objects.create(
            user=request.user,
            action='user_update',
            resource_type='user',
            resource_id=str(user.id),
            details={
                'field': 'role',
                'old_value': old_role,
                'new_value': new_role,
                'target_user': user.email
            },
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        return Response({
            'message': f'User role changed from {old_role} to {new_role}',
            'user': {
                'id': str(user.id),
                'email': user.email,
                'role': user.role
            }
        }, status=status.HTTP_200_OK)
    
    except User.DoesNotExist:
        return Response({
            'error': 'User not found'
        }, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def toggle_user_status(request, user_id):
    """Activate/deactivate user (Admin only)"""
    if not request.user.can_manage_users():
        return Response({
            'error': 'Insufficient permissions'
        }, status=status.HTTP_403_FORBIDDEN)
    
    try:
        user = User.objects.get(id=user_id)
        
        # Prevent admin from deactivating themselves
        if user.id == request.user.id:
            return Response({
                'error': 'Cannot deactivate your own account'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        user.is_active = not user.is_active
        user.save()
        
        # Log status change
        AuditLog.objects.create(
            user=request.user,
            action='user_update',
            resource_type='user',
            resource_id=str(user.id),
            details={
                'field': 'is_active',
                'new_value': user.is_active,
                'target_user': user.email
            },
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        status_text = 'activated' if user.is_active else 'deactivated'
        return Response({
            'message': f'User {status_text} successfully',
            'user': {
                'id': str(user.id),
                'email': user.email,
                'is_active': user.is_active
            }
        }, status=status.HTTP_200_OK)
    
    except User.DoesNotExist:
        return Response({
            'error': 'User not found'
        }, status=status.HTTP_404_NOT_FOUND)