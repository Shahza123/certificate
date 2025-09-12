"""
MongoDB Views for Authentication using MongoEngine

Updated views to work with MongoDB models.
"""

from rest_framework.response import Response
from rest_framework import status, generics, permissions
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from django.utils import timezone
from datetime import datetime, timedelta
from auths.mongodb_serializers import (
    MongoUserRegistrationSerializer, MongoUserLoginSerializer, 
    MongoUserProfileSerializer, MongoUserListSerializer
)
from auths.mongodb_models import User, AuditLog, UserManager
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
import logging

logger = logging.getLogger(__name__)


# Generate Token Manually
def get_tokens_for_user(user):
    # Create a token based on user's string ID
    token_user_id = str(user.id)
    refresh = RefreshToken()
    refresh['user_id'] = token_user_id
    refresh['email'] = user.email
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class UserRegistrationView(APIView):
    permission_classes = []  # Allow unauthenticated access for registration
    
    def post(self, request, format=None):
        serializer = MongoUserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            # Create user using MongoDB model
            try:
                user = serializer.save()
                
                token = get_tokens_for_user(user)
                
                # Log the registration
                AuditLog(
                    user=user,
                    action='user_create',
                    resource_type='user',
                    resource_id=str(user.id),
                    details={'email': user.email, 'role': user.role},
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                ).save()
                
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
            
            except Exception as e:
                return Response({
                    'error': f'Registration failed: {str(e)}'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    permission_classes = []  # Allow unauthenticated access for login
    
    def post(self, request, format=None):
        serializer = MongoUserLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            
            # Get client IP
            ip_address = request.META.get('REMOTE_ADDR')
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            
            try:
                user = User.objects(email=email).first()
                
                if user:
                    # Check if account is locked
                    if user.account_locked_until and user.account_locked_until > datetime.utcnow():
                        return Response({
                            'errors': {'non_field_errors': ['Account is temporarily locked. Please try again later.']}
                        }, status=status.HTTP_423_LOCKED)
                    
                    # Authenticate user
                    if user.check_password(password) and user.is_active:
                        # Reset failed login attempts on successful login
                        user.failed_login_attempts = 0
                        user.account_locked_until = None
                        user.last_login = datetime.utcnow()
                        user.last_login_ip = ip_address
                        user.save()
                        
                        token = get_tokens_for_user(user)
                        
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
                
                # Generic error message for security
                return Response({
                    'errors': {'non_field_errors': ['Email or Password is not Valid']}
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            except Exception as e:
                logger.error(f"Login error: {str(e)}")
                return Response({
                    'errors': {'non_field_errors': ['Login failed. Please try again.']}
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request, format=None):
        # Get user from MongoDB by email (since request.user might be Django user)
        try:
            # Extract email from JWT token or request
            user_email = getattr(request.user, 'email', None)
            if user_email:
                user = User.objects(email=user_email).first()
            else:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            
            if user:
                return Response({
                    'user': {
                        'id': str(user.id),
                        'email': user.email,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'role': user.role,
                        'department': user.department,
                        'phone_number': user.phone_number,
                        'two_factor_enabled': user.two_factor_enabled,
                        'created_at': user.created_at.isoformat(),
                        'permissions': {
                            'can_manage_certificates': user.can_manage_certificates(),
                            'can_deploy_certificates': user.can_deploy_certificates(),
                            'can_revoke_certificates': user.can_revoke_certificates(),
                            'can_manage_users': user.can_manage_users()
                        }
                    },
                    'msg': 'Profile fetched successfully'
                }, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        except Exception as e:
            logger.error(f"Profile fetch error: {str(e)}")
            return Response({'error': 'Failed to fetch profile'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserLogoutView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request, format=None):
        try:
            refresh_token = request.data.get("refresh")
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
            
            # Get user from MongoDB for logging
            user_email = getattr(request.user, 'email', None)
            if user_email:
                user = User.objects(email=user_email).first()
                if user:
                    # Log logout
                    AuditLog(
                        user=user,
                        action='logout',
                        resource_type='user',
                        resource_id=str(user.id),
                        ip_address=request.META.get('REMOTE_ADDR')
                    ).save()
            
            return Response({'msg': 'Logout successful'}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class UserListView(APIView):
    """List all users (Admin only)"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            # Get current user from MongoDB
            user_email = getattr(request.user, 'email', None)
            current_user = User.objects(email=user_email).first() if user_email else None
            
            if not current_user or not current_user.can_manage_users():
                return Response({
                    'error': 'Insufficient permissions'
                }, status=status.HTTP_403_FORBIDDEN)
            
            # Build query
            query = {}
            
            # Filter by role
            role = request.query_params.get('role')
            if role:
                query['role'] = role
            
            # Filter by active status
            is_active = request.query_params.get('is_active')
            if is_active is not None:
                query['is_active'] = is_active.lower() == 'true'
            
            # Search by email or name
            search = request.query_params.get('search')
            if search:
                from mongoengine import Q
                query = User.objects(
                    Q(email__icontains=search) |
                    Q(first_name__icontains=search) |
                    Q(last_name__icontains=search)
                )
            else:
                query = User.objects(**query)
            
            users = []
            for user in query.order_by('-created_at'):
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
        
        except Exception as e:
            logger.error(f"User list error: {str(e)}")
            return Response({'error': 'Failed to fetch users'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_user_role(request, user_id):
    """Change user role (Admin only)"""
    try:
        # Get current user from MongoDB
        user_email = getattr(request.user, 'email', None)
        current_user = User.objects(email=user_email).first() if user_email else None
        
        if not current_user or not current_user.can_manage_users():
            return Response({
                'error': 'Insufficient permissions'
            }, status=status.HTTP_403_FORBIDDEN)
        
        user = User.objects(id=user_id).first()
        if not user:
            return Response({
                'error': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        new_role = request.data.get('role')
        if new_role not in ['admin', 'certificate_manager', 'regular_user']:
            return Response({
                'error': 'Invalid role'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        old_role = user.role
        user.role = new_role
        user.save()
        
        # Log role change
        AuditLog(
            user=current_user,
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
        ).save()
        
        return Response({
            'message': f'User role changed from {old_role} to {new_role}',
            'user': {
                'id': str(user.id),
                'email': user.email,
                'role': user.role
            }
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Role change error: {str(e)}")
        return Response({
            'error': 'Failed to change user role'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def toggle_user_status(request, user_id):
    """Activate/deactivate user (Admin only)"""
    try:
        # Get current user from MongoDB
        user_email = getattr(request.user, 'email', None)
        current_user = User.objects(email=user_email).first() if user_email else None
        
        if not current_user or not current_user.can_manage_users():
            return Response({
                'error': 'Insufficient permissions'
            }, status=status.HTTP_403_FORBIDDEN)
        
        user = User.objects(id=user_id).first()
        if not user:
            return Response({
                'error': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Prevent admin from deactivating themselves
        if str(user.id) == str(current_user.id):
            return Response({
                'error': 'Cannot deactivate your own account'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        user.is_active = not user.is_active
        user.save()
        
        # Log status change
        AuditLog(
            user=current_user,
            action='user_update',
            resource_type='user',
            resource_id=str(user.id),
            details={
                'field': 'is_active',
                'new_value': user.is_active,
                'target_user': user.email
            },
            ip_address=request.META.get('REMOTE_ADDR')
        ).save()
        
        status_text = 'activated' if user.is_active else 'deactivated'
        return Response({
            'message': f'User {status_text} successfully',
            'user': {
                'id': str(user.id),
                'email': user.email,
                'is_active': user.is_active
            }
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Status toggle error: {str(e)}")
        return Response({
            'error': 'Failed to toggle user status'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
