"""
MongoDB Models for Authentication using MongoEngine

This module contains MongoDB-compatible models for user authentication and management.
"""

from mongoengine import Document, EmbeddedDocument, fields
from datetime import datetime, timedelta
import uuid
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password

# User Role Choices
USER_ROLE_CHOICES = [
    ('admin', 'Admin'),
    ('certificate_manager', 'Certificate Manager'),
    ('regular_user', 'Regular User'),
]


class UserProfile(EmbeddedDocument):
    """Embedded document for user profile information"""
    bio = fields.StringField(max_length=500)
    avatar_url = fields.URLField()
    notification_preferences = fields.DictField(default=dict)
    api_key = fields.StringField(max_length=128)
    api_key_created_at = fields.DateTimeField()
    
    def __str__(self):
        return f"Profile for user"


class User(Document):
    """MongoDB User model using MongoEngine"""
    
    # Basic Information
    id = fields.UUIDField(primary_key=True, default=uuid.uuid4)
    email = fields.EmailField(required=True, unique=True, max_length=255)
    first_name = fields.StringField(required=True, max_length=100)
    last_name = fields.StringField(required=True, max_length=100)
    password = fields.StringField(required=True, max_length=128)
    
    # Role and Department
    role = fields.StringField(choices=USER_ROLE_CHOICES, default='regular_user', max_length=20)
    department = fields.StringField(max_length=100)
    phone_number = fields.StringField(max_length=20)
    
    # Authentication and Security
    is_active = fields.BooleanField(default=True)
    is_admin = fields.BooleanField(default=False)
    two_factor_enabled = fields.BooleanField(default=False)
    last_login = fields.DateTimeField()
    last_login_ip = fields.StringField(max_length=45)
    failed_login_attempts = fields.IntField(default=0)
    account_locked_until = fields.DateTimeField()
    
    # Timestamps
    created_at = fields.DateTimeField(default=datetime.utcnow)
    updated_at = fields.DateTimeField(default=datetime.utcnow)
    last_password_change = fields.DateTimeField(default=datetime.utcnow)
    
    # Profile
    profile = fields.EmbeddedDocumentField(UserProfile)
    
    meta = {
        'collection': 'users',
        'indexes': [
            'email',
            'role',
            'created_at',
            ('email', 'role')
        ]
    }
    
    def __str__(self):
        return f"{self.email} ({self.role})"
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"
    
    def set_password(self, raw_password):
        """Set password with Django's password hashing"""
        self.password = make_password(raw_password)
        self.last_password_change = datetime.utcnow()
    
    def check_password(self, raw_password):
        """Check password against hash"""
        return check_password(raw_password, self.password)
    
    def save(self, *args, **kwargs):
        """Override save to update timestamps"""
        self.updated_at = datetime.utcnow()
        super().save(*args, **kwargs)
    
    # Permission methods
    def can_manage_certificates(self):
        """Can the user manage certificates?"""
        return self.role in ['admin', 'certificate_manager']
    
    def can_deploy_certificates(self):
        """Can the user deploy certificates?"""
        return self.role in ['admin', 'certificate_manager']
    
    def can_revoke_certificates(self):
        """Can the user revoke certificates?"""
        return self.role in ['admin', 'certificate_manager']
    
    def can_manage_users(self):
        """Can the user manage other users?"""
        return self.role == 'admin'
    
    @property
    def is_staff(self):
        """Is the user a member of staff?"""
        return self.is_admin or self.role in ['admin', 'certificate_manager']


class AuditLog(Document):
    """MongoDB model for audit logging"""
    
    ACTION_CHOICES = [
        ('login', 'User Login'),
        ('logout', 'User Logout'),
        ('certificate_create', 'Certificate Created'),
        ('certificate_delete', 'Certificate Deleted'),
        ('certificate_revoke', 'Certificate Revoked'),
        ('certificate_renew', 'Certificate Renewed'),
        ('certificate_download', 'Certificate Downloaded'),
        ('certificate_deploy', 'Certificate Deployed'),
        ('csr_create', 'CSR Created'),
        ('csr_approve', 'CSR Approved'),
        ('csr_reject', 'CSR Rejected'),
        ('user_create', 'User Created'),
        ('user_update', 'User Updated'),
        ('user_delete', 'User Deleted'),
        ('settings_change', 'Settings Changed'),
    ]
    
    id = fields.UUIDField(primary_key=True, default=uuid.uuid4)
    user = fields.ReferenceField(User, required=False)
    action = fields.StringField(choices=ACTION_CHOICES, required=True, max_length=50)
    resource_type = fields.StringField(max_length=50)
    resource_id = fields.StringField(max_length=100)
    details = fields.DictField(default=dict)
    ip_address = fields.StringField(max_length=45)
    user_agent = fields.StringField()
    timestamp = fields.DateTimeField(default=datetime.utcnow)
    
    meta = {
        'collection': 'audit_logs',
        'indexes': [
            'user',
            'action',
            'timestamp',
            'resource_type',
            ('user', 'timestamp'),
            ('action', 'timestamp'),
            ('resource_type', 'resource_id')
        ],
        'ordering': ['-timestamp']
    }
    
    def __str__(self):
        user_email = self.user.email if self.user else 'Anonymous'
        return f"{user_email} - {self.action} at {self.timestamp}"


# Custom User Manager equivalent for MongoEngine
class UserManager:
    """User manager for MongoDB User model"""
    
    @staticmethod
    def create_user(email, first_name, last_name, password, role='regular_user'):
        """Create a new user"""
        user = User(
            email=email,
            first_name=first_name,
            last_name=last_name,
            role=role
        )
        user.set_password(password)
        user.save()
        return user
    
    @staticmethod
    def create_superuser(email, first_name, last_name, password):
        """Create a superuser"""
        user = UserManager.create_user(
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=password,
            role='admin'
        )
        user.is_admin = True
        user.save()
        return user
    
    @staticmethod
    def get_by_email(email):
        """Get user by email"""
        try:
            return User.objects(email=email).first()
        except User.DoesNotExist:
            return None
    
    @staticmethod
    def authenticate(email, password):
        """Authenticate user"""
        user = UserManager.get_by_email(email)
        if user and user.check_password(password) and user.is_active:
            return user
        return None


# Make User.objects work like Django ORM
# Note: For MongoEngine, User.objects is automatically available
