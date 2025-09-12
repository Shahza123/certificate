from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
import uuid

# User Role Choices
USER_ROLE_CHOICES = [
    ('admin', 'Admin'),
    ('certificate_manager', 'Certificate Manager'),
    ('regular_user', 'Regular User'),
]

#  Custom User Manager
class UserManager(BaseUserManager):
  def create_user(self, email, first_name, last_name, password=None, password2=None, role='regular_user'):
      """
      Creates and saves a User with the given email, name, first_name, last_name and password.
      """
      if not email:
          raise ValueError('User must have an email address')

      user = self.model(
          email=self.normalize_email(email),
          first_name=first_name,
          last_name=last_name,
          role=role,
      )

      user.set_password(password)
      user.save(using=self._db)
      return user

  def create_superuser(self, email, first_name, last_name, password=None):
      """
      Creates and saves a superuser with the given email, name, first_name, last_name and password.
      """
      user = self.create_user(
          email,
          password=password,
          first_name=first_name,
          last_name=last_name,
          role='admin'
      )
      user.is_admin = True
      user.save(using=self._db)
      return user

#  Custom User Model
class User(AbstractBaseUser):
  id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
  email = models.EmailField(
      verbose_name='Email',
      max_length=255,
      unique=True,
  )
  first_name = models.CharField(max_length=100)
  last_name = models.CharField(max_length=100)
  role = models.CharField(max_length=20, choices=USER_ROLE_CHOICES, default='regular_user')
  department = models.CharField(max_length=100, blank=True, null=True)
  phone_number = models.CharField(max_length=20, blank=True, null=True)
  
  # Authentication and Security
  is_active = models.BooleanField(default=True)
  is_admin = models.BooleanField(default=False)
  two_factor_enabled = models.BooleanField(default=False)
  last_login_ip = models.GenericIPAddressField(blank=True, null=True)
  failed_login_attempts = models.IntegerField(default=0)
  account_locked_until = models.DateTimeField(blank=True, null=True)
  
  # Timestamps
  created_at = models.DateTimeField(auto_now_add=True)
  updated_at = models.DateTimeField(auto_now=True)
  last_password_change = models.DateTimeField(auto_now_add=True)

  objects = UserManager()

  USERNAME_FIELD = 'email'
  REQUIRED_FIELDS = ['first_name', 'last_name']

  def __str__(self):
      return f"{self.email} ({self.get_role_display()})"

  @property
  def full_name(self):
      return f"{self.first_name} {self.last_name}"

  def has_perm(self, perm, obj=None):
      """Does the user have a specific permission?"""
      if self.is_admin:
          return True
      
      # Role-based permissions
      role_permissions = {
          'admin': ['view', 'add', 'change', 'delete', 'deploy', 'revoke', 'manage_users'],
          'certificate_manager': ['view', 'add', 'change', 'deploy', 'revoke'],
          'regular_user': ['view', 'add']
      }
      
      user_permissions = role_permissions.get(self.role, [])
      return perm in user_permissions

  def has_module_perms(self, app_label):
      """Does the user have permissions to view the app `app_label`?"""
      return True

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

  class Meta:
      indexes = [
          models.Index(fields=['email']),
          models.Index(fields=['role']),
          models.Index(fields=['created_at']),
      ]


class UserProfile(models.Model):
    """Extended user profile for additional information"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    bio = models.TextField(max_length=500, blank=True)
    avatar = models.ImageField(upload_to='avatars/', blank=True, null=True)
    notification_preferences = models.JSONField(default=dict, blank=True)
    api_key = models.CharField(max_length=128, unique=True, blank=True, null=True)
    api_key_created_at = models.DateTimeField(blank=True, null=True)
    
    def __str__(self):
        return f"Profile for {self.user.email}"


class AuditLog(models.Model):
    """Audit log for tracking user actions"""
    ACTION_CHOICES = [
        ('login', 'User Login'),
        ('logout', 'User Logout'),
        ('certificate_create', 'Certificate Created'),
        ('certificate_revoke', 'Certificate Revoked'),
        ('certificate_renew', 'Certificate Renewed'),
        ('certificate_download', 'Certificate Downloaded'),
        ('certificate_deploy', 'Certificate Deployed'),
        ('user_create', 'User Created'),
        ('user_update', 'User Updated'),
        ('user_delete', 'User Deleted'),
        ('settings_change', 'Settings Changed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    resource_type = models.CharField(max_length=50, blank=True)
    resource_id = models.CharField(max_length=100, blank=True)
    details = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
            models.Index(fields=['resource_type', 'resource_id']),
        ]
    
    def __str__(self):
        user_email = self.user.email if self.user else 'Anonymous'
        return f"{user_email} - {self.get_action_display()} at {self.timestamp}"



