"""
MongoDB Models for Certificate Management using MongoEngine

This module contains MongoDB-compatible models for certificate management.
"""

from mongoengine import Document, EmbeddedDocument, fields
from datetime import datetime, timedelta
import uuid
from auths.mongodb_models import User


class Certificate(Document):
    """MongoDB Certificate model"""
    
    CERTIFICATE_TYPES = [
        ('self_signed', 'Self-Signed'),
        ('ca_signed', 'CA-Signed'),
        ('step_ca', 'Step-CA'),
        ('csr_based', 'CSR-Based')
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('revoked', 'Revoked'),
        ('pending', 'Pending'),
        ('renewal_pending', 'Renewal Pending'),
        ('deployment_pending', 'Deployment Pending'),
        ('deployed', 'Deployed'),
        ('failed', 'Failed')
    ]
    
    KEY_SIZES = [
        ('2048', '2048'),
        ('4096', '4096'),
        ('8192', '8192')
    ]
    
    KEY_TYPES = [
        ('RSA', 'RSA'),
        ('ECDSA', 'ECDSA'),
        ('Ed25519', 'Ed25519')
    ]
    
    # Basic Information
    id = fields.UUIDField(primary_key=True, default=uuid.uuid4)
    hostname = fields.StringField(required=True, max_length=255)
    certificate_type = fields.StringField(choices=CERTIFICATE_TYPES, default='step_ca', max_length=20)
    status = fields.StringField(choices=STATUS_CHOICES, default='pending', max_length=20)
    
    # Certificate Details
    key_size = fields.StringField(choices=KEY_SIZES, default='2048', max_length=10)
    key_type = fields.StringField(choices=KEY_TYPES, default='RSA', max_length=10)
    validity_period = fields.StringField(default='1-year', max_length=20)
    
    # CSR Information
    csr_content = fields.StringField()
    subject_alternative_names = fields.ListField(fields.StringField(), default=list)
    
    # Extended Certificate Information
    serial_number = fields.StringField(max_length=100)
    fingerprint_sha256 = fields.StringField(max_length=100)
    common_name = fields.StringField(max_length=255)
    organization = fields.StringField(max_length=255)
    organizational_unit = fields.StringField(max_length=255)
    country = fields.StringField(max_length=2)
    state = fields.StringField(max_length=255)
    locality = fields.StringField(max_length=255)
    
    # Deployment Information
    deployment_targets = fields.ListField(fields.StringField(), default=list)
    deployment_status = fields.StringField(max_length=50)
    last_deployment_date = fields.DateTimeField()
    
    # Renewal Information
    auto_renewal = fields.BooleanField(default=False)
    renewal_threshold_days = fields.IntField(default=30)
    previous_certificate = fields.ReferenceField('self')
    
    # Dates
    issued_date = fields.DateTimeField()
    expiry_date = fields.DateTimeField()
    created_at = fields.DateTimeField(default=datetime.utcnow)
    updated_at = fields.DateTimeField(default=datetime.utcnow)
    
    # User and Service Information
    created_by = fields.ReferenceField(User, required=True)
    issuer = fields.StringField(default='Step-CA Service', max_length=255)
    step_ca_service = fields.StringField(default='localhost:9000', max_length=255)
    email = fields.EmailField()
    
    # Certificate Content
    certificate_content = fields.StringField()
    private_key = fields.StringField()
    certificate_chain = fields.StringField()
    
    # Step-CA specific fields
    step_ca_token = fields.StringField(max_length=500)
    step_ca_fingerprint = fields.StringField(max_length=100)
    
    # Validation and Monitoring
    last_validation_check = fields.DateTimeField()
    validation_status = fields.StringField(max_length=50)
    
    meta = {
        'collection': 'certificates',
        'indexes': [
            'hostname',
            'status',
            'expiry_date',
            'created_by',
            'certificate_type',
            ('hostname', 'created_by'),
            ('status', 'expiry_date')
        ],
        'ordering': ['-created_at']
    }
    
    def __str__(self):
        return f"{self.hostname} - {self.certificate_type}"
    
    @property
    def is_expired(self):
        """Check if certificate is expired"""
        if self.expiry_date:
            return datetime.utcnow() > self.expiry_date
        return False
    
    @property
    def days_until_expiry(self):
        """Get number of days until expiry"""
        if self.expiry_date:
            delta = self.expiry_date - datetime.utcnow()
            return delta.days
        return None
    
    @property
    def is_expiring_soon(self):
        """Check if certificate expires within 30 days"""
        days = self.days_until_expiry
        return days is not None and days <= 30
    
    def save(self, *args, **kwargs):
        """Override save to update timestamps and status"""
        self.updated_at = datetime.utcnow()
        
        # Auto-update status based on expiry
        if self.is_expired and self.status == 'active':
            self.status = 'expired'
        
        super().save(*args, **kwargs)


class CSRTemplate(Document):
    """Template for Certificate Signing Requests"""
    
    id = fields.UUIDField(primary_key=True, default=uuid.uuid4)
    name = fields.StringField(required=True, unique=True, max_length=100)
    description = fields.StringField()
    
    # Subject Information
    country = fields.StringField(default='US', max_length=2)
    state = fields.StringField(default='', max_length=255)
    locality = fields.StringField(default='', max_length=255)
    organization = fields.StringField(default='', max_length=255)
    organizational_unit = fields.StringField(default='IT Department', max_length=255)
    
    # Key Configuration
    key_type = fields.StringField(choices=Certificate.KEY_TYPES, default='RSA', max_length=10)
    key_size = fields.StringField(choices=Certificate.KEY_SIZES, default='2048', max_length=10)
    
    # Default validity
    default_validity = fields.StringField(default='1-year', max_length=20)
    
    # Template settings
    is_active = fields.BooleanField(default=True)
    created_by = fields.ReferenceField(User, required=True)
    created_at = fields.DateTimeField(default=datetime.utcnow)
    updated_at = fields.DateTimeField(default=datetime.utcnow)
    
    meta = {
        'collection': 'csr_templates',
        'indexes': ['name', 'created_by', 'is_active'],
        'ordering': ['name']
    }
    
    def __str__(self):
        return f"CSR Template: {self.name}"


class CertificateSigningRequest(Document):
    """Model to track Certificate Signing Requests"""
    
    STATUS_CHOICES = [
        ('pending', 'Pending Review'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('completed', 'Completed'),
        ('expired', 'Expired'),
    ]
    
    id = fields.UUIDField(primary_key=True, default=uuid.uuid4)
    certificate = fields.ReferenceField(Certificate)
    
    # CSR Content
    csr_content = fields.StringField(required=True)
    private_key = fields.StringField()
    
    # Request Details
    common_name = fields.StringField(required=True, max_length=255)
    subject_alternative_names = fields.ListField(fields.StringField(), default=list)
    organization = fields.StringField(max_length=255)
    organizational_unit = fields.StringField(max_length=255)
    country = fields.StringField(max_length=2)
    state = fields.StringField(max_length=255)
    locality = fields.StringField(max_length=255)
    email = fields.EmailField()
    
    # Key Information
    key_type = fields.StringField(default='RSA', max_length=10)
    key_size = fields.StringField(default='2048', max_length=10)
    
    # Request Management
    status = fields.StringField(choices=STATUS_CHOICES, default='pending', max_length=20)
    requested_by = fields.ReferenceField(User, required=True)
    approved_by = fields.ReferenceField(User)
    
    # Validity
    requested_validity = fields.StringField(default='1-year', max_length=20)
    
    # Timestamps
    created_at = fields.DateTimeField(default=datetime.utcnow)
    approved_at = fields.DateTimeField()
    completed_at = fields.DateTimeField()
    
    # Additional Information
    justification = fields.StringField()
    rejection_reason = fields.StringField()
    
    meta = {
        'collection': 'certificate_signing_requests',
        'indexes': ['requested_by', 'status', 'created_at'],
        'ordering': ['-created_at']
    }
    
    def __str__(self):
        return f"CSR for {self.common_name} by {self.requested_by.email}"


class DeploymentTarget(Document):
    """Model to define certificate deployment targets"""
    
    TARGET_TYPES = [
        ('ssh', 'SSH Server'),
        ('api', 'API Endpoint'),
        ('webhook', 'Webhook'),
        ('manual', 'Manual Download'),
    ]
    
    id = fields.UUIDField(primary_key=True, default=uuid.uuid4)
    name = fields.StringField(required=True, max_length=100)
    description = fields.StringField()
    target_type = fields.StringField(choices=TARGET_TYPES, required=True, max_length=20)
    
    # Connection Information
    hostname = fields.StringField(required=True, max_length=255)
    port = fields.IntField(default=22)
    username = fields.StringField(max_length=100)
    
    # SSH Configuration
    ssh_key_path = fields.StringField(max_length=500)
    remote_cert_path = fields.StringField(max_length=500)
    remote_key_path = fields.StringField(max_length=500)
    post_deploy_command = fields.StringField()
    
    # API Configuration
    api_endpoint = fields.URLField()
    api_token = fields.StringField(max_length=500)
    api_headers = fields.DictField(default=dict)
    
    # Status
    is_active = fields.BooleanField(default=True)
    last_deployment = fields.DateTimeField()
    last_deployment_status = fields.StringField(max_length=50)
    
    # Management
    created_by = fields.ReferenceField(User, required=True)
    created_at = fields.DateTimeField(default=datetime.utcnow)
    updated_at = fields.DateTimeField(default=datetime.utcnow)
    
    meta = {
        'collection': 'deployment_targets',
        'indexes': ['created_by', 'target_type', 'is_active'],
        'unique_together': [('name', 'created_by')]
    }
    
    def __str__(self):
        return f"{self.name} ({self.target_type})"


class CertificateDeployment(Document):
    """Model to track certificate deployments"""
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    id = fields.UUIDField(primary_key=True, default=uuid.uuid4)
    certificate = fields.ReferenceField(Certificate, required=True)
    target = fields.ReferenceField(DeploymentTarget, required=True)
    
    # Deployment Details
    status = fields.StringField(choices=STATUS_CHOICES, default='pending', max_length=20)
    started_at = fields.DateTimeField(default=datetime.utcnow)
    completed_at = fields.DateTimeField()
    
    # Execution Information
    initiated_by = fields.ReferenceField(User, required=True)
    deployment_log = fields.StringField()
    error_message = fields.StringField()
    
    # Configuration
    backup_existing = fields.BooleanField(default=True)
    restart_services = fields.BooleanField(default=False)
    services_to_restart = fields.ListField(fields.StringField(), default=list)
    
    meta = {
        'collection': 'certificate_deployments',
        'indexes': ['certificate', 'target', 'initiated_by', 'status', 'started_at'],
        'ordering': ['-started_at']
    }
    
    def __str__(self):
        return f"Deployment of {self.certificate.hostname} to {self.target.name}"


class NotificationRule(Document):
    """Model to define notification rules for certificate events"""
    
    EVENT_TYPES = [
        ('expiry_30', 'Certificate Expires in 30 Days'),
        ('expiry_7', 'Certificate Expires in 7 Days'),
        ('expiry_1', 'Certificate Expires in 1 Day'),
        ('expired', 'Certificate Expired'),
        ('issued', 'Certificate Issued'),
        ('revoked', 'Certificate Revoked'),
        ('deployment_success', 'Deployment Successful'),
        ('deployment_failed', 'Deployment Failed'),
        ('csr_pending', 'CSR Pending Approval'),
    ]
    
    NOTIFICATION_METHODS = [
        ('email', 'Email'),
        ('webhook', 'Webhook'),
        ('api', 'API Call'),
    ]
    
    id = fields.UUIDField(primary_key=True, default=uuid.uuid4)
    name = fields.StringField(required=True, max_length=100)
    description = fields.StringField()
    
    # Rule Configuration
    event_type = fields.StringField(choices=EVENT_TYPES, required=True, max_length=30)
    notification_method = fields.StringField(choices=NOTIFICATION_METHODS, required=True, max_length=20)
    
    # Recipients
    recipients = fields.ListField(fields.StringField(), default=list)
    
    # Filtering
    certificate_types = fields.ListField(fields.StringField(), default=list)
    hostnames = fields.ListField(fields.StringField(), default=list)
    
    # Webhook Configuration
    webhook_url = fields.URLField()
    webhook_headers = fields.DictField(default=dict)
    webhook_payload_template = fields.StringField()
    
    # Status
    is_active = fields.BooleanField(default=True)
    created_by = fields.ReferenceField(User, required=True)
    created_at = fields.DateTimeField(default=datetime.utcnow)
    updated_at = fields.DateTimeField(default=datetime.utcnow)
    
    meta = {
        'collection': 'notification_rules',
        'indexes': ['created_by', 'event_type', 'is_active'],
        'ordering': ['name']
    }
    
    def __str__(self):
        return f"{self.name} - {self.event_type}"


class CertificateRequest(Document):
    """Model to track certificate generation requests"""
    
    REQUEST_STATUS = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed')
    ]
    
    id = fields.UUIDField(primary_key=True, default=uuid.uuid4)
    certificate = fields.ReferenceField(Certificate)
    requested_by = fields.ReferenceField(User, required=True)
    
    # Request details
    hostname = fields.StringField(required=True, max_length=255)
    email = fields.EmailField()
    validity_period = fields.StringField(max_length=20)
    step_ca_service = fields.StringField(max_length=255)
    
    # Request tracking
    status = fields.StringField(choices=REQUEST_STATUS, default='pending', max_length=20)
    created_at = fields.DateTimeField(default=datetime.utcnow)
    completed_at = fields.DateTimeField()
    
    # Error tracking
    error_message = fields.StringField()
    
    meta = {
        'collection': 'certificate_requests',
        'indexes': ['requested_by', 'status', 'created_at'],
        'ordering': ['-created_at']
    }
    
    def __str__(self):
        return f"Certificate request for {self.hostname} by {self.requested_by.email}"


class StepCAService(Document):
    """Model to manage Step-CA service configurations"""
    
    id = fields.UUIDField(primary_key=True, default=uuid.uuid4)
    name = fields.StringField(required=True, unique=True, max_length=100)
    url = fields.StringField(required=True, max_length=255)
    ca_url = fields.StringField(required=True, max_length=255)
    
    # Authentication
    ca_fingerprint = fields.StringField(max_length=100)
    root_cert_path = fields.StringField(max_length=500)
    
    # Service status
    is_active = fields.BooleanField(default=True)
    last_health_check = fields.DateTimeField()
    health_status = fields.StringField(default='unknown', max_length=50)
    
    # Configuration
    default_validity = fields.StringField(default='1-year', max_length=20)
    max_validity = fields.StringField(default='5-years', max_length=20)
    
    created_at = fields.DateTimeField(default=datetime.utcnow)
    updated_at = fields.DateTimeField(default=datetime.utcnow)
    
    meta = {
        'collection': 'step_ca_services',
        'indexes': ['name', 'is_active']
    }
    
    def __str__(self):
        return f"{self.name} ({self.url})"
