from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
import uuid

User = get_user_model()

class Certificate(models.Model):
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
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    hostname = models.CharField(max_length=255, help_text="Hostname or IP address")
    certificate_type = models.CharField(max_length=20, choices=CERTIFICATE_TYPES, default='step_ca')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Certificate Details
    key_size = models.CharField(max_length=10, choices=KEY_SIZES, default='2048')
    key_type = models.CharField(max_length=10, choices=KEY_TYPES, default='RSA')
    validity_period = models.CharField(max_length=20, default='1-year')
    
    # CSR Information
    csr_content = models.TextField(blank=True, null=True, help_text="Certificate Signing Request in PEM format")
    subject_alternative_names = models.JSONField(default=list, blank=True, help_text="List of SAN entries")
    
    # Extended Certificate Information
    serial_number = models.CharField(max_length=100, blank=True, null=True)
    fingerprint_sha256 = models.CharField(max_length=100, blank=True, null=True)
    common_name = models.CharField(max_length=255, blank=True, null=True)
    organization = models.CharField(max_length=255, blank=True, null=True)
    organizational_unit = models.CharField(max_length=255, blank=True, null=True)
    country = models.CharField(max_length=2, blank=True, null=True)
    state = models.CharField(max_length=255, blank=True, null=True)
    locality = models.CharField(max_length=255, blank=True, null=True)
    
    # Deployment Information
    deployment_targets = models.JSONField(default=list, blank=True, help_text="List of deployment targets")
    deployment_status = models.CharField(max_length=50, blank=True, null=True)
    last_deployment_date = models.DateTimeField(blank=True, null=True)
    
    # Renewal Information
    auto_renewal = models.BooleanField(default=False)
    renewal_threshold_days = models.IntegerField(default=30, help_text="Days before expiry to trigger renewal")
    previous_certificate = models.ForeignKey('self', on_delete=models.SET_NULL, blank=True, null=True, related_name='renewed_certificates')
    
    # Dates
    issued_date = models.DateTimeField(null=True, blank=True)
    expiry_date = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # User and Service Information
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='certificates')
    issuer = models.CharField(max_length=255, default='Step-CA Service')
    step_ca_service = models.CharField(max_length=255, default='localhost:9000')
    email = models.EmailField(blank=True, null=True, help_text="Optional email for certificate notifications")
    
    # Certificate Content
    certificate_content = models.TextField(blank=True, null=True, help_text="PEM formatted certificate")
    private_key = models.TextField(blank=True, null=True, help_text="PEM formatted private key")
    certificate_chain = models.TextField(blank=True, null=True, help_text="Certificate chain if applicable")
    
    # Step-CA specific fields
    step_ca_token = models.CharField(max_length=500, blank=True, null=True)
    step_ca_fingerprint = models.CharField(max_length=100, blank=True, null=True)
    
    # Validation and Monitoring
    last_validation_check = models.DateTimeField(null=True, blank=True)
    validation_status = models.CharField(max_length=50, blank=True, null=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['hostname']),
            models.Index(fields=['status']),
            models.Index(fields=['expiry_date']),
            models.Index(fields=['created_by']),
        ]
    
    def __str__(self):
        return f"{self.hostname} - {self.get_certificate_type_display()}"
    
    @property
    def is_expired(self):
        """Check if certificate is expired"""
        if self.expiry_date:
            now = timezone.now()
            expiry = self.expiry_date
            
            # Handle timezone-naive datetime
            if timezone.is_naive(expiry):
                expiry = timezone.make_aware(expiry)
            
            return now > expiry
        return False
    
    @property
    def days_until_expiry(self):
        """Get number of days until expiry"""
        if self.expiry_date:
            now = timezone.now()
            expiry = self.expiry_date
            
            # Handle timezone-naive datetime
            if timezone.is_naive(expiry):
                expiry = timezone.make_aware(expiry)
            
            delta = expiry - now
            return delta.days
        return None
    
    @property
    def is_expiring_soon(self):
        """Check if certificate expires within 30 days"""
        days = self.days_until_expiry
        return days is not None and days <= 30
    
    def save(self, *args, **kwargs):
        # Auto-update status based on expiry
        if self.is_expired and self.status == 'active':
            self.status = 'expired'
        super().save(*args, **kwargs)


class CertificateRequest(models.Model):
    """Model to track certificate generation requests"""
    REQUEST_STATUS = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed')
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    certificate = models.OneToOneField(Certificate, on_delete=models.CASCADE, null=True, blank=True)
    requested_by = models.ForeignKey(User, on_delete=models.CASCADE)
    
    # Request details
    hostname = models.CharField(max_length=255)
    email = models.EmailField(blank=True, null=True)
    validity_period = models.CharField(max_length=20)
    step_ca_service = models.CharField(max_length=255)
    
    # Request tracking
    status = models.CharField(max_length=20, choices=REQUEST_STATUS, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Error tracking
    error_message = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return f"Certificate request for {self.hostname} by {self.requested_by.email}"


class CSRTemplate(models.Model):
    """Template for Certificate Signing Requests"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    
    # Subject Information
    country = models.CharField(max_length=2, default='US')
    state = models.CharField(max_length=255, default='')
    locality = models.CharField(max_length=255, default='')
    organization = models.CharField(max_length=255, default='')
    organizational_unit = models.CharField(max_length=255, default='IT Department')
    
    # Key Configuration
    key_type = models.CharField(max_length=10, choices=Certificate.KEY_TYPES, default='RSA')
    key_size = models.CharField(max_length=10, choices=Certificate.KEY_SIZES, default='2048')
    
    # Default validity
    default_validity = models.CharField(max_length=20, default='1-year')
    
    # Template settings
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"CSR Template: {self.name}"
    
    class Meta:
        ordering = ['name']


class CertificateSigningRequest(models.Model):
    """Model to track Certificate Signing Requests"""
    STATUS_CHOICES = [
        ('pending', 'Pending Review'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('completed', 'Completed'),
        ('expired', 'Expired'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    certificate = models.OneToOneField(Certificate, on_delete=models.CASCADE, null=True, blank=True, related_name='csr')
    
    # CSR Content
    csr_content = models.TextField(help_text="Certificate Signing Request in PEM format")
    private_key = models.TextField(blank=True, null=True, help_text="Associated private key (optional)")
    
    # Request Details
    common_name = models.CharField(max_length=255)
    subject_alternative_names = models.JSONField(default=list, blank=True)
    organization = models.CharField(max_length=255, blank=True)
    organizational_unit = models.CharField(max_length=255, blank=True)
    country = models.CharField(max_length=2, blank=True)
    state = models.CharField(max_length=255, blank=True)
    locality = models.CharField(max_length=255, blank=True)
    email = models.EmailField(blank=True, null=True)
    
    # Key Information
    key_type = models.CharField(max_length=10, default='RSA')
    key_size = models.CharField(max_length=10, default='2048')
    
    # Request Management
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    requested_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='csr_requests')
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_csrs')
    
    # Validity
    requested_validity = models.CharField(max_length=20, default='1-year')
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Additional Information
    justification = models.TextField(blank=True, help_text="Reason for certificate request")
    rejection_reason = models.TextField(blank=True)
    
    def __str__(self):
        return f"CSR for {self.common_name} by {self.requested_by.email}"
    
    class Meta:
        ordering = ['-created_at']


class DeploymentTarget(models.Model):
    """Model to define certificate deployment targets"""
    TARGET_TYPES = [
        ('ssh', 'SSH Server'),
        ('api', 'API Endpoint'),
        ('webhook', 'Webhook'),
        ('manual', 'Manual Download'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    target_type = models.CharField(max_length=20, choices=TARGET_TYPES)
    
    # Connection Information
    hostname = models.CharField(max_length=255)
    port = models.IntegerField(default=22)
    username = models.CharField(max_length=100, blank=True)
    
    # SSH Configuration
    ssh_key_path = models.CharField(max_length=500, blank=True, help_text="Path to SSH private key")
    remote_cert_path = models.CharField(max_length=500, blank=True, help_text="Remote path for certificate")
    remote_key_path = models.CharField(max_length=500, blank=True, help_text="Remote path for private key")
    post_deploy_command = models.TextField(blank=True, help_text="Command to run after deployment")
    
    # API Configuration
    api_endpoint = models.URLField(blank=True)
    api_token = models.CharField(max_length=500, blank=True)
    api_headers = models.JSONField(default=dict, blank=True)
    
    # Status
    is_active = models.BooleanField(default=True)
    last_deployment = models.DateTimeField(null=True, blank=True)
    last_deployment_status = models.CharField(max_length=50, blank=True)
    
    # Management
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.name} ({self.get_target_type_display()})"
    
    class Meta:
        unique_together = ['name', 'created_by']


class CertificateDeployment(models.Model):
    """Model to track certificate deployments"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    certificate = models.ForeignKey(Certificate, on_delete=models.CASCADE, related_name='deployments')
    target = models.ForeignKey(DeploymentTarget, on_delete=models.CASCADE)
    
    # Deployment Details
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Execution Information
    initiated_by = models.ForeignKey(User, on_delete=models.CASCADE)
    deployment_log = models.TextField(blank=True)
    error_message = models.TextField(blank=True)
    
    # Configuration
    backup_existing = models.BooleanField(default=True)
    restart_services = models.BooleanField(default=False)
    services_to_restart = models.JSONField(default=list, blank=True)
    
    def __str__(self):
        return f"Deployment of {self.certificate.hostname} to {self.target.name}"
    
    class Meta:
        ordering = ['-started_at']


class NotificationRule(models.Model):
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
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    
    # Rule Configuration
    event_type = models.CharField(max_length=30, choices=EVENT_TYPES)
    notification_method = models.CharField(max_length=20, choices=NOTIFICATION_METHODS)
    
    # Recipients
    recipients = models.JSONField(default=list, help_text="List of email addresses or webhook URLs")
    
    # Filtering
    certificate_types = models.JSONField(default=list, blank=True, help_text="Filter by certificate types")
    hostnames = models.JSONField(default=list, blank=True, help_text="Filter by hostnames")
    
    # Webhook Configuration
    webhook_url = models.URLField(blank=True)
    webhook_headers = models.JSONField(default=dict, blank=True)
    webhook_payload_template = models.TextField(blank=True)
    
    # Status
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.name} - {self.get_event_type_display()}"
    
    class Meta:
        ordering = ['name']


class StepCAService(models.Model):
    """Model to manage Step-CA service configurations"""
    name = models.CharField(max_length=100, unique=True)
    url = models.CharField(max_length=255, help_text="Step-CA service URL (e.g., localhost:9000)")
    ca_url = models.CharField(max_length=255, help_text="CA URL for certificate operations")
    
    # Authentication
    ca_fingerprint = models.CharField(max_length=100, blank=True, null=True)
    root_cert_path = models.CharField(max_length=500, blank=True, null=True)
    
    # Service status
    is_active = models.BooleanField(default=True)
    last_health_check = models.DateTimeField(null=True, blank=True)
    health_status = models.CharField(max_length=50, default='unknown')
    
    # Configuration
    default_validity = models.CharField(max_length=20, default='1-year')
    max_validity = models.CharField(max_length=20, default='5-years')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.name} ({self.url})"
    
    class Meta:
        verbose_name = "Step-CA Service"
        verbose_name_plural = "Step-CA Services"
