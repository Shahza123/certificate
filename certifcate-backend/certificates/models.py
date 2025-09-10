from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
import uuid

User = get_user_model()

class Certificate(models.Model):
    CERTIFICATE_TYPES = [
        ('self_signed', 'Self-Signed'),
        ('ca_signed', 'CA-Signed'),
        ('step_ca', 'Step-CA')
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('revoked', 'Revoked'),
        ('pending', 'Pending')
    ]
    
    KEY_SIZES = [
        ('2048', '2048'),
        ('4096', '4096'),
        ('8192', '8192')
    ]
    
    # Basic Information
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    hostname = models.CharField(max_length=255, help_text="Hostname or IP address")
    certificate_type = models.CharField(max_length=20, choices=CERTIFICATE_TYPES, default='step_ca')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Certificate Details
    key_size = models.CharField(max_length=10, choices=KEY_SIZES, default='2048')
    validity_period = models.CharField(max_length=20, default='1-year')
    
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
