from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from .models import Certificate, CertificateRequest, StepCAService


@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    list_display = [
        'hostname', 'certificate_type', 'status', 'created_by_email',
        'issued_date', 'expiry_date', 'days_until_expiry_display', 'created_at'
    ]
    list_filter = [
        'certificate_type', 'status', 'created_at', 'issued_date',
        'expiry_date', 'key_size'
    ]
    search_fields = ['hostname', 'created_by__email', 'issuer']
    readonly_fields = [
        'id', 'created_at', 'updated_at', 'days_until_expiry',
        'is_expired', 'is_expiring_soon'
    ]
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('id', 'hostname', 'certificate_type', 'status', 'created_by')
        }),
        ('Certificate Details', {
            'fields': ('key_size', 'validity_period', 'issuer', 'email')
        }),
        ('Dates', {
            'fields': ('issued_date', 'expiry_date', 'created_at', 'updated_at')
        }),
        ('Step-CA Configuration', {
            'fields': ('step_ca_service', 'step_ca_token', 'step_ca_fingerprint'),
            'classes': ('collapse',)
        }),
        ('Certificate Content', {
            'fields': ('certificate_content', 'private_key', 'certificate_chain'),
            'classes': ('collapse',)
        }),
        ('Validation', {
            'fields': ('last_validation_check', 'validation_status'),
            'classes': ('collapse',)
        }),
        ('Computed Fields', {
            'fields': ('days_until_expiry', 'is_expired', 'is_expiring_soon'),
            'classes': ('collapse',)
        })
    )
    
    def created_by_email(self, obj):
        return obj.created_by.email
    created_by_email.short_description = 'Created By'
    created_by_email.admin_order_field = 'created_by__email'
    
    def days_until_expiry_display(self, obj):
        days = obj.days_until_expiry
        if days is None:
            return '-'
        
        if days < 0:
            return format_html('<span style="color: red;">Expired ({} days ago)</span>', abs(days))
        elif days <= 30:
            return format_html('<span style="color: orange;">{} days</span>', days)
        else:
            return format_html('{} days', days)
    
    days_until_expiry_display.short_description = 'Days Until Expiry'
    days_until_expiry_display.admin_order_field = 'expiry_date'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('created_by')


@admin.register(CertificateRequest)
class CertificateRequestAdmin(admin.ModelAdmin):
    list_display = [
        'hostname', 'requested_by_email', 'status', 'created_at',
        'completed_at', 'certificate_link'
    ]
    list_filter = ['status', 'created_at', 'completed_at']
    search_fields = ['hostname', 'requested_by__email', 'step_ca_service']
    readonly_fields = ['id', 'created_at', 'completed_at']
    
    fieldsets = (
        ('Request Information', {
            'fields': ('id', 'hostname', 'email', 'requested_by')
        }),
        ('Configuration', {
            'fields': ('validity_period', 'step_ca_service')
        }),
        ('Status', {
            'fields': ('status', 'created_at', 'completed_at', 'error_message')
        }),
        ('Certificate', {
            'fields': ('certificate',)
        })
    )
    
    def requested_by_email(self, obj):
        return obj.requested_by.email
    requested_by_email.short_description = 'Requested By'
    requested_by_email.admin_order_field = 'requested_by__email'
    
    def certificate_link(self, obj):
        if obj.certificate:
            url = reverse('admin:certificates_certificate_change', args=[obj.certificate.id])
            return format_html('<a href="{}">View Certificate</a>', url)
        return '-'
    certificate_link.short_description = 'Certificate'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('requested_by', 'certificate')


@admin.register(StepCAService)
class StepCAServiceAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'url', 'is_active', 'health_status',
        'last_health_check', 'created_at'
    ]
    list_filter = ['is_active', 'health_status', 'created_at', 'last_health_check']
    search_fields = ['name', 'url', 'ca_url']
    readonly_fields = ['created_at', 'updated_at', 'last_health_check', 'health_status']
    
    fieldsets = (
        ('Service Information', {
            'fields': ('name', 'url', 'ca_url', 'is_active')
        }),
        ('Authentication', {
            'fields': ('ca_fingerprint', 'root_cert_path'),
            'classes': ('collapse',)
        }),
        ('Configuration', {
            'fields': ('default_validity', 'max_validity')
        }),
        ('Health Status', {
            'fields': ('health_status', 'last_health_check'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    actions = ['check_health']
    
    def check_health(self, request, queryset):
        """Admin action to check health of selected services"""
        from .step_ca_service import get_step_ca_service
        from django.utils import timezone
        
        for service in queryset:
            try:
                step_ca = get_step_ca_service(service.ca_url)
                health_info = step_ca.get_ca_info()
                
                service.health_status = health_info['status']
                service.last_health_check = timezone.now()
                service.save()
                
                self.message_user(request, f'Health check completed for {service.name}: {health_info["status"]}')
            
            except Exception as e:
                service.health_status = 'error'
                service.last_health_check = timezone.now()
                service.save()
                
                self.message_user(request, f'Health check failed for {service.name}: {str(e)}', level='error')
    
    check_health.short_description = 'Check health of selected services'


# Admin site customization
admin.site.site_header = 'Certificate Management Administration'
admin.site.site_title = 'Certificate Management'
admin.site.index_title = 'Certificate Management Administration'
