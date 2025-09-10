from rest_framework import serializers
from .models import Certificate, CertificateRequest, StepCAService
from django.contrib.auth import get_user_model

User = get_user_model()


class CertificateSerializer(serializers.ModelSerializer):
    created_by_email = serializers.CharField(source='created_by.email', read_only=True)
    days_until_expiry = serializers.IntegerField(read_only=True)
    is_expired = serializers.BooleanField(read_only=True)
    is_expiring_soon = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = Certificate
        fields = [
            'id', 'hostname', 'certificate_type', 'status', 'key_size',
            'validity_period', 'issued_date', 'expiry_date', 'created_at',
            'updated_at', 'created_by_email', 'issuer', 'step_ca_service',
            'email', 'days_until_expiry', 'is_expired', 'is_expiring_soon',
            'last_validation_check', 'validation_status'
        ]
        read_only_fields = [
            'id', 'created_at', 'updated_at', 'created_by_email',
            'issued_date', 'expiry_date', 'days_until_expiry',
            'is_expired', 'is_expiring_soon', 'last_validation_check',
            'validation_status'
        ]


class CertificateDetailSerializer(CertificateSerializer):
    """Detailed serializer including certificate content for authorized users"""
    certificate_content = serializers.CharField(read_only=True)
    certificate_chain = serializers.CharField(read_only=True)
    
    class Meta(CertificateSerializer.Meta):
        fields = CertificateSerializer.Meta.fields + [
            'certificate_content', 'certificate_chain', 'step_ca_token',
            'step_ca_fingerprint'
        ]


class CertificateCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new certificate requests"""
    
    class Meta:
        model = Certificate
        fields = [
            'hostname', 'certificate_type', 'key_size', 'validity_period',
            'step_ca_service', 'email'
        ]
    
    def validate_hostname(self, value):
        """Validate hostname format"""
        import re
        
        # IP address pattern
        ip_pattern = r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
        
        # Domain name pattern
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        
        # Localhost pattern
        if value.lower() == 'localhost':
            return value
        
        if not (re.match(ip_pattern, value) or re.match(domain_pattern, value)):
            raise serializers.ValidationError(
                "Please enter a valid IP address, domain name, or localhost"
            )
        
        return value
    
    def validate_email(self, value):
        """Validate email format if provided"""
        if value and value.strip():
            import re
            email_pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
            if not re.match(email_pattern, value):
                raise serializers.ValidationError("Please enter a valid email address")
        return value
    
    def create(self, validated_data):
        """Create certificate with current user"""
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)


class CertificateRequestSerializer(serializers.ModelSerializer):
    requested_by_email = serializers.CharField(source='requested_by.email', read_only=True)
    certificate_id = serializers.UUIDField(source='certificate.id', read_only=True)
    
    class Meta:
        model = CertificateRequest
        fields = [
            'id', 'hostname', 'email', 'validity_period', 'step_ca_service',
            'status', 'created_at', 'completed_at', 'error_message',
            'requested_by_email', 'certificate_id'
        ]
        read_only_fields = [
            'id', 'created_at', 'completed_at', 'requested_by_email',
            'certificate_id', 'status', 'error_message'
        ]


class StepCAServiceSerializer(serializers.ModelSerializer):
    """Serializer for Step-CA service configuration"""
    
    class Meta:
        model = StepCAService
        fields = [
            'id', 'name', 'url', 'ca_url', 'ca_fingerprint',
            'is_active', 'last_health_check', 'health_status',
            'default_validity', 'max_validity', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'created_at', 'updated_at', 'last_health_check',
            'health_status'
        ]


class CertificateValidationSerializer(serializers.Serializer):
    """Serializer for certificate validation requests"""
    hostname = serializers.CharField(max_length=255)
    port = serializers.IntegerField(default=443, min_value=1, max_value=65535)
    
    def validate_hostname(self, value):
        """Validate hostname format"""
        import re
        
        # IP address pattern
        ip_pattern = r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
        
        # Domain name pattern
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        
        # Localhost pattern
        if value.lower() == 'localhost':
            return value
        
        if not (re.match(ip_pattern, value) or re.match(domain_pattern, value)):
            raise serializers.ValidationError(
                "Please enter a valid IP address, domain name, or localhost"
            )
        
        return value


class CertificateDownloadSerializer(serializers.Serializer):
    """Serializer for certificate download requests"""
    format = serializers.ChoiceField(
        choices=[
            ('pem', 'PEM'),
            ('der', 'DER'),
            ('p12', 'PKCS#12'),
            ('jks', 'Java KeyStore')
        ],
        default='pem'
    )
    include_private_key = serializers.BooleanField(default=False)
    include_chain = serializers.BooleanField(default=True)
    password = serializers.CharField(required=False, allow_blank=True)
    
    def validate(self, data):
        """Validate download parameters"""
        if data['format'] in ['p12', 'jks'] and not data.get('password'):
            raise serializers.ValidationError({
                'password': 'Password is required for PKCS#12 and JKS formats'
            })
        return data
