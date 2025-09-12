from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import (
    Certificate, CertificateRequest, StepCAService, CSRTemplate,
    CertificateSigningRequest, DeploymentTarget, CertificateDeployment,
    NotificationRule
)

User = get_user_model()


class UserBasicSerializer(serializers.ModelSerializer):
    """Basic user information for serialization"""
    full_name = serializers.ReadOnlyField()
    
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'full_name', 'role']


class CSRTemplateSerializer(serializers.ModelSerializer):
    """Serializer for CSR Templates"""
    created_by = UserBasicSerializer(read_only=True)
    
    class Meta:
        model = CSRTemplate
        fields = '__all__'
        read_only_fields = ['created_by', 'created_at', 'updated_at']


class CertificateSigningRequestSerializer(serializers.ModelSerializer):
    """Serializer for Certificate Signing Requests"""
    requested_by = UserBasicSerializer(read_only=True)
    approved_by = UserBasicSerializer(read_only=True)
    certificate_id = serializers.UUIDField(source='certificate.id', read_only=True)
    
    class Meta:
        model = CertificateSigningRequest
        fields = '__all__'
        read_only_fields = ['requested_by', 'approved_by', 'approved_at', 'completed_at']


class CertificateSigningRequestCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating CSR"""
    
    class Meta:
        model = CertificateSigningRequest
        fields = [
            'csr_content', 'private_key', 'common_name', 'subject_alternative_names',
            'organization', 'organizational_unit', 'country', 'state', 'locality',
            'email', 'key_type', 'key_size', 'requested_validity', 'justification'
        ]
    
    def create(self, validated_data):
        validated_data['requested_by'] = self.context['request'].user
        return super().create(validated_data)


class DeploymentTargetSerializer(serializers.ModelSerializer):
    """Serializer for Deployment Targets"""
    created_by = UserBasicSerializer(read_only=True)
    
    class Meta:
        model = DeploymentTarget
        fields = '__all__'
        read_only_fields = ['created_by', 'created_at', 'updated_at', 'last_deployment', 'last_deployment_status']
        extra_kwargs = {
            'ssh_key_path': {'write_only': True},
            'api_token': {'write_only': True},
        }


class CertificateDeploymentSerializer(serializers.ModelSerializer):
    """Serializer for Certificate Deployments"""
    initiated_by = UserBasicSerializer(read_only=True)
    target = DeploymentTargetSerializer(read_only=True)
    certificate_hostname = serializers.CharField(source='certificate.hostname', read_only=True)
    
    class Meta:
        model = CertificateDeployment
        fields = '__all__'
        read_only_fields = ['initiated_by', 'started_at', 'completed_at', 'deployment_log', 'error_message']


class NotificationRuleSerializer(serializers.ModelSerializer):
    """Serializer for Notification Rules"""
    created_by = UserBasicSerializer(read_only=True)
    
    class Meta:
        model = NotificationRule
        fields = '__all__'
        read_only_fields = ['created_by', 'created_at', 'updated_at']


class CertificateSerializer(serializers.ModelSerializer):
    """Basic Certificate serializer for list views"""
    created_by = UserBasicSerializer(read_only=True)
    is_expired = serializers.ReadOnlyField()
    days_until_expiry = serializers.ReadOnlyField()
    is_expiring_soon = serializers.ReadOnlyField()
    
    class Meta:
        model = Certificate
        fields = [
            'id', 'hostname', 'certificate_type', 'status', 'key_size', 'key_type',
            'validity_period', 'common_name', 'organization', 'issued_date', 'expiry_date',
            'created_at', 'updated_at', 'created_by', 'is_expired', 'days_until_expiry',
            'is_expiring_soon', 'auto_renewal', 'deployment_status'
        ]


class CertificateDetailSerializer(serializers.ModelSerializer):
    """Detailed Certificate serializer"""
    created_by = UserBasicSerializer(read_only=True)
    is_expired = serializers.ReadOnlyField()
    days_until_expiry = serializers.ReadOnlyField()
    is_expiring_soon = serializers.ReadOnlyField()
    csr = CertificateSigningRequestSerializer(read_only=True)
    deployments = CertificateDeploymentSerializer(many=True, read_only=True)
    previous_certificate = serializers.SlugRelatedField(
        slug_field='hostname', read_only=True
    )
    renewed_certificates = CertificateSerializer(many=True, read_only=True)
    
    class Meta:
        model = Certificate
        fields = '__all__'
        read_only_fields = [
            'created_by', 'issued_date', 'created_at', 'updated_at',
            'certificate_content', 'private_key', 'certificate_chain',
            'serial_number', 'fingerprint_sha256', 'last_deployment_date'
        ]


class CertificateCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating certificates"""
    
    class Meta:
        model = Certificate
        fields = [
            'hostname', 'certificate_type', 'key_size', 'key_type', 'validity_period',
            'email', 'common_name', 'organization', 'organizational_unit',
            'country', 'state', 'locality', 'subject_alternative_names',
            'auto_renewal', 'renewal_threshold_days', 'step_ca_service'
        ]
    
    def create(self, validated_data):
        validated_data['created_by'] = self.context['request'].user
        # Set common_name to hostname if not provided
        if not validated_data.get('common_name'):
            validated_data['common_name'] = validated_data['hostname']
        return super().create(validated_data)


class CertificateRenewalSerializer(serializers.Serializer):
    """Serializer for certificate renewal requests"""
    validity_period = serializers.CharField(max_length=20, required=False)
    auto_renewal = serializers.BooleanField(required=False)
    renewal_threshold_days = serializers.IntegerField(min_value=1, max_value=365, required=False)


class CertificateRevocationSerializer(serializers.Serializer):
    """Serializer for certificate revocation"""
    reason = serializers.ChoiceField(
        choices=[
            ('unspecified', 'Unspecified'),
            ('key_compromise', 'Key Compromise'),
            ('ca_compromise', 'CA Compromise'),
            ('affiliation_changed', 'Affiliation Changed'),
            ('superseded', 'Superseded'),
            ('cessation_of_operation', 'Cessation of Operation'),
            ('certificate_hold', 'Certificate Hold'),
            ('privilege_withdrawn', 'Privilege Withdrawn'),
            ('aa_compromise', 'AA Compromise'),
        ],
        default='unspecified'
    )


class CertificateValidationSerializer(serializers.Serializer):
    """Serializer for certificate validation requests"""
    hostname = serializers.CharField(max_length=255)
    port = serializers.IntegerField(min_value=1, max_value=65535, default=443)


class CertificateDownloadSerializer(serializers.Serializer):
    """Serializer for certificate download requests"""
    format = serializers.ChoiceField(
        choices=[('pem', 'PEM'), ('der', 'DER'), ('p12', 'PKCS#12'), ('jks', 'Java KeyStore')],
        default='pem'
    )
    include_private_key = serializers.BooleanField(default=False)
    include_chain = serializers.BooleanField(default=False)
    password = serializers.CharField(max_length=100, required=False, allow_blank=True)


class CertificateDeploymentCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating certificate deployments"""
    target_id = serializers.UUIDField(write_only=True)
    
    class Meta:
        model = CertificateDeployment
        fields = [
            'target_id', 'backup_existing', 'restart_services', 'services_to_restart'
        ]
    
    def create(self, validated_data):
        target_id = validated_data.pop('target_id')
        target = DeploymentTarget.objects.get(
            id=target_id,
            created_by=self.context['request'].user
        )
        validated_data['target'] = target
        validated_data['initiated_by'] = self.context['request'].user
        return super().create(validated_data)


class CSRGenerationSerializer(serializers.Serializer):
    """Serializer for generating CSR"""
    common_name = serializers.CharField(max_length=255)
    organization = serializers.CharField(max_length=255, required=False, allow_blank=True)
    organizational_unit = serializers.CharField(max_length=255, required=False, allow_blank=True)
    country = serializers.CharField(max_length=2, required=False, allow_blank=True)
    state = serializers.CharField(max_length=255, required=False, allow_blank=True)
    locality = serializers.CharField(max_length=255, required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    subject_alternative_names = serializers.ListField(
        child=serializers.CharField(max_length=255),
        required=False,
        allow_empty=True
    )
    key_type = serializers.ChoiceField(
        choices=[('RSA', 'RSA'), ('ECDSA', 'ECDSA'), ('Ed25519', 'Ed25519')],
        default='RSA'
    )
    key_size = serializers.ChoiceField(
        choices=[('2048', '2048'), ('4096', '4096'), ('8192', '8192')],
        default='2048'
    )


class CertificateRequestSerializer(serializers.ModelSerializer):
    """Serializer for Certificate Requests"""
    requested_by = UserBasicSerializer(read_only=True)
    certificate = CertificateSerializer(read_only=True)
    
    class Meta:
        model = CertificateRequest
        fields = '__all__'
        read_only_fields = ['requested_by', 'created_at', 'completed_at']


class StepCAServiceSerializer(serializers.ModelSerializer):
    """Serializer for Step-CA Services"""
    
    class Meta:
        model = StepCAService
        fields = '__all__'
        read_only_fields = ['created_at', 'updated_at', 'last_health_check', 'health_status']


class CertificateStatisticsSerializer(serializers.Serializer):
    """Serializer for certificate statistics"""
    total_certificates = serializers.IntegerField()
    active_certificates = serializers.IntegerField()
    expired_certificates = serializers.IntegerField()
    revoked_certificates = serializers.IntegerField()
    expiring_soon = serializers.IntegerField()
    certificate_types = serializers.DictField()
    deployment_statistics = serializers.DictField()
    monthly_issuance = serializers.ListField()
    top_hostnames = serializers.ListField()


class ACMEAccountSerializer(serializers.Serializer):
    """Serializer for ACME account operations"""
    email = serializers.EmailField()
    terms_of_service_agreed = serializers.BooleanField(default=False)


class ACMEOrderSerializer(serializers.Serializer):
    """Serializer for ACME order operations"""
    identifiers = serializers.ListField(
        child=serializers.CharField(max_length=255),
        min_length=1
    )
    not_before = serializers.DateTimeField(required=False)
    not_after = serializers.DateTimeField(required=False)