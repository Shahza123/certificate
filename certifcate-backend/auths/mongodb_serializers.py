"""
MongoDB Serializers for Authentication

Custom serializers that work with MongoEngine models instead of Django ORM.
"""

from rest_framework import serializers
from auths.mongodb_models import User as MongoUser, UserManager


class MongoUserRegistrationSerializer(serializers.Serializer):
    """
    MongoDB User Registration Serializer
    """
    email = serializers.EmailField(max_length=255)
    first_name = serializers.CharField(max_length=100)
    last_name = serializers.CharField(max_length=100)
    password = serializers.CharField(write_only=True, min_length=6)
    password2 = serializers.CharField(write_only=True, min_length=6)
    role = serializers.ChoiceField(
        choices=[('admin', 'Admin'), ('certificate_manager', 'Certificate Manager'), ('regular_user', 'Regular User')],
        default='regular_user',
        required=False
    )
    
    def validate_email(self, value):
        """Check if email already exists in MongoDB"""
        if MongoUser.objects(email=value).first():
            raise serializers.ValidationError("A user with this email already exists.")
        return value
    
    def validate(self, attrs):
        """Validate that passwords match"""
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError("Passwords don't match.")
        return attrs
    
    def create(self, validated_data):
        """Create user in MongoDB"""
        validated_data.pop('password2', None)  # Remove password2
        
        user = UserManager.create_user(
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            password=validated_data['password'],
            role=validated_data.get('role', 'regular_user')
        )
        return user


class MongoUserLoginSerializer(serializers.Serializer):
    """
    MongoDB User Login Serializer
    """
    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(write_only=True)


class MongoUserProfileSerializer(serializers.Serializer):
    """
    MongoDB User Profile Serializer
    """
    id = serializers.CharField(read_only=True)
    email = serializers.EmailField(read_only=True)
    first_name = serializers.CharField(max_length=100)
    last_name = serializers.CharField(max_length=100)
    role = serializers.CharField(read_only=True)
    department = serializers.CharField(max_length=100, allow_blank=True, required=False)
    phone_number = serializers.CharField(max_length=20, allow_blank=True, required=False)
    two_factor_enabled = serializers.BooleanField(read_only=True)
    is_active = serializers.BooleanField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)
    
    def update(self, instance, validated_data):
        """Update MongoDB user"""
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


class MongoUserListSerializer(serializers.Serializer):
    """
    Serializer for listing MongoDB users
    """
    id = serializers.CharField(read_only=True)
    email = serializers.EmailField(read_only=True)
    first_name = serializers.CharField(read_only=True)
    last_name = serializers.CharField(read_only=True)
    role = serializers.CharField(read_only=True)
    department = serializers.CharField(read_only=True)
    is_active = serializers.BooleanField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)
    last_login = serializers.DateTimeField(read_only=True)
