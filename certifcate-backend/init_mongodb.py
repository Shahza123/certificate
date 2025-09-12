#!/usr/bin/env python
"""
MongoDB Initialization Script for WCAMAN

This script initializes the MongoDB database with sample data and creates initial users.
"""

import os
import sys
import django
from datetime import datetime

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

# Import MongoDB models
from auths.mongodb_models import User, UserManager, AuditLog
from certificates.mongodb_models import (
    Certificate, CSRTemplate, StepCAService, NotificationRule
)

def create_initial_users():
    """Create initial admin and test users"""
    print("🔧 Creating initial users...")
    
    # Create admin user
    admin_email = "admin@wcaman.local"
    if not User.objects(email=admin_email).first():
        admin = UserManager.create_superuser(
            email=admin_email,
            first_name="System",
            last_name="Administrator",
            password="admin123"
        )
        print(f"✅ Created admin user: {admin.email}")
    else:
        print(f"ℹ️  Admin user already exists: {admin_email}")
    
    # Create certificate manager
    manager_email = "manager@wcaman.local"
    if not User.objects(email=manager_email).first():
        manager = UserManager.create_user(
            email=manager_email,
            first_name="Certificate",
            last_name="Manager",
            password="manager123",
            role="certificate_manager"
        )
        print(f"✅ Created certificate manager: {manager.email}")
    else:
        print(f"ℹ️  Certificate manager already exists: {manager_email}")
    
    # Create regular user
    user_email = "user@wcaman.local"
    if not User.objects(email=user_email).first():
        user = UserManager.create_user(
            email=user_email,
            first_name="Regular",
            last_name="User",
            password="user123",
            role="regular_user"
        )
        print(f"✅ Created regular user: {user.email}")
    else:
        print(f"ℹ️  Regular user already exists: {user_email}")


def create_initial_csr_templates():
    """Create initial CSR templates"""
    print("📋 Creating initial CSR templates...")
    
    admin = User.objects(email="admin@wcaman.local").first()
    if not admin:
        print("❌ Admin user not found. Run create_initial_users first.")
        return
    
    templates = [
        {
            'name': 'Standard Web Server',
            'description': 'Standard template for web server certificates',
            'organization': 'WCAMAN Certificate Authority',
            'organizational_unit': 'IT Department',
            'country': 'US',
            'state': 'California',
            'locality': 'San Francisco',
            'key_type': 'RSA',
            'key_size': '2048',
            'default_validity': '1-year'
        },
        {
            'name': 'High Security Server',
            'description': 'High security template with 4096-bit RSA keys',
            'organization': 'WCAMAN Certificate Authority',
            'organizational_unit': 'Security Department',
            'country': 'US',
            'state': 'California',
            'locality': 'San Francisco',
            'key_type': 'RSA',
            'key_size': '4096',
            'default_validity': '2-years'
        }
    ]
    
    for template_data in templates:
        if not CSRTemplate.objects(name=template_data['name']).first():
            template = CSRTemplate(
                created_by=admin,
                **template_data
            )
            template.save()
            print(f"✅ Created CSR template: {template.name}")
        else:
            print(f"ℹ️  CSR template already exists: {template_data['name']}")


def create_step_ca_service():
    """Create default Step-CA service configuration"""
    print("🔧 Creating Step-CA service configuration...")
    
    service_name = "Default Step-CA"
    if not StepCAService.objects(name=service_name).first():
        service = StepCAService(
            name=service_name,
            url="https://localhost:9000",
            ca_url="https://localhost:9000",
            is_active=True,
            health_status="unknown",
            default_validity="1-year",
            max_validity="5-years"
        )
        service.save()
        print(f"✅ Created Step-CA service: {service.name}")
    else:
        print(f"ℹ️  Step-CA service already exists: {service_name}")


def create_notification_rules():
    """Create default notification rules"""
    print("📧 Creating default notification rules...")
    
    admin = User.objects(email="admin@wcaman.local").first()
    if not admin:
        print("❌ Admin user not found. Run create_initial_users first.")
        return
    
    rules = [
        {
            'name': 'Certificate Expiry - 30 Days',
            'description': 'Notify when certificates expire in 30 days',
            'event_type': 'expiry_30',
            'notification_method': 'email',
            'recipients': ['admin@wcaman.local']
        },
        {
            'name': 'Certificate Expiry - 7 Days',
            'description': 'Notify when certificates expire in 7 days',
            'event_type': 'expiry_7',
            'notification_method': 'email',
            'recipients': ['admin@wcaman.local', 'manager@wcaman.local']
        },
        {
            'name': 'CSR Pending Approval',
            'description': 'Notify when CSR requests need approval',
            'event_type': 'csr_pending',
            'notification_method': 'email',
            'recipients': ['admin@wcaman.local', 'manager@wcaman.local']
        }
    ]
    
    for rule_data in rules:
        if not NotificationRule.objects(name=rule_data['name']).first():
            rule = NotificationRule(
                created_by=admin,
                **rule_data
            )
            rule.save()
            print(f"✅ Created notification rule: {rule.name}")
        else:
            print(f"ℹ️  Notification rule already exists: {rule_data['name']}")


def main():
    """Main initialization function"""
    print("🚀 Initializing WCAMAN MongoDB Database...")
    print("=" * 50)
    
    try:
        # Test MongoDB connection
        User.objects.count()
        print("✅ MongoDB connection successful!")
        
        # Create initial data
        create_initial_users()
        create_initial_csr_templates()
        create_step_ca_service()
        create_notification_rules()
        
        print("=" * 50)
        print("🎉 MongoDB initialization completed successfully!")
        print("\n📋 Default Users Created:")
        print("  👤 Admin: admin@wcaman.local / admin123")
        print("  👤 Manager: manager@wcaman.local / manager123")
        print("  👤 User: user@wcaman.local / user123")
        print("\n🌐 You can now start the Django server:")
        print("  python manage.py runserver")
        
    except Exception as e:
        print(f"❌ MongoDB initialization failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
