"""
MongoDB Authentication Backend for Django

This module provides authentication backend that works with MongoEngine User model.
"""

from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
from auths.mongodb_models import User as MongoUser, UserManager


class MongoEngineBackend(BaseBackend):
    """
    Authentication backend for MongoEngine User model
    """
    
    def authenticate(self, request, username=None, password=None, email=None, **kwargs):
        """
        Authenticate user using MongoDB
        """
        try:
            # Use email as username
            email_to_check = email or username
            if not email_to_check:
                return None
            
            # Get user from MongoDB
            user = MongoUser.objects(email=email_to_check).first()
            if user and user.check_password(password) and user.is_active:
                return self._create_django_user(user)
            
        except Exception as e:
            print(f"Authentication error: {e}")
            return None
        
        return None
    
    def get_user(self, user_id):
        """
        Get user by ID for Django compatibility
        """
        try:
            # Try to get from MongoDB first
            user = MongoUser.objects(id=user_id).first()
            if user:
                return self._create_django_user(user)
        except Exception as e:
            print(f"Get user error: {e}")
        
        return None
    
    def _create_django_user(self, mongo_user):
        """
        Create a Django-compatible user object from MongoDB user
        """
        # Create a simple user object for Django compatibility
        class DjangoCompatUser:
            def __init__(self, mongo_user):
                self.id = str(mongo_user.id)
                self.email = mongo_user.email
                self.first_name = mongo_user.first_name
                self.last_name = mongo_user.last_name
                self.role = mongo_user.role
                self.is_active = mongo_user.is_active
                self.is_staff = mongo_user.is_staff
                self.is_superuser = mongo_user.role == 'admin'
                self.username = mongo_user.email  # Use email as username
                self._mongo_user = mongo_user
            
            def is_authenticated(self):
                return True
            
            def is_anonymous(self):
                return False
            
            def get_username(self):
                return self.email
            
            def __str__(self):
                return self.email
        
        return DjangoCompatUser(mongo_user)


class MongoEngineUserMiddleware:
    """
    Middleware to handle MongoDB users in Django requests
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Process the request
        response = self.get_response(request)
        return response
    
    def process_request(self, request):
        """
        Add MongoDB user to request if authenticated
        """
        if hasattr(request, 'user') and request.user.is_authenticated:
            # Enhance request.user with MongoDB capabilities
            if hasattr(request.user, '_mongo_user'):
                request.mongo_user = request.user._mongo_user
        
        return None
