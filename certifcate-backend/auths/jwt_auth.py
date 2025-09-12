"""
JWT Authentication for MongoDB Users

Custom JWT authentication that works with MongoEngine User model.
"""

from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework import exceptions
from django.contrib.auth.models import AnonymousUser
from auths.mongodb_models import User as MongoUser
import jwt
from django.conf import settings


class MongoJWTAuthentication(JWTAuthentication):
    """
    Custom JWT authentication for MongoDB users
    """
    
    def get_user(self, validated_token):
        """
        Get user from MongoDB based on JWT token
        """
        try:
            user_id = validated_token.get('user_id')
            email = validated_token.get('email')
            
            # Get user from MongoDB
            if email:
                user = MongoUser.objects(email=email).first()
            elif user_id:
                user = MongoUser.objects(id=user_id).first()
            else:
                return None
            
            if user and user.is_active:
                return self._create_django_user(user)
            
        except Exception as e:
            print(f"JWT auth error: {e}")
            return None
        
        return None
    
    def _create_django_user(self, mongo_user):
        """
        Create a Django-compatible user object from MongoDB user
        """
        class DjangoUser:
            def __init__(self, mongo_user):
                self.id = str(mongo_user.id)
                self.email = mongo_user.email
                self.first_name = mongo_user.first_name
                self.last_name = mongo_user.last_name
                self.role = mongo_user.role
                self.is_active = mongo_user.is_active
                self.is_staff = mongo_user.is_staff
                self.is_superuser = mongo_user.role == 'admin'
                self.username = mongo_user.email
                self._mongo_user = mongo_user
                self.pk = str(mongo_user.id)
            
            @property
            def is_authenticated(self):
                return True
            
            @property
            def is_anonymous(self):
                return False
            
            def get_username(self):
                return self.email
            
            def __str__(self):
                return self.email
        
        return DjangoUser(mongo_user)
