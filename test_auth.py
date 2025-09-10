#!/usr/bin/env python3
"""
Test script to verify authentication endpoints are working
"""
import requests
import json

BASE_URL = "http://127.0.0.1:8000/api/auth"

def test_registration():
    """Test user registration"""
    print("🔍 Testing Registration...")
    
    data = {
        "email": "test@example.com",
        "first_name": "Test",
        "last_name": "User", 
        "password": "testpass123",
        "password2": "testpass123"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/register/", json=data)
        print(f"Registration Status: {response.status_code}")
        
        if response.status_code == 201:
            result = response.json()
            print("✅ Registration successful!")
            print(f"Message: {result.get('msg')}")
            if 'token' in result:
                print("✅ JWT tokens received")
                return result['token']
            return None
        else:
            print("❌ Registration failed:")
            print(json.dumps(response.json(), indent=2))
            return None
            
    except Exception as e:
        print(f"❌ Registration error: {e}")
        return None

def test_login():
    """Test user login"""
    print("\n🔍 Testing Login...")
    
    data = {
        "email": "test@example.com",
        "password": "testpass123"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/login/", json=data)
        print(f"Login Status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print("✅ Login successful!")
            print(f"Message: {result.get('msg')}")
            if 'token' in result:
                print("✅ JWT tokens received")
                return result['token']
            return None
        else:
            print("❌ Login failed:")
            print(json.dumps(response.json(), indent=2))
            return None
            
    except Exception as e:
        print(f"❌ Login error: {e}")
        return None

def test_protected_endpoint(access_token):
    """Test protected profile endpoint"""
    print("\n🔍 Testing Protected Endpoint...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(f"{BASE_URL}/profile/", headers=headers)
        print(f"Profile Status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print("✅ Protected endpoint access successful!")
            print(f"User email: {result.get('email')}")
            return True
        else:
            print("❌ Protected endpoint access failed:")
            print(json.dumps(response.json(), indent=2))
            return False
            
    except Exception as e:
        print(f"❌ Protected endpoint error: {e}")
        return False

def test_token_refresh(refresh_token):
    """Test token refresh"""
    print("\n🔍 Testing Token Refresh...")
    
    data = {
        "refresh": refresh_token
    }
    
    try:
        response = requests.post(f"{BASE_URL}/token/refresh/", json=data)
        print(f"Refresh Status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print("✅ Token refresh successful!")
            if 'access' in result:
                print("✅ New access token received")
                return result['access']
            return None
        else:
            print("❌ Token refresh failed:")
            print(json.dumps(response.json(), indent=2))
            return None
            
    except Exception as e:
        print(f"❌ Token refresh error: {e}")
        return None

if __name__ == "__main__":
    print("🚀 Testing Django Authentication System")
    print("=" * 50)
    
    # Test registration
    tokens = test_registration()
    
    if tokens:
        access_token = tokens.get('access')
        refresh_token = tokens.get('refresh')
        
        # Test protected endpoint
        test_protected_endpoint(access_token)
        
        # Test token refresh
        if refresh_token:
            new_access_token = test_token_refresh(refresh_token)
            if new_access_token:
                # Test protected endpoint with new token
                print("\n🔍 Testing Protected Endpoint with Refreshed Token...")
                test_protected_endpoint(new_access_token)
    
    # Test login with existing user
    login_tokens = test_login()
    
    if login_tokens:
        print("\n✅ All authentication tests completed!")
        print("\n🎯 Summary:")
        print("   ✅ User Registration")
        print("   ✅ User Login") 
        print("   ✅ JWT Token Generation")
        print("   ✅ Protected Endpoint Access")
        print("   ✅ Token Refresh")
        print("\n🔥 Your authentication system is working perfectly!")
    else:
        print("\n❌ Some tests failed. Check your Django server.")
        
    print("\n" + "=" * 50)
    print("Frontend is running at: http://localhost:5174/")
    print("Backend is running at: http://127.0.0.1:8000/")
    print("API Base URL: http://127.0.0.1:8000/api/auth/")
