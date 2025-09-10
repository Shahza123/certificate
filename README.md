# Full Stack Certificate Management System

A complete certificate management system with Django backend (JWT auth) and React frontend, featuring Step-CA integration.

## Features

### Authentication
- ✅ User Registration with validation
- ✅ User Login with JWT authentication  
- ✅ Protected routes
- ✅ Token refresh mechanism
- ✅ Automatic token management

### Certificate Management
- ✅ SSL Certificate generation via Step-CA
- ✅ Certificate validation and monitoring
- ✅ Certificate download in multiple formats (PEM, DER, P12, JKS)
- ✅ Certificate expiry tracking and notifications
- ✅ Step-CA service health monitoring
- ✅ Certificate search and filtering
- ✅ Certificate revocation support

### UI/UX
- ✅ Beautiful, responsive UI with Tailwind CSS
- ✅ Form validation and error handling
- ✅ Real-time certificate status updates
- ✅ Dark mode support

## Backend (Django)

### Setup

1. Navigate to the backend directory:
```bash
cd certifcate-backend
```

2. Activate virtual environment:
```bash
# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate
```

3. Install dependencies (if not already installed):
```bash
pip install django djangorestframework djangorestframework-simplejwt django-cors-headers
```

## Step-CA Setup (Optional - for real certificates)

The system works in **development mode** with mock certificates by default. To use real Step-CA certificates:

### Install Step-CA CLI

**Windows:**
```bash
# Using Chocolatey
choco install step

# Or download from GitHub releases
# https://github.com/smallstep/cli/releases
```

**Linux/Mac:**
```bash
# Linux
wget https://dl.step.sm/gh-release/cli/docs-cli-install/v0.24.4/step-cli_0.24.4_amd64.deb
sudo dpkg -i step-cli_0.24.4_amd64.deb

# Mac
brew install step
```

### Configure Step-CA Service

1. Initialize Step-CA:
```bash
step ca init
```

2. Start Step-CA server:
```bash
step-ca $(step path)/config/ca.json
```

3. Update Django settings in `core/settings.py`:
```python
STEP_CA_URL = 'https://your-step-ca-server:9000'
STEP_CA_FINGERPRINT = 'your-ca-fingerprint'  # Optional
```

4. Run migrations:
```bash
python manage.py makemigrations
python manage.py migrate
```

5. Create superuser (optional):
```bash
python manage.py createsuperuser
```

6. Start the development server:
```bash
python manage.py runserver
```

The backend will be available at `http://127.0.0.1:8000/`

### API Endpoints

- `POST /api/auth/register/` - User registration
- `POST /api/auth/login/` - User login
- `POST /api/auth/token/refresh/` - Refresh JWT token
- `GET /api/auth/profile/` - Get user profile (protected)

## Frontend (React + Vite)

### Setup

1. Navigate to the frontend directory:
```bash
cd webCertificate/Web-Certificate
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm run dev
```

The frontend will be available at `http://localhost:5173/`

## Usage

1. **Start both servers** (backend on port 8000, frontend on port 5173)

2. **Register a new account:**
   - Navigate to `http://localhost:5173/signup`
   - Fill in the registration form
   - You'll be automatically logged in and redirected to the dashboard

3. **Login with existing account:**
   - Navigate to `http://localhost:5173/login`  
   - Enter your email and password
   - You'll be redirected to the dashboard

4. **Protected Dashboard:**
   - Only accessible when authenticated
   - Shows your authentication status
   - Includes logout functionality

## Technical Details

### Authentication Flow

1. **Registration/Login:** User credentials are sent to Django backend
2. **Token Generation:** Backend generates JWT access and refresh tokens
3. **Token Storage:** Tokens are stored in browser localStorage
4. **Protected Requests:** Access token is included in Authorization header
5. **Token Refresh:** When access token expires, refresh token is used automatically
6. **Logout:** Tokens are removed from localStorage

### Frontend Architecture

- **React Router:** For navigation and protected routes
- **Context API:** For global authentication state management
- **Tailwind CSS:** For responsive, modern UI
- **Custom Hooks:** useAuth hook for authentication operations

### Backend Architecture

- **Django REST Framework:** For API endpoints
- **Simple JWT:** For JWT token management
- **Custom User Model:** Email-based authentication
- **CORS Headers:** For cross-origin requests

## Security Features

- Password validation
- CSRF protection
- JWT token expiration
- Automatic token refresh
- Protected route access control
- Input validation and sanitization

## File Structure

```
├── certifcate-backend/          # Django backend
│   ├── auths/                   # Authentication app
│   │   ├── models.py           # Custom User model
│   │   ├── serializers.py      # API serializers
│   │   ├── views.py            # API views
│   │   └── urls.py             # URL routing
│   └── core/                   # Django project settings
│
└── webCertificate/Web-Certificate/  # React frontend
    ├── src/
    │   ├── components/         # React components
    │   │   ├── Login.jsx      # Login form
    │   │   ├── Signup.jsx     # Registration form
    │   │   ├── Dashboard.jsx  # Protected dashboard
    │   │   └── ProtectedRoute.jsx # Route protection
    │   ├── contexts/          # React contexts
    │   │   └── AuthContext.jsx # Authentication state
    │   ├── services/          # API services
    │   │   └── authService.js # Authentication API calls
    │   └── App.jsx            # Main app component
    └── package.json
```

## Next Steps

You can extend this system by adding:

- User profile management
- Password reset functionality  
- Email verification
- Role-based permissions
- Social authentication
- Two-factor authentication
- Certificate generation features
