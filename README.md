# WACMAN SSL Certificate Manager

A professional, enterprise-grade SSL Certificate Management System built with React and modern web technologies. This application provides a comprehensive interface for managing SSL certificates, user roles, and certificate authority operations.

**🚀 Currently in Demo Mode - Static UI Only**

## 🚀 Features

### Core Functionality
- **SSL Certificate Generation**: Create self-signed and CA-signed certificates
- **Certificate Management**: View, validate, and manage all issued certificates
- **Role-Based Access Control**: Admin, CA Manager, and User roles with appropriate permissions
- **Professional UI/UX**: Modern, responsive design with intuitive navigation
- **Form Validation**: Comprehensive client-side validation with user feedback
- **Static UI Mode**: No authentication required - perfect for demonstrations

### Technical Features
- **React 19**: Latest React features and performance optimizations
- **Tailwind CSS**: Utility-first CSS framework for rapid UI development
- **Context API**: Modern state management with React Context
- **Public Routes**: All routes accessible without authentication
- **Professional Components**: Reusable UI components with modern design
- **Responsive Design**: Mobile-first approach with desktop optimization

## 🏗️ Architecture

```
src/
├── components/
│   ├── ui/                 # Reusable UI components
│   │   ├── Button.jsx     # Professional button component
│   │   ├── FormField.jsx  # Form input component
│   │   └── Toast.jsx      # Notification system
│   ├── layout/            # Layout components
│   │   ├── NavBar.jsx     # Top navigation bar
│   │   └── SideBar.jsx    # Side navigation
│   └── AdminPanel.jsx     # User management interface
├── pages/                 # Application pages
│   ├── Dashboard.jsx      # Main dashboard
│   ├── IssueCertificate.jsx # Certificate generation
│   ├── Certificates.jsx   # Certificate listing
│   ├── LogIn.jsx          # Demo login page
│   └── ...                # Other pages
└── App.jsx                # Main application component
```

## 🛠️ Installation & Setup

### Prerequisites
- Node.js 18+ 
- npm or yarn

### Installation
```bash
# Clone the repository
git clone <repository-url>
cd Web-Certificate

# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

### Environment Setup
The application is currently in **static UI mode** for demonstration purposes:

1. **No Authentication Required**: All routes are publicly accessible
2. **Mock Data**: Uses sample data for demonstration
3. **Demo Mode**: Perfect for showcasing the interface
4. **Ready for Integration**: Can easily be connected to real backend services

## 🔐 Demo Mode

### How to Use
1. **Start the app**: `npm run dev`
2. **Access any route**: Navigate directly to `/dashboard`, `/issue`, etc.
3. **No login required**: All features are immediately accessible
4. **Demo forms**: Fill out forms to see the UI in action

### Demo Features
- **Login Page**: Beautiful login form (redirects to dashboard)
- **Sign Up Page**: Professional registration form (redirects to dashboard)
- **Dashboard**: Full dashboard with mock data
- **Certificate Generation**: Working form with validation
- **User Management**: Admin panel with sample users
- **Navigation**: Complete sidebar navigation

## 📱 Usage

### 1. Direct Access
- Navigate directly to any route without authentication
- All features are immediately available
- Perfect for demonstrations and testing

### 2. Generate Certificate
- Navigate to "Generate New Certificate"
- Fill in hostname/IP address
- Select certificate type and parameters
- Submit to see the success flow

### 3. Manage Certificates
- View all certificates in the "Certificates" section
- Search and filter certificates
- See the professional table interface

### 4. User Management
- Access user management through sidebar
- View sample users and roles
- Experience the admin interface

## 🎨 UI Components

### FormField Component
Professional form input with validation:
```jsx
<FormField
  label="Hostname"
  name="hostname"
  type="text"
  value={hostname}
  onChange={handleChange}
  error={errors.hostname}
  required
/>
```

### Button Component
Multiple variants and states:
```jsx
<Button
  variant="primary"
  size="lg"
  loading={isSubmitting}
  fullWidth
>
  Generate Certificate
</Button>
```

## 🔒 Current Status

- **Static UI Mode**: No authentication required
- **Public Routes**: All features accessible immediately
- **Demo Data**: Sample certificates and users
- **Professional Design**: Enterprise-grade interface
- **Ready for Backend**: Easy to integrate with real services

## 📊 Prototype Requirements Met

✅ **STEP-CA Service Integration Ready**
- Linux OS deployment ready
- SSL certificate generation for specified hosts
- Support for IP addresses, localhost, and domains

✅ **Professional UI Framework**
- Beautiful login and signup pages
- Role-based interface design
- Modern, responsive interface

✅ **CA Manager Capabilities**
- Ready for step-ca service connection
- Certificate management interface
- User role management

## 🚀 Future Enhancements

- **Real API Integration**: Connect to actual STEP-CA service
- **Authentication System**: Add real user login/logout
- **Database Integration**: Persistent storage for certificates
- **Advanced Validation**: Certificate chain validation
- **Audit Logging**: Track all certificate operations
- **Bulk Operations**: Generate multiple certificates

## 🧪 Testing

```bash
# Run linting
npm run lint

# Run tests (when implemented)
npm test

# Build and preview
npm run build
npm run preview
```

## 📁 Project Structure

```
Web-Certificate/
├── public/                 # Static assets
├── src/                   # Source code
│   ├── components/        # Reusable components
│   ├── pages/            # Application pages
│   ├── App.jsx           # Main app component
│   └── main.jsx          # Entry point
├── package.json           # Dependencies
├── tailwind.config.js     # Tailwind configuration
├── vite.config.js         # Vite configuration
└── README.md              # This file
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Contact the development team
- Check the documentation

---

**🚀 Demo Mode Active - No Authentication Required!**

**Built with ❤️ using React, Tailwind CSS, and modern web technologies**
