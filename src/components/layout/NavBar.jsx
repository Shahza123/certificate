import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Bell, ChevronDown, User, Settings, Shield } from "lucide-react";

const NavBar = ({ sidebarWidth = 250 }) => {
  const [dropdownOpen, setDropdownOpen] = useState(false);

  // Mock user data for static UI
  const mockUser = {
    name: "Demo User",
    email: "demo@wacman.com",
    role: "ca-manager"
  };

  const getUserInitials = (name) => {
    return name
      .split(' ')
      .map(word => word.charAt(0))
      .join('')
      .toUpperCase()
      .slice(0, 2);
  };

  const getRoleColor = (role) => {
    switch (role) {
      case 'admin':
        return 'bg-purple-600';
      case 'ca-manager':
        return 'bg-blue-600';
      case 'user':
        return 'bg-green-600';
      default:
        return 'bg-gray-600';
    }
  };

  const getRoleLabel = (role) => {
    switch (role) {
      case 'admin':
        return 'Administrator';
      case 'ca-manager':
        return 'CA Manager';
      case 'user':
        return 'User';
      default:
        return 'User';
    }
  };

  return (
    <nav
      className="fixed top-0 z-50 bg-white shadow-sm border-b border-gray-200"
      style={{ left: sidebarWidth, right: 0 }}
    >
      <div className="flex items-center justify-between px-6 py-4">
        {/* Left Section - Page Title */}
        <div className="flex items-center">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 rounded-lg">
              <Shield className="w-5 h-5 text-blue-600" />
            </div>
            <h1 className="text-2xl font-bold text-gray-900">
              Generate SSL Certificate
            </h1>
          </div>
        </div>

        {/* Right Section */}
        <div className="flex items-center gap-4">
          {/* Notification Icon */}
          <button className="relative p-2 rounded-full hover:bg-gray-100 transition-colors">
            <Bell className="w-5 h-5 text-gray-600" />
            <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full"></span>
          </button>

          {/* User Profile Dropdown */}
          <div className="relative">
            <button
              onClick={() => setDropdownOpen(!dropdownOpen)}
              className="flex items-center gap-2 p-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition-colors focus:outline-none"
            >
              <div className={`w-8 h-8 flex items-center justify-center rounded-full text-white font-semibold text-sm ${getRoleColor(mockUser.role)}`}>
                {getUserInitials(mockUser.name)}
              </div>
              <span className="text-sm font-medium">
                {mockUser.name}
              </span>
              <ChevronDown className="w-4 h-4" />
            </button>
            
            {dropdownOpen && (
              <div className="absolute right-0 mt-2 w-64 bg-white border border-gray-200 shadow-lg rounded-lg z-50">
                {/* User Info Header */}
                <div className="px-4 py-3 border-b border-gray-100 bg-gray-50">
                  <p className="text-sm font-medium text-gray-900">{mockUser.name}</p>
                  <p className="text-xs text-gray-500">{mockUser.email}</p>
                  <div className="mt-2">
                    <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${getRoleColor(mockUser.role)} text-white`}>
                      {getRoleLabel(mockUser.role)}
                    </span>
                  </div>
                </div>

                {/* Menu Items */}
                <div className="py-2">
                  <Link
                    to="/profile"
                    className="flex items-center px-4 py-2 hover:bg-gray-50 text-sm text-gray-700 transition-colors"
                    onClick={() => setDropdownOpen(false)}
                  >
                    <User className="w-4 h-4 mr-3" />
                    Profile
                  </Link>
                  
                  <Link
                    to="/user-management"
                    className="flex items-center px-4 py-2 hover:bg-gray-50 text-sm text-gray-700 transition-colors"
                    onClick={() => setDropdownOpen(false)}
                  >
                    <Settings className="w-4 h-4 mr-3" />
                    User Management
                  </Link>
                  
                  <Link
                    to="/dashboard"
                    className="flex items-center px-4 py-2 hover:bg-gray-50 text-sm text-gray-700 transition-colors"
                    onClick={() => setDropdownOpen(false)}
                  >
                    <User className="w-4 h-4 mr-3" />
                    Dashboard
                  </Link>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
};

export default NavBar;
