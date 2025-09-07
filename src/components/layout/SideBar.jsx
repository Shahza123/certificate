import React from "react";
import { Link, useLocation } from "react-router-dom";
import { 
  LayoutDashboard, 
  ShieldCheck, 
  FileText, 
  CheckCircle, 
  Users, 
  Settings,
  Shield
} from "lucide-react";

const SideBar = ({ isOpen, toggleSidebar }) => {
  const location = useLocation();

  // All navigation items are now visible for static UI
  const navigationLinks = [
    { to: "/dashboard", label: "Dashboard", icon: <LayoutDashboard /> },
    { to: "/certificates", label: "Certificates", icon: <FileText /> },
    { to: "/issue", label: "Generate New Certificate", icon: <ShieldCheck /> },
    { to: "/validation", label: "Validation", icon: <CheckCircle /> },
    { to: "/user-management", label: "User Management", icon: <Users /> },
    { to: "/settings", label: "Settings", icon: <Settings /> },
  ];

  // Mock user data for static UI
  const mockUser = {
    name: "Demo User",
    role: "ca-manager"
  };

  return (
    <div
      className={`fixed left-0 top-0 h-screen bg-gray-50 dark:bg-gray-800 text-gray-900 dark:text-gray-50 transition-all duration-300 z-40 ${
        isOpen ? 'w-[250px]' : 'w-16'
      } flex flex-col items-center`}
    >
      {/* Sidebar Toggle Button */}
      <button
        onClick={toggleSidebar}
        className={
          isOpen
            ? "absolute top-4 right-4 z-50 p-2 bg-gray-100 rounded-md hover:bg-gray-200 focus:outline-none text-gray-800"
            : "mt-4 p-2 bg-gray-100 rounded-md hover:bg-gray-200 focus:outline-none text-gray-700"
        }
      >
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
        </svg>
      </button>
      
      {/* Logo/Brand */}
      <div className={`${isOpen ? 'mt-16' : 'mt-5'} mb-8`}>
        <div className="flex items-center justify-center">
          <div className="p-2 bg-blue-600 rounded-lg">
            <Shield className="w-6 h-6 text-gray-900 dark:text-gray-50" />
          </div>
          {isOpen && (
            <h1 className="ml-3 font-bold text-xl text-gray-900 dark:text-gray-50">
              Digital Sign Certificate
            </h1>
          )}
        </div>
      </div>

      {/* User Info */}
      <div className={`${isOpen ? 'w-full px-4' : 'w-full'} mb-6`}>
        <div className={`${isOpen ? 'p-3' : 'p-2'} bg-gray-700 rounded-lg`}>
          <div className="flex items-center">
            <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center text-gray-900 dark:text-gray-50 font-semibold text-sm">
              {mockUser.name.split(' ').map(word => word.charAt(0)).join('').toUpperCase().slice(0, 2)}
            </div>
            {isOpen && (
              <div className="ml-3">
                <p className="text-sm font-medium text-gray-300">{mockUser.name}</p>
                <p className="text-xs text-gray-300 capitalize">{mockUser.role}</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className={`flex-1 w-full ${isOpen ? 'mt-0' : 'mt-0'} pt-0`}>
        <ul className={`space-y-2 flex flex-col ${isOpen ? 'items-start pl-4 pr-2' : 'items-center'}`}>
          {navigationLinks.map((link) => (
            <li key={link.to} className="w-full">
              <Link
                to={link.to}
                className={`flex items-center gap-3 p-3 rounded-md hover:bg-gray-700 transition w-full ${
                  location.pathname === link.to ? "bg-blue-600 text-gray-900 dark:text-gray-50" : "text-gray-900 dark:text-gray-50 hover:text-white"
                } ${isOpen ? 'justify-start' : 'justify-center'}`}
              >
                <span className="w-5 h-5 flex items-center justify-center">{link.icon}</span>
                {isOpen && <span className="text-sm font-medium">{link.label}</span>}
              </Link>
            </li>
          ))}
        </ul>
      </nav>

      {/* Demo Mode Indicator */}
      <div className={`w-full ${isOpen ? 'px-4' : 'px-2'} pb-6`}>
        <div className={`${isOpen ? 'p-3' : 'p-2'} bg-yellow-600 rounded-lg text-center`}>
          {isOpen && (
            <span className="text-xs font-medium text-gray-900 dark:text-gray-50">Demo Mode</span>
          )}
        </div>
      </div>
    </div>
  );
};

export default SideBar;
