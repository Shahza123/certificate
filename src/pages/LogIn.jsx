import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Eye, EyeOff } from 'lucide-react';

const LogIn = () => {
  const navigate = useNavigate();
  const [showPassword, setShowPassword] = useState(false);

  const handleDemoLogin = () => {
    // Simple redirect to dashboard for demo
    navigate('/dashboard');
  };

  return (
    <div className="min-h-screen bg-gray-100 dark:bg-gray-900 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo and Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-600 rounded-full mb-4">
            <Shield className="w-8 h-8 text-white " />
          </div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-50 mb-2">Welcome Back</h1>
          <p className="text-gray-900 dark:text-gray-50">Sign in to your SSL Certificate Manager</p>
        </div>

        {/* Login Form */}
        <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-xl border border-gray-100 dark:border-gray-900 p-8">
          <form className="space-y-6">
            <div className="space-y-2">
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-50">
                Username <span className="text-red-500">*</span>
              </label>
     <input
  type="text"
  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-700 
             rounded-md bg-white dark:bg-gray-900 
             text-gray-900 dark:text-gray-100
             placeholder-gray-400 dark:placeholder-gray-500
             focus:ring-2 focus:ring-blue-500 focus:border-transparent"
               placeholder=" Full Name"
/>


            </div>

            <div className="space-y-2">
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-50">
                Password <span className="text-red-500">*</span>
              </label>
              <div className="relative">
                <input
  type={showPassword ? 'text' : 'password'}
  className="w-full px-3 py-2 pr-10 border border-gray-300 dark:border-gray-700 
             rounded-md bg-white dark:bg-gray-900 
             text-gray-900 dark:text-gray-100
             placeholder-gray-400 dark:placeholder-gray-500
             focus:ring-2 focus:ring-blue-500 focus:border-transparent"
               placeholder=" User name"
/>

                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-600"
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  defaultChecked
                />
                <span className="ml-2 text-sm text-gray-600 dark:text-gray-50">Remember me</span>
              </label>
              <a href="#" className="text-sm text-blue-600 hover:text-blue-500 font-medium">
                Forgot password?
              </a>
            </div>

            <button
              type="button"
              onClick={handleDemoLogin}
              className="w-full bg-blue-700 dark:bg-gray-900 text-white py-3 rounded-lg hover:bg-blue-800 dark:hover:bg-gray-950 transition-colors font-medium"
            >
              Sign In (Demo)
            </button>
          </form>

          {/* Demo Credentials */}
          <div className="mt-6 p-4 bg-blue-50 dark:bg-gray-700 rounded-lg border border-blue-200 dark:border-gray-700">
            <h3 className="text-sm font-medium text-blue-800 dark:text-gray-100 mb-2">Demo Mode:</h3>
            <div className="space-y-1 text-xs text-blue-700 dark:text-gray-300">
              <div>• This is a static UI demonstration</div>
              <div>• Click "Sign In (Demo)" to access the system</div>
              <div>• No actual authentication required</div>
            </div>
          </div>

          {/* Sign Up Link */}
          <div className="mt-6 text-center">
            <p className="text-sm text-gray-600 dark:text-gray-100">
              Don't have an account?{' '}
              <Link 
                to="/signup" 
                className="text-blue-600 hover:text-blue-500 font-medium transition-colors"
              >
                Sign up
              </Link>
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="text-center mt-8">
          <p className="text-xs text-gray-500 dark:text-gray-100">
            © 2024 WACMAN SSL Certificate Manager. All rights reserved.
          </p>
        </div>
      </div>
    </div>
  );
};

export default LogIn;
