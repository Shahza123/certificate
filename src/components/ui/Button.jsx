import React from 'react';
import { Loader2 } from 'lucide-react';

const Button = ({
  children,
  variant = 'primary',
  size = 'md',
  disabled = false,
  loading = false,
  fullWidth = false,
  className = '',
  onClick,
  type = 'button',
  ...props
}) => {
  const baseClasses =
    "inline-flex items-center justify-center font-medium rounded-md transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed";

  const variants = {
    primary:
      "bg-blue-600 text-white hover:bg-blue-700 focus:ring-blue-500 shadow-sm hover:shadow-md " +
      "dark:bg-gray-900 dark:hover:bg-gray-950 dark:focus:ring-gray-400",
    secondary:
      "bg-gray-600 text-white hover:bg-gray-700 focus:ring-gray-500 shadow-sm hover:shadow-md " +
      "dark:bg-gray-700 dark:hover:bg-gray-800 dark:focus:ring-gray-600",
    success:
      "bg-green-600 text-white hover:bg-green-700 focus:ring-green-500 shadow-sm hover:shadow-md " +
      "dark:bg-green-500 dark:hover:bg-green-600 dark:focus:ring-green-400",
    danger:
      "bg-red-600 text-white hover:bg-red-700 focus:ring-red-500 shadow-sm hover:shadow-md " +
      "dark:bg-red-500 dark:hover:bg-red-600 dark:focus:ring-red-400",
    warning:
      "bg-yellow-600 text-white hover:bg-yellow-700 focus:ring-yellow-500 shadow-sm hover:shadow-md " +
      "dark:bg-yellow-500 dark:hover:bg-yellow-600 dark:focus:ring-yellow-400",
    outline:
      "border-2 border-gray-300 text-gray-700 hover:bg-gray-50 focus:ring-gray-500 bg-white " +
      "dark:border-gray-700 dark:text-gray-200 dark:bg-gray-800 dark:hover:bg-gray-700",
    ghost:
      "text-gray-700 hover:bg-gray-100 focus:ring-gray-500 bg-transparent " +
      "dark:text-gray-200 dark:hover:bg-gray-700 dark:focus:ring-gray-600"
  };

  const sizes = {
    sm: "px-3 py-1.5 text-sm",
    md: "px-4 py-2 text-sm",
    lg: "px-6 py-3 text-base",
    xl: "px-8 py-4 text-lg"
  };

  const widthClass = fullWidth ? "w-full" : "";

  const classes = `${baseClasses} ${variants[variant]} ${sizes[size]} ${widthClass} ${className}`;

  return (
    <button
      type={type}
      className={classes}
      disabled={disabled || loading}
      onClick={onClick}
      {...props}
    >
      {loading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
      {children}
    </button>
  );
};

export default Button;
