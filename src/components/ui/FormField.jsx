import React from 'react';
import { AlertCircle, CheckCircle } from 'lucide-react';

const FormField = ({
  label,
  name,
  type = 'text',
  value,
  onChange,
  onBlur,
  error,
  success,
  required = false,
  placeholder,
  options = [],
  className = '',
  disabled = false,
  ...props
}) => {
  const inputId = `field-${name}`;
  
  const getInputClasses = () => {
    let baseClasses =
      "w-full px-3 py-2 border rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent " +
      "bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-200 border-gray-300 dark:border-gray-700 " +
      "placeholder-gray-400 dark:placeholder-gray-500";

    if (error) {
      baseClasses += " border-red-300 bg-red-50 dark:bg-red-900 focus:ring-red-500";
    } else if (success) {
      baseClasses += " border-green-300 bg-green-50 dark:bg-green-900 focus:ring-green-500";
    } else {
      baseClasses += " hover:border-gray-400 dark:hover:border-gray-500";
    }

    if (disabled) {
      baseClasses += " bg-gray-100 dark:bg-gray-700 cursor-not-allowed";
    }

    return baseClasses;
  };

  const renderInput = () => {
    switch (type) {
      case 'select':
        return (
          <select
            id={inputId}
            name={name}
            value={value}
            onChange={onChange}
            onBlur={onBlur}
            disabled={disabled}
            className={getInputClasses()}
            {...props}
          >
            <option value="">{placeholder || `Select ${label}`}</option>
            {options.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        );

      case 'textarea':
        return (
          <textarea
            id={inputId}
            name={name}
            value={value}
            onChange={onChange}
            onBlur={onBlur}
            disabled={disabled}
            placeholder={placeholder}
            className={`${getInputClasses()} resize-vertical min-h-[100px]`}
            {...props}
          />
        );

      default:
        return (
          <input
            id={inputId}
            type={type}
            name={name}
            value={value}
            onChange={onChange}
            onBlur={onBlur}
            disabled={disabled}
            placeholder={placeholder}
            className={getInputClasses()}
            {...props}
          />
        );
    }
  };

  return (
    <div className={`space-y-2 ${className}`}>
      <label
        htmlFor={inputId}
        className="block text-sm font-medium text-gray-700 dark:text-gray-300"
      >
        {label}
        {required && <span className="text-red-500 ml-1">*</span>}
      </label>

      {renderInput()}

      {/* Error Message */}
      {error && (
        <div className="flex items-center text-sm text-red-600 dark:text-red-400">
          <AlertCircle className="w-4 h-4 mr-1 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Success Message */}
      {success && !error && (
        <div className="flex items-center text-sm text-green-600 dark:text-green-400">
          <CheckCircle className="w-4 h-4 mr-1 flex-shrink-0" />
          <span>{success}</span>
        </div>
      )}
    </div>
  );
};

export default FormField;
