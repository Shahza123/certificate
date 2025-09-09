// src/components/pages/IssueCertificate.jsx
import React, { useState } from "react";
import FormField from "../components/ui/FormField";
import Button from "../components/ui/Button";
import { Shield, FileText, CheckCircle, Server, Globe, Home } from "lucide-react";

const IssueCertificate = () => {
  const [formData, setFormData] = useState({
    hostname: "",
    validityPeriod: "1-year",
    stepCAService: "localhost:9000"
  });

  const [errors, setErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);

  // Predefined host options based on prototype requirements
  const predefinedHosts = [
    { value: "127.0.0.1", label: "127.0.0.1 (Localhost)", icon: <Home className="w-4 h-4" /> },
    { value: "wacman.com", label: "wacman.com (Domain)", icon: <Globe className="w-4 h-4" /> },
    { value: "custom", label: "Custom IP/Hostname", icon: <Server className="w-4 h-4" /> }
  ];

  const validityPeriodOptions = [
    { value: "1-year", label: "1 Year" },
    { value: "2-years", label: "2 Years" },
    { value: "3-years", label: "3 Years" },
    { value: "5-years", label: "5 Years" }
  ];

  // Always CA-signed via STEP-CA service
  const getCertificateType = () => "CA-Signed (STEP-CA)";
  
  // Automatic key size - standard for CA-signed certificates
  const getKeySize = () => "2048";

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    
    // Clear error when user starts typing
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }

    // If predefined host is selected, update hostname
    if (name === 'predefinedHost' && value !== 'custom') {
      setFormData(prev => ({ ...prev, hostname: value }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Validation for demo
    if (!formData.hostname.trim()) {
      setErrors({ hostname: 'Hostname is required' });
      return;
    }

    // Validate hostname format
    const hostnameRegex = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$|^localhost$/;
    if (!hostnameRegex.test(formData.hostname)) {
      setErrors({ hostname: 'Please enter a valid IP address, domain name, or localhost' });
      return;
    }

    setIsSubmitting(true);
    
    try {
      // Simulate STEP-CA service call
      console.log('Connecting to STEP-CA service:', formData.stepCAService);
      console.log('Generating CA-signed certificate for host:', formData.hostname);
      console.log('Certificate type: CA-Signed (STEP-CA)');
      console.log('Key size (auto):', getKeySize());
      
      // Simulate API call delay
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Success
      setSubmitted(true);
      
      // Reset form after success
      setTimeout(() => {
        setFormData({
          hostname: "",
          validityPeriod: "1-year",
          stepCAService: "localhost:9000"
        });
        setSubmitted(false);
      }, 3000);
      
    } catch (err) {
      console.error('Error:', err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleReset = () => {
    setFormData({
      hostname: "",
      validityPeriod: "1-year",
      stepCAService: "localhost:9000"
    });
    setErrors({});
    setSubmitted(false);
  };

  if (submitted) {
    return (
      <div className="max-w-2xl mx-auto text-center py-12">
        <div className="inline-flex items-center justify-center w-16 h-16 bg-green-100 rounded-full mb-6">
          <CheckCircle className="w-8 h-8 text-green-600" />
        </div>
        <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-50 mb-4">
          CA-Signed Certificate Generated Successfully!
        </h2>
        <p className="text-gray-600  dark:text-gray-50 mb-8">
          Your CA-signed SSL certificate for <strong>{formData.hostname}</strong> has been generated via STEP-CA service and is ready for use.
        </p>
        <div className="flex gap-4 justify-center">
          <Button
            variant="outline"
            onClick={handleReset}
          >
            Generate Another Certificate
          </Button>
          <Button
            variant="primary"
            onClick={() => window.location.href = '/certificates'}
          >
            View All Certificates
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto">
      {/* Header */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-100 rounded-full mb-4 mt-5">
          <Shield className="w-8 h-8 text-blue-600" />
        </div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
          Generate CA-Signed SSL Certificate
        </h1>
        <p className="text-gray-600 dark:text-gray-300">
          Create CA-signed certificates for specific hosts via STEP-CA service
        </p>
      </div>

      {/* Form */}
      <div className="bg-white dark:bg-gray-800  text-gray-700 dark:text-gray-50 rounded-xl shadow-sm border border-blue-100 dark:border-gray-900 p-8">
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* STEP-CA Service Configuration */}
          {/* <div className="bg-blue-50 dark:bg-gray-900 border border-blue-200 dark:border-gray-800 shadow-xl rounded-lg p-4 mb-6">
            <div className="flex items-start">
              <Server className="w-5 h-5 text-blue-600  dark:text-gray-50  mt-0.5 mr-3 flex-shrink-0" />
              <div className="text-sm text-blue-800 dark:text-gray-50">
                <p className="font-medium mb-1">STEP-CA Service Configuration:</p>
                <p className="text-blue-700 dark:text-gray-200">Service running on Linux OS at: <strong>{formData.stepCAService}</strong></p>
              </div>
            </div>
          </div> */}

      {/* Certificate Type Display */}
<div className="bg-green-50 dark:bg-gray-900 border border-green-200 dark:border-gray-800 shadow-xl rounded-lg p-4">
  <div className="flex items-center">
    <Shield className="w-5 h-5 text-green-600 dark:text-green-400 mr-3" />
    <div>
      <p className="font-medium text-green-800 dark:text-green-300">
        Certificate Type: CA-Signed (STEP-CA)
      </p>
      <p className="text-sm text-green-700 dark:text-gray-200">
        All certificates are automatically signed by the STEP-CA service
      </p>
    </div>
  </div>
</div>

{/* Predefined Host Selection */}
<div className="space-y-2">
  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
    Select Host Type <span className="text-red-500">*</span>
  </label>
  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
    {predefinedHosts.map((host) => (
      <button
        key={host.value}
        type="button"
        onClick={() =>
          handleChange({ target: { name: 'predefinedHost', value: host.value } })
        }
        className={`p-3 border rounded-lg text-left transition-colors ${
          formData.hostname === host.value
            ? 'border-blue-500 bg-blue-50 text-blue-700 dark:border-blue-400 dark:bg-blue-900 dark:text-blue-300'
            : 'border-gray-300 hover:border-gray-400 dark:border-gray-700 dark:text-gray-200 dark:hover:border-gray-500'
        }`}
      >
        <div className="flex items-center gap-2">
          {host.icon}
          <span className="text-sm font-medium">{host.label}</span>
        </div>
      </button>
    ))}
  </div>
</div>

{/* Hostname/IP Field */}
<FormField
  label="Hostname/IP Address"
  name="hostname"
  type="text"
  value={formData.hostname}
  onChange={handleChange}
  error={errors.hostname}
  required
  placeholder="Enter IP address, domain, or localhost"
  className="col-span-2"
/>

{/* Validity Period */}
<div className="grid grid-cols-1 md:grid-cols-2 gap-6">
  <FormField
    label="Validity Period"
    name="validityPeriod"
    type="select"
    value={formData.validityPeriod}
    onChange={handleChange}
    options={validityPeriodOptions}
    required
  />

  

  {/* <div className="space-y-2 text-gray-700 dark:text-gray-300">
    <label className="block text-sm font-medium">
      STEP-CA Service Endpoint
    </label>
    <input
      type="text"
      name="stepCAService"
      value={formData.stepCAService}
      onChange={handleChange}
      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-800 dark:border-gray-700 dark:text-gray-200"
      placeholder="localhost:9000"
    />
  </div> */}
</div>

{/* Automatic Key Size Display */}
<div className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-md rounded-lg p-4">
  <div className="flex items-center justify-between">
    <div>
      <h4 className="font-medium text-gray-800 dark:text-gray-100">
        Key Size (Automatic)
      </h4>
      <p className="text-sm text-gray-600 dark:text-gray-400">
        Standard 2048-bit RSA key for CA-signed certificates
      </p>
    </div>
    <div className="text-right">
      <span className="text-lg font-bold text-blue-600 dark:text-blue-400">
        {getKeySize()} bits
      </span>
      <p className="text-xs text-gray-500 dark:text-gray-400">RSA</p>
    </div>
  </div>
</div>


          {/* Certificate Details Preview */}
          <div className="bg-blue-50 dark:bg-gray-900  border border-blue-200 dark:border-gray-900 shadow-md rounded-lg p-4">
            <div className="flex items-start">
              <FileText className="w-5 h-5 text-blue-600 dark:text-gray-100 mt-0.5 mr-3 flex-shrink-0" />
              <div className="text-sm text-blue-800 dark:text-gray-50">
                <p className="font-medium mb-1">Certificate Details:</p>
                <ul className="space-y-1 text-blue-700 dark:text-gray-200">
                  <li>• Host: <strong>{formData.hostname || 'Not specified'}</strong></li>
                  <li>• Type: <strong>CA-Signed (STEP-CA)</strong></li>
                  <li>• Validity: {formData.validityPeriod.replace('-', ' ')}</li>
                  <li>• Key Size: {getKeySize()} bits (Automatic)</li>
                  <li>• Service: {formData.stepCAService}</li>
                </ul>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-col sm:flex-row gap-4 pt-6">
            <Button
              type="submit"
              variant="primary"
              size="lg"
              loading={isSubmitting}
              disabled={isSubmitting}
              className="flex-1"
            >
              {isSubmitting ? 'Generating Certificate...' : 'Generate CA-Signed Certificate'}
            </Button>
            
            <Button
              type="button"
              variant="outline"
              size="lg"
              onClick={handleReset}
              disabled={isSubmitting}
              className="flex-1"
            >
              Reset Form
            </Button>
          </div>
        </form>
      </div>

      {/* Prototype Requirements Section */}
      {/* <div className="mt-8 bg-green-50 dark:bg-gray-700 rounded-xl p-6">
        <h3 className="text-lg font-semibold text-green-900 dark:text-white mb-4">Prototype Requirements Met</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="font-medium text-green-800 dark:text-gray-100 mb-2">STEP-CA Service Integration:</h4>
            <ul className="text-sm text-green-700 dark:text-gray-100 space-y-1">
              <li>✅ Linux OS deployment ready</li>
              <li>✅ Service endpoint configuration</li>
              <li>✅ CA-signed certificate generation</li>
            </ul>
          </div>
          <div>
            <h4 className="font-medium text-green-800 dark:text-gray-100 mb-2">Required Hosts Support:</h4>
            <ul className="text-sm text-green-700 dark:text-gray-100 space-y-1">
              <li>✅ IP Addresses (e.g., 192.168.1.100)</li>
              <li>✅ 127.0.0.1 (localhost)</li>
              <li>✅ wacman.com (domain)</li>
            </ul>
          </div>
        </div>
      </div> */}

      {/* Help Section */}
      {/* <div className="mt-8 bg-gray-50 dark:bg-gray-700 rounded-xl p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Need Help?</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="font-medium text-gray-800 dark:text-gray-100 mb-2">Supported Hostname Formats:</h4>
            <ul className="text-sm text-gray-600 dark:text-gray-300 space-y-1">
              <li>• IP Addresses: 192.168.1.100, 127.0.0.1</li>
              <li>• Domain Names: wacman.com, example.org</li>
              <li>• Localhost: localhost</li>
            </ul>
          </div>
          <div>
            <h4 className="font-medium text-gray-800 dark:text-gray-100 mb-2">CA-Signed Certificates:</h4>
            <ul className="text-sm text-gray-600 dark:text-gray-300 space-y-1">
              <li>• <strong>Type:</strong> Always CA-signed via STEP-CA</li>
              <li>• <strong>Key Size:</strong> Automatically 2048 bits</li>
              <li>• <strong>Security:</strong> Professional-grade certificates</li>
            </ul>
          </div>
        </div>
      </div> */}
    </div>
  );
};

export default IssueCertificate;
