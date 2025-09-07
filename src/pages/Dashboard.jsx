import React from 'react';
import { 
  ShieldCheck, 
  FileText, 
  CheckCircle, 
  AlertTriangle, 
  Clock, 
  Users, 
  Settings,
  Plus,
  Eye,
  Download
} from 'lucide-react';

const Dashboard = () => {
  // Mock data for dashboard
  const stats = {
    totalCertificates: 24,
    activeCertificates: 22,
    expiredCertificates: 2,
    pendingValidation: 3,
    systemUptime: '99.9%',
    lastBackup: '2 hours ago'
  };

  const recentCertificates = [
    {
      id: 1,
      hostname: '192.168.1.100',
      type: 'Self-Signed',
      status: 'Active',
      issuedDate: '2024-01-15',
      expiryDate: '2025-01-15'
    },
    {
      id: 2,
      hostname: '127.0.0.1',
      type: 'Self-Signed',
      status: 'Active',
      issuedDate: '2024-01-10',
      expiryDate: '2025-01-10'
    },
    {
      id: 3,
      hostname: 'wacman.com',
      type: 'Self-Signed',
      status: 'Active',
      issuedDate: '2024-01-05',
      expiryDate: '2025-01-05'
    }
  ];

  const quickActions = [
    {
      title: 'Generate New Certificate',
      description: 'Create SSL certificate for new host',
      icon: <Plus className="w-6 h-6" />,
      color: 'bg-blue-600 hover:bg-blue-700',
      link: '/issue'
    },
    {
      title: 'View Certificates',
      description: 'Browse all issued certificates',
      icon: <FileText className="w-6 h-6" />,
      color: 'bg-green-600 hover:bg-green-700',
      link: '/certificates'
    },
    {
      title: 'Validate Certificate',
      description: 'Check certificate status and validity',
      icon: <CheckCircle className="w-6 h-6" />,
      color: 'bg-purple-600 hover:bg-purple-700',
      link: '/validation'
    },
    {
      title: 'User Management',
      description: 'Manage system users and roles',
      icon: <Users className="w-6 h-6" />,
      color: 'bg-orange-600 hover:bg-orange-700',
      link: '/user-management'
    }
  ];

  return (
    <div className="space-y-6 bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-50 ml-4">SSL Certificate Dashboard</h1>
          <p className="text-gray-600 dark:text-gray-300 ml-4 mt-2">Manage and monitor your SSL certificate infrastructure</p>
        </div>
        <div className="mt-4 sm:mt-0">
          <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-green-100 text-green-800">
            <div className="w-2 h-2 bg-green-400 rounded-full mr-2 "></div>
            System Online
          </span>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {quickActions.map((action, index) => (
          <a
            key={index}
            href={action.link}
            className="bg-white dark:bg-slate-700  p-6  rounded-xl shadow-sm hover:shadow-md transition-shadow border border-gray-100 group"
          >
            <div className={`inline-flex p-3 rounded-lg text-white mb-4 ${action.color}`}>
              {action.icon}
            </div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-300 mb-2 group-hover:text-blue-600 transition-colors">
              {action.title}
            </h3>
            <p className="text-sm text-gray-600 dark:text-gray-50">{action.description}</p>
          </a>
        ))}
      </div>

      {/* Statistics Cards */}
      <div className=" grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
        <div className="bg-white dark:bg-slate-700  p-6 rounded-xl shadow-sm border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-300">Total Certificates</p>
              <p className="text-3xl font-bold text-gray-900 dark:text-gray-50">{stats.totalCertificates}</p>
            </div>
            <div className="p-3 bg-blue-100 rounded-lg">
              <ShieldCheck className="w-6 h-6 text-blue-600" />
            </div>
          </div>
          <div className="mt-4">
            <div className="flex items-center text-sm text-gray-600 dark:text-gray-50">
              <span className="text-green-600 font-medium">{stats.activeCertificates} Active</span>
              <span className="mx-2">•</span>
              <span className="text-red-600 font-medium">{stats.expiredCertificates} Expired</span>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-slate-700  p-6 rounded-xl shadow-sm border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-300">System Status</p>
              <p className="text-3xl font-bold text-gray-900 dark:text-gray-50">{stats.systemUptime}</p>
            </div>
            <div className="p-3 bg-green-100 rounded-lg">
              <CheckCircle className="w-6 h-6 text-green-600" />
            </div>
          </div>
          <div className="mt-4">
            <div className="flex items-center text-sm text-gray-600 dark:text-gray-50">
              <Clock className="w-4 h-4 mr-1" />
              Last backup: {stats.lastBackup}
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-slate-700 p-6 rounded-xl shadow-sm border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-300">Pending Actions</p>
              <p className="text-3xl font-bold text-gray-900 dark:text-gray-50">{stats.pendingValidation}</p>
            </div>
            <div className="p-3 bg-yellow-100 rounded-lg">
              <AlertTriangle className="w-6 h-6 text-yellow-600" />
            </div>
          </div>
          <div className="mt-4">
            <div className="flex items-center text-sm text-gray-600">
              <span className="text-yellow-600 font-medium">Certificates pending validation</span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Certificates */}
      <div className="bg-white dark:bg-slate-700  rounded-xl shadow-sm border border-gray-100">
        <div className="p-6 border-b border-gray-100">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold text-gray-900 dark:text-gray-300">Recent Certificates</h2>
            <a 
              href="/certificates" 
              className="text-blue-600 hover:text-blue-700 text-sm font-medium"
            >
              View All →
            </a>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className=" w-full">
            <thead className="bg-white dark:bg-slate-800 ">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-50 uppercase tracking-wider">
                  Hostname/IP
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-50 uppercase tracking-wider">
                  Type
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-50 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-50 uppercase tracking-wider">
                  Expiry Date
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500  dark:text-gray-50 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-slate-700  divide-y divide-gray-100">
              {recentCertificates.map((cert) => (
                <tr key={cert.id} className="dark:hover:bg-gray-800">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm font-medium text-gray-900 dark:text-white">{cert.hostname}</div>
                    <div className="text-sm text-gray-500 dark:text-gray-50">Issued: {cert.issuedDate}</div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-blue-100 text-gray-800">
                      {cert.type}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800">
                      {cert.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                    {cert.expiryDate}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <div className="flex space-x-2">
                      <button className="text-blue-600 hover:text-blue-900 p-1">
                        <Eye className="w-4 h-4" />
                      </button>
                      <button className="text-green-600 hover:text-green-900 p-1">
                        <Download className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* System Information */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white dark:bg-slate-700  p-6 rounded-xl shadow-sm border border-gray-100">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-300 mb-4">STEP-CA Service Status</h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600 dark:text-gray-50">Service Status</span>
              <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                Running
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600 dark:text-gray-50">Port</span>
              <span className="text-sm font-medium text-gray-900 dark:text-white">443</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600 dark:text-gray-50">Last Health Check</span>
              <span className="text-sm font-medium text-gray-900 dark:text-white">2 minutes ago</span>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-slate-700  p-6 rounded-xl shadow-sm border border-gray-100">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-300 mb-4">Quick Statistics</h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600 dark:text-gray-50">Total Users</span>
              <span className="text-sm font-medium text-gray-900 dark:text-white">156</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600 dark:text-gray-50">Active Sessions</span>
              <span className="text-sm font-medium text-gray-900 dark:text-white">23</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600 dark:text-gray-50">Storage Used</span>
              <span className="text-sm font-medium text-gray-900 dark:text-white">2.4 GB</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
