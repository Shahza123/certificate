import React, { useState } from "react";

const AdminPanel = () => {
  const [users, setUsers] = useState([
    { id: 1, name: "Falak Mushtaque", email: "falak@example.com", role: "Admin", active: true },
    { id: 2, name: "Ayesha Khan", email: "ayesha@example.com", role: "User", active: false },
    { id: 3, name: "Bilal Ahmed", email: "bilal@example.com", role: "Moderator", active: true },
    { id: 4, name: "Ali Raza", email: "ali.raza@example.com", role: "User", active: true },
    { id: 5, name: "Zainab Fatima", email: "zainab@example.com", role: "Admin", active: false },
    { id: 6, name: "Hassan Noor", email: "hassan@example.com", role: "User", active: true },
    { id: 7, name: "Mehak Javed", email: "mehak@example.com", role: "Moderator", active: false },
    { id: 8, name: "Usman Tariq", email: "usman@example.com", role: "User", active: true },
  ]);

  const toggleUser = (id) => {
    setUsers((prev) =>
      prev.map((u) => (u.id === id ? { ...u, active: !u.active } : u))
    );
  };

  const getRoleColor = (role) => {
    switch (role) {
      case "Admin":
        return "bg-purple-100 text-purple-800";
      case "User":
        return "bg-blue-100 text-blue-800";
      case "Moderator":
        return "bg-green-100 text-green-800";
      default:
        return "bg-gray-100 text-gray-800";
    }
  };

  return (
    <div className="p-4 max-w-5xl mx-auto">
      <h2 className="text-3xl font-bold text-gray-700 mb-6">Admin Panel</h2>

      <div className="overflow-x-auto bg-white shadow-md rounded-lg">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-700 text-white">
            <tr>
              <th className="px-6 py-3 text-left text-sm font-semibold">User</th>
              <th className="px-6 py-3 text-left text-sm font-semibold">Email</th>
              <th className="px-6 py-3 text-left text-sm font-semibold">Role</th>
              <th className="px-6 py-3 text-left text-sm font-semibold">Status</th>
              <th className="px-6 py-3 text-left text-sm font-semibold">Actions</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-100">
            {users.map((user) => (
              <tr key={user.id} className="hover:bg-gray-50 transition">
                <td className="px-6 py-4 flex items-center space-x-3">
                  <div className="bg-[#eee] text-gray-700 rounded-full h-10 w-10 flex items-center justify-center font-bold uppercase">
                    {user.name.charAt(0)}
                  </div>
                  <span>{user.name}</span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-700">{user.email}</td>
                <td className="px-6 py-4">
                  <span className={`px-3 py-1 text-xs rounded-full font-medium ${getRoleColor(user.role)}`}>
                    {user.role}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm">
                  {user.active ? (
                    <span className="text-green-600 font-semibold">Active</span>
                  ) : (
                    <span className="text-red-500 font-semibold">Disabled</span>
                  )}
                </td>
                <td className="px-6 py-4">
                  <button
                    onClick={() => toggleUser(user.id)}
                    className={`text-xs px-3 py-1 rounded-full transition font-semibold ${
                      user.active
                        ? "bg-red-100 text-red-700 hover:bg-red-200"
                        : "bg-green-100 text-green-700 hover:bg-green-200"
                    }`}
                  >
                    {user.active ? "Disable" : "Enable"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default AdminPanel;
