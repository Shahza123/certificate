import React, { useState } from "react";

const RevokeCertificate = () => {
  const [searchTerm, setSearchTerm] = useState("");
  const [certificate, setCertificate] = useState(null);
  const [revoked, setRevoked] = useState(false);

  // Dummy certificate data (you can replace this with API calls)
  const mockCertificate = {
    id: "CERT12345",
    name: "Falak Mushtaque",
    cnic: "12345-6789012-3",
    course: "Blockchain Security",
    issueDate: "2025-06-10",
  };

  const handleSearch = (e) => {
    e.preventDefault();
    // Simulated search by ID or CNIC
    if (
      searchTerm === mockCertificate.id ||
      searchTerm === mockCertificate.cnic
    ) {
      setCertificate(mockCertificate);
    } else {
      setCertificate(null);
      alert("Certificate not found.");
    }
  };

  const handleRevoke = () => {
    // Simulate revoke logic
    setRevoked(true);
    setCertificate(null);
    setSearchTerm("");

    setTimeout(() => setRevoked(false), 3000);
  };

  return (
    <div className="p-4 max-w-2xl mx-auto">
      <h2 className="text-2xl font-bold text-gray-700 mb-6">Revoke Certificate</h2>

      {revoked && (
        <div className="bg-red-100 text-red-700 p-3 rounded mb-4">
          ⚠️ Certificate revoked successfully!
        </div>
      )}

      <form onSubmit={handleSearch} className="mb-4">
        <label className="block text-gray-700 font-medium mb-1">
          Search by Certificate ID or CNIC
        </label>
        <div className="flex gap-2">
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            required
            className="flex-1 border border-gray-300 p-2 rounded focus:outline-gray-950"
            placeholder="Enter Certificate ID or CNIC"
          />
          <button
            type="submit"
            className="bg-gray-800 text-white px-4 py-2 rounded hover:bg-gray-950"
          >
            Search
          </button>
        </div>
      </form>

      {certificate && (
        <div className="bg-white shadow-md rounded p-4 border mt-4">
          <h3 className="text-lg font-bold mb-2">Certificate Found:</h3>
          <p><strong>Name:</strong> {certificate.name}</p>
          <p><strong>CNIC:</strong> {certificate.cnic}</p>
          <p><strong>Course:</strong> {certificate.course}</p>
          <p><strong>Issue Date:</strong> {certificate.issueDate}</p>

          <button
            onClick={handleRevoke}
            className="mt-4 bg-red-600 text-white px-4 py-2 rounded hover:bg-red-800"
          >
            Revoke Certificate
          </button>
        </div>
      )}
    </div>
  );
};

export default RevokeCertificate;
