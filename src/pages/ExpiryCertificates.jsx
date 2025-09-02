import React from "react";

const expiredCerts = [
  {
    id: 1,
    commonName: "expired.device.tech.com",
    organization: "Tech Labs",
    issuedTo: "Ali Khan",
    issuedOn: "2022-01-10",
    expiryDate: "2023-01-10",
    type: "Self-Signed",
    status: "Expired",
  },
  {
    id: 2,
    commonName: "secure.webapp.org",
    organization: "SecureWeb Org",
    issuedTo: "Sara Malik",
    issuedOn: "2024-06-01",
    expiryDate: "2025-06-01",
    type: "CA-Signed",
    status: "Expired",
  },
];

const ExpiryCertificates = () => {
  return (
    <div className="p-6">
      <h2 className="text-xl font-bold text-red-700 mb-4">🔴 Expired Certificates</h2>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {expiredCerts.map((cert) => (
          <div key={cert.id} className="bg-white shadow-md border p-4 rounded-lg">
            <h3 className="text-lg font-semibold text-red-700">{cert.commonName}</h3>
            <p><strong>Organization:</strong> {cert.organization}</p>
            <p><strong>Issued To:</strong> {cert.issuedTo}</p>
            <p><strong>Issued On:</strong> {cert.issuedOn}</p>
            <p><strong>Expiry Date:</strong> {cert.expiryDate}</p>
            <p><strong>Type:</strong> {cert.type}</p>
            <span className="inline-block mt-2 text-sm px-2 py-1 bg-red-100 text-red-700 rounded">
              {cert.status}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ExpiryCertificates;
