import React from "react";

const activeCerts = [
  {
    id: 1,
    commonName: "device.speedtechlights.com",
    organization: "SpeedTech Lights",
    issuedTo: "Fahad Mehmid",
    issuedOn: "2025-07-24",
    expiryDate: "2026-07-24",
    type: "CA-Signed",
    status: "Active",
  },
  {
    id: 2,
    commonName: "iot.device.local",
    organization: "IoT Devices Inc.",
    issuedTo: "Hassan Raza",
    issuedOn: "2025-02-14",
    expiryDate: "2026-02-14",
    type: "CA-Signed",
    status: "Active",
  },
];

const ActiveCertificates = () => {
  return (
    <div className="p-6">
      <h2 className="text-xl font-bold text-green-700 mb-4">🟢 Active Certificates</h2>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {activeCerts.map((cert) => (
          <div key={cert.id} className="bg-white shadow-md border p-4 rounded-lg">
            <h3 className="text-lg font-semibold text-[#612782]">{cert.commonName}</h3>
            <p><strong>Organization:</strong> {cert.organization}</p>
            <p><strong>Issued To:</strong> {cert.issuedTo}</p>
            <p><strong>Issued On:</strong> {cert.issuedOn}</p>
            <p><strong>Expiry Date:</strong> {cert.expiryDate}</p>
            <p><strong>Type:</strong> {cert.type}</p>
            <span className="inline-block mt-2 text-sm px-2 py-1 bg-green-100 text-green-700 rounded">
              {cert.status}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ActiveCertificates;
