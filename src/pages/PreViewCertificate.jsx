import React, { useRef } from 'react';
import html2canvas from 'html2canvas';
import jsPDF from 'jspdf';

const DynamicCertificateWithPDF = ({
  recipient = "Falak Mushtaque",
  course = "Web-Based Digital Management",
  dateIssued = "July 28, 2025",
  certificateId = "IDH-28D59728",
  director = "Dr. Arif Husen",
  organization = "Virtual University Of Pakistan"
}) => {
  const certRef = useRef();

  const downloadPDF = async () => {
    const canvas = await html2canvas(certRef.current, { scale: 2 });
    const imgData = canvas.toDataURL('image/png');
    const pdf = new jsPDF('landscape', 'pt', [canvas.width, canvas.height]);
    pdf.addImage(imgData, 'PNG', 0, 0, canvas.width, canvas.height);
    pdf.save('certificate.pdf');
  };

  return (
    <div className="flex flex-col items-center justify-center bg-gray-100 min-h-screen py-10 px-4">
      <div
        ref={certRef}
        className="bg-white p-10 w-full max-w-3xl shadow-md border border-gray-400 relative"
      >
        {/* Outer black border */}
        <div className="border-2 border-black p-10 text-center relative">

          {/* Watermark in background */}
          <div className="absolute bottom-20 right-10 opacity-10 z-0">
           <svg
    xmlns="http://www.w3.org/2000/svg"
    className="w-32 h-32"
    fill="none"
    viewBox="0 0 24 24"
    stroke="currentColor"
    strokeWidth={1.5}
  >
    {/* Graduation Cap Icon */}
    <path strokeLinecap="round" strokeLinejoin="round" d="M12 14l9-5-9-5-9 5 9 5z" />
    <path strokeLinecap="round" strokeLinejoin="round" d="M12 14v7" />
    <path strokeLinecap="round" strokeLinejoin="round" d="M3 9v6a9 9 0 009 9" />
  </svg>
          </div>

          {/* Certificate Text */}
          <div className="relative z-10">
            <h1 className="text-2xl font-extrabold text-gray-900 uppercase mb-6">
              Certificate of Completion
            </h1>

            <p className="text-gray-700 mb-2">This certifies that</p>
            <h2 className="text-xl font-bold text-blue-900 mb-2">{recipient}</h2>
            <p className="text-gray-700 mb-2">
              has successfully completed the professional certification in
            </p>
            <p className="italic font-semibold text-gray-800 text-lg mb-8">
              {course}
            </p>

            {/* Dashed divider */}
            <div className="border-t border-dashed my-8"></div>

            {/* Footer Info */}
            <div className="flex justify-between text-sm text-gray-700 mt-4">
              <div className="text-left">
                <p className="font-semibold">{director}</p>
                <p>Director of Training</p>
                <p>{organization}</p>
              </div>
              <div className="text-right">
                <p>Date Issued: {dateIssued}</p>
                <p>Certificate ID: ID#: {certificateId}</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Download PDF Button */}
      <button
        onClick={downloadPDF}
        className="mt-6 bg-gray-800 hover:bg-black text-white font-medium px-5 py-2 rounded shadow print:hidden"
      >
        Download Certificate (PDF)
      </button>
    </div>
  );
};

export default DynamicCertificateWithPDF;
