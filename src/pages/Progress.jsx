import React, { useState } from "react";

const Progress = () => {
  // Sample data; replace or extend with real data as needed
  const [items] = useState([
    { id: 1, name: "Falak Mushtaque", course: "Blockchain Security", progress: 75 },
    { id: 2, name: "Ayesha Khan", course: "Web Development", progress: 40 },
    { id: 3, name: "Bilal Ahmed", course: "Data Science", progress: 90 },
    { id: 4, name: "Sara Ali", course: "Machine Learning", progress: 55 },
  ]);

  return (
    <div className="p-4 max-w-4xl mx-auto">
      <h2 className="text-2xl font-bold text-gray-700 mb-6">Progress Tracking</h2>
      <div className="space-y-4">
        {items.map((item) => (
          <div key={item.id} className="bg-white shadow rounded-lg p-4">
            <div className="flex justify-between mb-2">
              <div>
                <h3 className="font-semibold">{item.name}</h3>
                <p className="text-sm text-gray-600">{item.course}</p>
              </div>
              <div className="text-sm font-medium">{item.progress}%</div>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-4">
              <div
                className="bg-gray-700 h-4 rounded-full transition-all duration-500"
                style={{ width: `${item.progress}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Progress;
