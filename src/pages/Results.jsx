import React, { useState } from "react";

const Results = () => {
  const [form, setForm] = useState({
    name: "",
    course: "",
    result: "",
  });

  const [results, setResults] = useState([]);
  const [submitted, setSubmitted] = useState(false);

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    setResults([...results, form]);
    setForm({ name: "", course: "", result: "" });
    setSubmitted(true);
    setTimeout(() => setSubmitted(false), 2000);
  };

  return (
    <div className="p-4 max-w-3xl mx-auto">
      <h2 className="text-2xl font-bold text-gray-700 mb-6">Manage Results</h2>

      {submitted && (
        <div className="bg-green-100 text-green-700 p-3 rounded mb-4">
          ✅ Result saved successfully!
        </div>
      )}

      <form onSubmit={handleSubmit} className="bg-gray-700 p-6 rounded shadow mb-8 space-y-4">
        <div>
          <label className="block text-white font-medium mb-1">Name</label>
          <input
            type="text"
            name="name"
            value={form.name}
            onChange={handleChange}
            required
            className="w-full border border-gray-300 p-2 rounded focus:outline-gray-950"
          />
        </div>

        <div>
          <label className="block text-white font-medium mb-1">Course</label>
          <input
            type="text"
            name="course"
            value={form.course}
            onChange={handleChange}
            required
            className="w-full border border-gray-300 p-2 rounded focus:outline-gray-950"
          />
        </div>

        <div>
          <label className="block text-white font-medium mb-1">Result (e.g. 85%)</label>
          <input
            type="text"
            name="result"
            value={form.result}
            onChange={handleChange}
            required
            className="w-full border border-gray-300 p-2 rounded focus:outline-gray-950"
          />
        </div>

        <button
          type="submit"
          className="bg-gray-800 text-white py-2 px-4 rounded hover:bg-gray-950 transition"
        >
          Submit Result
        </button>
      </form>

      <div className="bg-gray-700 p-4 rounded shadow">
        <h3 className=" text-white text-lg font-bold mb-4">Submitted Results</h3>
        {results.length === 0 ? (
          <p className="text-white">No results added yet.</p>
        ) : (
          <table className="w-full text-left">
            <thead>
              <tr className=" border-b text-gray-700 font-medium">
                <th className="py-2">Name</th>
                <th className="py-2">Course</th>
                <th className="py-2">Result</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r, index) => (
                <tr key={index} className=" text-white border-b hover:bg-gray-800">
                  <td className="py-2">{r.name}</td>
                  <td className="py-2">{r.course}</td>
                  <td className="py-2">{r.result}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default Results;
