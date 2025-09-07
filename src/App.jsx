import React, { useState } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import { ThemeProvider } from "./theme/theme-provider";

// Pages
import LogIn from "./pages/LogIn";
import Dashboard from "./pages/Dashboard";



import AdminPanel from "./components/AdminPanel";
import SignUp from "./pages/SignUp";
import NavBar from "./components/layout/NavBar";
import SideBar from "./components/layout/SideBar";
import ViewCertificate from "./pages/ViewCertificate";



import IssueCertificate from "./pages/IssueCertificate";
import Certificates from "./pages/Certificates";
// import { ThemeProvider } from "./theme/theme-provider";

function DashboardLayout() {
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const toggleSidebar = () => setIsSidebarOpen(!isSidebarOpen);
  const sidebarWidth = isSidebarOpen ? 250 : 64;
  
  return (
    <div className="h-screen-full w-full relative bg-gray-100 dark:bg-gray-900">
      <SideBar isOpen={isSidebarOpen} toggleSidebar={toggleSidebar} />
      <div style={{ marginLeft: sidebarWidth }} className="transition-all duration-300">
        <NavBar sidebarWidth={sidebarWidth} />
        <main className="w-full pt-20 min-h-screen px-6">
          <Routes>
            <Route index element={<Dashboard />} />
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="certificates" element={<Certificates />} />
            <Route path="issue" element={<IssueCertificate />} />
            <Route path="validation" element={<ViewCertificate />} />
            <Route path="user-management" element={<AdminPanel />} />
            <Route path="logout" element={<Dashboard />} />
            
            {/* Legacy routes for backward compatibility */}
            
          </Routes>
        </main>
      </div>
    </div>
  );
}

function App() {
  return (
    
    
     

<ThemeProvider>
<Router>
      <Routes>
        {/* All routes are now accessible without authentication */}
        <Route path="/" element={<DashboardLayout />} />
        <Route path="/login" element={<LogIn />} />
        <Route path="/signup" element={<SignUp />} />
        <Route path="/*" element={<DashboardLayout />} />
      </Routes>
    </Router>
</ThemeProvider>
    
  );
}

export default App;
