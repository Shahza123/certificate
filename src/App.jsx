import React, { useState } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import { ThemeProvider } from "./theme/theme-provider";

// Pages
import LogIn from "./pages/LogIn";
import Dashboard from "./pages/Dashboard";
import RevokeCertificate from "./pages/RevokeCertificate";
import Progress from "./pages/Progress";
import Results from "./pages/Results";
import AdminPanel from "./components/AdminPanel";
import SignUp from "./pages/SignUp";
import NavBar from "./components/layout/NavBar";
import SideBar from "./components/layout/SideBar";
import ViewCertificate from "./pages/ViewCertificate";
import PreViewCertificate from "./pages/PreViewCertificate";
import ActiveCertificates from "./pages/ActiveCertificates";
import ExpiryCertificates from "./pages/ExpiryCertificates";
import IssueCertificate from "./pages/IssueCertificate";
import Certificates from "./pages/Certificates";
// import { ThemeProvider } from "./theme/theme-provider";

function DashboardLayout() {
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const toggleSidebar = () => setIsSidebarOpen(!isSidebarOpen);
  const sidebarWidth = isSidebarOpen ? 250 : 64;
  
  return (
    <div className="h-screen w-screen relative bg-white dark:bg-gray-900">
      <SideBar isOpen={isSidebarOpen} toggleSidebar={toggleSidebar} />
      <div style={{ marginLeft: sidebarWidth }} className="transition-all duration-300">
        <NavBar sidebarWidth={sidebarWidth} />
        <main className="w-full pt-20 min-h-screen">
          <Routes>
            <Route index element={<Dashboard />} />
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="certificates" element={<Certificates />} />
            <Route path="issue" element={<IssueCertificate />} />
            <Route path="validation" element={<ViewCertificate />} />
            <Route path="user-management" element={<AdminPanel />} />
            <Route path="logout" element={<Dashboard />} />
            
            {/* Legacy routes for backward compatibility */}
            <Route path="revoke" element={<RevokeCertificate />} />
            <Route path="progress" element={<Progress />} />
            <Route path="results" element={<Results />} />
            <Route path="view-certificate" element={<ViewCertificate />} />
            <Route path="active-certificates" element={<ActiveCertificates/>} />
            <Route path="expiry-certificates" element={<ExpiryCertificates />} />
            <Route path="preview-certificate" element={<PreViewCertificate />} />
            <Route path="admin" element={<AdminPanel />} />
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
