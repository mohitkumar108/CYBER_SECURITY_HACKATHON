import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ApiProvider } from './context/ApiContext';
import Sidebar from './components/Layout/Sidebar';
import Header from './components/Layout/Header';
import Dashboard from './pages/Dashboard';
import ThreatAnalysis from './pages/ThreatAnalysis';
import Monitoring from './pages/Monitoring';
import Vulnerabilities from './pages/Vulnerabilities';
import Activity from './pages/Activity';
import Settings from './pages/Settings';

function App() {
  return (
    <ApiProvider>
      <Router>
        <div className="flex min-h-screen bg-gray-50">
          <Sidebar />
          <div className="flex-1 flex flex-col">
            <Header />
            <main className="flex-1 p-6">
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/threat-analysis" element={<ThreatAnalysis />} />
                <Route path="/monitoring" element={<Monitoring />} />
                <Route path="/vulnerabilities" element={<Vulnerabilities />} />
                <Route path="/activity" element={<Activity />} />
                <Route path="/settings" element={<Settings />} />
              </Routes>
            </main>
          </div>
        </div>
      </Router>
    </ApiProvider>
  );
}

export default App;
