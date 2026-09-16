import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Navbar from './components/common/Navbar';
import Sidebar from './components/common/Sidebar';
import ServerConnectionModal from './components/common/ServerConnectionModal';
import NexusLandingPage from './pages/NexusLandingPage';
import AttackGraphPage from './pages/AttackGraphPage';
import AssetInventoryPage from './pages/AssetInventoryPage';
import ThreatsPage from './pages/ThreatsPage';
import SimulationPage from './pages/SimulationPage';

export function App() {
  const [refreshKey, setRefreshKey] = useState(0);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isServerModalOpen, setIsServerModalOpen] = useState(false);

  const handleGlobalRefresh = () => {
    setIsRefreshing(true);
    setRefreshKey((prev) => prev + 1);
    setTimeout(() => {
      setIsRefreshing(false);
    }, 600);
  };

  useEffect(() => {
    const handleUrlChange = () => {
      handleGlobalRefresh();
    };
    window.addEventListener('nexus_server_url_changed', handleUrlChange);
    return () => window.removeEventListener('nexus_server_url_changed', handleUrlChange);
  }, []);

  return (
    <BrowserRouter>
      <div className="flex min-h-screen flex-col bg-[#030508] text-slate-100 font-sans antialiased">
        <Navbar 
          onRefresh={handleGlobalRefresh} 
          isRefreshing={isRefreshing}
          onOpenServerModal={() => setIsServerModalOpen(true)}
        />

        <div className="flex flex-1 overflow-hidden">
          <Sidebar onOpenServerModal={() => setIsServerModalOpen(true)} />

          <main className="flex-1 overflow-y-auto p-6 lg:p-8" key={refreshKey}>
            <div className="mx-auto max-w-7xl">
              <Routes>
                <Route path="/" element={<NexusLandingPage onOpenServerModal={() => setIsServerModalOpen(true)} />} />
                <Route path="/graph" element={<AttackGraphPage onOpenServerModal={() => setIsServerModalOpen(true)} />} />
                <Route path="/assets" element={<AssetInventoryPage onOpenServerModal={() => setIsServerModalOpen(true)} />} />
                <Route path="/threats" element={<ThreatsPage onOpenServerModal={() => setIsServerModalOpen(true)} />} />
                <Route path="/simulate" element={<SimulationPage onOpenServerModal={() => setIsServerModalOpen(true)} />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </div>
          </main>
        </div>

        {/* Server Connection Settings Modal */}
        <ServerConnectionModal
          isOpen={isServerModalOpen}
          onClose={() => setIsServerModalOpen(false)}
          onConnected={() => handleGlobalRefresh()}
        />
      </div>
    </BrowserRouter>
  );
}

export default App;
