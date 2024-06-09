import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import HybridEncryptionComponent from './components/hybrid-encryption';
import RsaEncryptionComponent from './components/rsa-encryption'

const App: React.FC = () => {
  return (
    <Router>
      <div>
        <h2>Security Enhancement - WebApp Utility</h2>
        <Routes>
          <Route path="/hybrid" element={<HybridEncryptionComponent />} />

          <Route path="/rsa" element={<RsaEncryptionComponent />} />
        </Routes>
      </div>
    </Router>
  );
};

export default App;
