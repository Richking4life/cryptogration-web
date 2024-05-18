import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import EncryptionForm from './component/EncryptionForm'

const App: React.FC = () => {
  return (
    <Router>
      <div>
        <h2>Security Enhancement - WebApp Utility</h2>
        <Routes>
          <Route path="/encryption" element={<EncryptionForm />} />
        </Routes>
      </div>
    </Router>
  );
};

export default App;
