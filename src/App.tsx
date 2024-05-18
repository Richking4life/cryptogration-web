import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import EncryptionForm from './component/EncryptionForm'

const App: React.FC = () => {
  return (
    <Router>
      <div>
        <h1>React TypeScript App with Anti-Forgery Token</h1>
        <Routes>
          <Route path="/encryption" element={<EncryptionForm />} />
        </Routes>
      </div>
    </Router>
  );
};

export default App;
