import { useState } from 'react';
import { ThemeProvider } from './context/ThemeContext';
import LoginPage from './pages/LoginPage';
import ChatPage from './pages/ChatPage';
import ResolutionGuard from './components/ResolutionGuard';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  return (
    <ThemeProvider>
      <ResolutionGuard>
        {isAuthenticated ? (
          <ChatPage onLogout={() => setIsAuthenticated(false)} />
        ) : (
          <LoginPage onLogin={() => setIsAuthenticated(true)} />
        )}
      </ResolutionGuard>
    </ThemeProvider>
  );
}

export default App;
