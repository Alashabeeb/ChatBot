import { useState, useEffect } from 'react';
import { ThemeProvider } from './context/ThemeContext';
import LoginPage from './pages/LoginPage';
import ChatPage from './pages/ChatPage';
import ResolutionGuard from './components/ResolutionGuard';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);
  const [isCheckingAuth, setIsCheckingAuth] = useState(true);

  useEffect(() => {
    const verifyAuth = async () => {
      const token = localStorage.getItem('soc_auth_token');
      if (!token) {
        setIsAuthenticated(false);
        setCurrentUser(null);
        setIsCheckingAuth(false);
        return;
      }

      try {
        const API_URL = window.location.hostname === 'localhost'
          ? 'http://localhost:3002/api/auth/me'
          : `http://${window.location.hostname}:3002/api/auth/me`;

        const res = await fetch(API_URL, {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });

        const data = await res.json();
        if (res.ok && data.success && data.user) {
          setCurrentUser(data.user);
          setIsAuthenticated(true);
        } else {
          // Token invalid / expired
          localStorage.removeItem('soc_auth_token');
          localStorage.removeItem('soc_auth_user');
          setIsAuthenticated(false);
          setCurrentUser(null);
        }
      } catch (err) {
        console.error('Auth verification error:', err);
        // If server is unreachable, check cached user data if token exists
        const cachedUser = localStorage.getItem('soc_auth_user');
        if (cachedUser && token) {
          try {
            setCurrentUser(JSON.parse(cachedUser));
            setIsAuthenticated(true);
          } catch (e) {
            setIsAuthenticated(false);
          }
        } else {
          setIsAuthenticated(false);
        }
      } finally {
        setIsCheckingAuth(false);
      }
    };

    verifyAuth();
  }, []);

  const handleLogin = (user) => {
    setCurrentUser(user);
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    localStorage.removeItem('soc_auth_token');
    localStorage.removeItem('soc_auth_user');
    setCurrentUser(null);
    setIsAuthenticated(false);
  };

  if (isCheckingAuth) {
    return (
      <div style={{
        height: '100vh',
        width: '100vw',
        background: '#030806',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        color: '#10b981',
        fontFamily: 'sans-serif'
      }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{
            width: '32px',
            height: '32px',
            border: '3px solid rgba(16, 185, 129, 0.2)',
            borderTopColor: '#10b981',
            borderRadius: '50%',
            animation: 'spin 0.8s linear infinite',
            margin: '0 auto 12px'
          }} />
          <span>Verifying SOC Credentials...</span>
        </div>
      </div>
    );
  }

  return (
    <ThemeProvider>
      <ResolutionGuard>
        {isAuthenticated ? (
          <ChatPage
            currentUser={currentUser}
            onLogout={handleLogout}
          />
        ) : (
          <LoginPage onLogin={handleLogin} />
        )}
      </ResolutionGuard>
    </ThemeProvider>
  );
}

export default App;
