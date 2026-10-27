import React from 'react';
import { ThemeToggle } from './ThemeToggle';

interface AuthNavbarProps {
  authMode: 'signin' | 'signup' | 'verify-otp' | 'forgot-password';
  setAuthMode: (mode: 'signin' | 'signup' | 'verify-otp' | 'forgot-password') => void;
  theme: 'dark' | 'light';
  onToggleTheme: () => void;
}

export const AuthNavbar: React.FC<AuthNavbarProps> = ({ authMode, setAuthMode, theme, onToggleTheme }) => {
  const toggleAuthMode = () => {
    if (authMode === 'signup') {
      setAuthMode('signin');
      window.history.pushState({}, '', '/login');
    } else {
      setAuthMode('signup');
      window.history.pushState({}, '', '/signup');
    }
  };

  return (
    <header className="auth-navbar-container">
      <div className="auth-navbar-left" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <div className="brand-logo" onClick={() => { setAuthMode('signin'); window.history.pushState({}, '', '/login'); }} style={{ cursor: 'pointer', display: 'flex', alignItems: 'center' }}>
          <img src="/logo.png" alt="SentinelAI Logo" style={{ height: '28px', width: 'auto', marginRight: '8px' }} />
          <span className="brand-name">Sentinel<span className="highlight">AI</span></span>
        </div>
        <ThemeToggle theme={theme} onToggleTheme={onToggleTheme} floating={false} />
      </div>

      <div className="auth-navbar-right">
        <button className="login-trigger-btn" onClick={toggleAuthMode}>
          {authMode === 'signup' ? 'Sign In' : 'Sign Up'}
        </button>
      </div>
    </header>
  );
};

