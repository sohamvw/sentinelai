import React, { useState } from 'react';
import { ThemeToggle } from './ThemeToggle';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  user: any;
  onLogout: () => void;
  theme: 'dark' | 'light';
  onToggleTheme: () => void;
  authMode?: 'signin' | 'signup';
  setAuthMode?: (mode: 'signin' | 'signup') => void;
}

export const Navbar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  user,
  onLogout,
  theme,
  onToggleTheme,
  authMode = 'signin',
  setAuthMode
}) => {
  const [showProfileMenu, setShowProfileMenu] = useState(false);

  const tabs = [
    { id: 'dashboard', label: 'Dashboard', icon: '🚀' },
    { id: 'findings', label: 'Findings', icon: '🛡️' },
    { id: 'audit-logs', label: 'Audit Logs', icon: '📋' },
    { id: 'reports', label: 'Reports', icon: '📄' },
  ];

  const handleAuthButtonClick = () => {
    setActiveTab('auth');
    if (authMode === 'signup') {
      if (setAuthMode) setAuthMode('signin');
      window.location.hash = '#login';
    } else {
      if (setAuthMode) setAuthMode('signup');
      window.location.hash = '#signup';
    }
  };

  return (
    <aside className="sidebar-container">
      <div className="sidebar-header">
        <div className="brand-logo" onClick={() => user ? setActiveTab('dashboard') : setActiveTab('auth')}>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <span className="brand-name">Sentinel<span className="highlight">AI</span></span>
            <span className="brand-tag" style={{ fontSize: '9px', letterSpacing: '1px', opacity: 0.7 }}>SECURITY ENGINE</span>
          </div>
        </div>

        <ThemeToggle theme={theme} onToggleTheme={onToggleTheme} floating={false} />
      </div>

      {user ? (
        <nav className="sidebar-nav">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              className={`sidebar-nav-item ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              <span className="tab-icon">{tab.icon}</span>
              <span className="tab-label">{tab.label}</span>
            </button>
          ))}
        </nav>
      ) : (
        <div className="sidebar-nav">
          <button className="sidebar-nav-item active" onClick={handleAuthButtonClick}>
            <span className="tab-icon">🔑</span>
            <span className="tab-label">{authMode === 'signup' ? 'Sign In' : 'Sign Up'}</span>
          </button>
        </div>
      )}

      <div className="sidebar-footer">
        {user ? (
          <div style={{ position: 'relative', width: '100%' }}>
            {showProfileMenu && (
              <div style={{
                position: 'absolute',
                bottom: '100%',
                left: '0',
                width: '100%',
                marginBottom: '8px',
                background: 'var(--bg-glass)',
                backdropFilter: 'blur(16px)',
                border: '1px solid var(--border-glass)',
                borderRadius: '12px',
                padding: '8px',
                boxShadow: '0 10px 25px rgba(0,0,0,0.5)',
                display: 'flex',
                flexDirection: 'column',
                gap: '4px',
                zIndex: 200
              }}>
                <button
                  onClick={() => { setShowProfileMenu(false); setActiveTab('profile'); }}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    padding: '8px 12px',
                    background: 'transparent',
                    border: 'none',
                    borderRadius: '6px',
                    color: 'var(--text-main)',
                    fontSize: '13px',
                    cursor: 'pointer',
                    width: '100%',
                    textAlign: 'left'
                  }}
                >
                  👤 Profile & Settings
                </button>
                <button
                  onClick={() => { setShowProfileMenu(false); onLogout(); }}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    padding: '8px 12px',
                    background: 'rgba(239, 68, 68, 0.1)',
                    border: '1px solid rgba(239, 68, 68, 0.2)',
                    borderRadius: '6px',
                    color: '#ef4444',
                    fontSize: '13px',
                    fontWeight: 'bold',
                    cursor: 'pointer',
                    width: '100%',
                    textAlign: 'left'
                  }}
                >
                  🚪 Logout
                </button>
              </div>
            )}

            <div
              onClick={() => setShowProfileMenu(!showProfileMenu)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '10px 12px',
                borderRadius: '10px',
                background: 'var(--bg-glass-hover)',
                border: '1px solid var(--border-glass)',
                cursor: 'pointer',
                transition: 'all 0.2s ease'
              }}
            >
              <div style={{
                width: '32px',
                height: '32px',
                borderRadius: '50%',
                background: 'var(--primary-color)',
                color: '#fff',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontWeight: 'bold',
                fontSize: '14px'
              }}>
                {user.first_name?.[0] || 'U'}
              </div>
              <div style={{ flex: 1, overflow: 'hidden' }}>
                <div style={{ fontSize: '13px', fontWeight: 'bold', color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {user.first_name} {user.last_name}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {user.email}
                </div>
              </div>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>▲</span>
            </div>
          </div>
        ) : null}
      </div>
    </aside>
  );
};
