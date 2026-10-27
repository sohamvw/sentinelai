import React, { useState } from 'react';
import { ThemeToggle } from './ThemeToggle';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  user: any;
  onLogout: () => void;
  theme?: 'dark' | 'light';
  onToggleTheme?: () => void;
  isCollapsed?: boolean;
  onToggleCollapse?: () => void;
  isMobileOpen: boolean;
  onCloseMobile: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  user,
  onLogout,
  theme = 'dark',
  onToggleTheme,
  isCollapsed = false,
  isMobileOpen,
  onCloseMobile
}) => {
  const [showProfileMenu, setShowProfileMenu] = useState(false);

  const tabs = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'findings', label: 'Findings' },
    { id: 'audit-logs', label: 'Audit Logs' },
    { id: 'reports', label: 'Reports' },
    { id: 'remediation', label: 'LLM Remediation' },
  ];


  return (
    <>
      {/* Mobile Backdrop */}
      {isMobileOpen && (
        <div
          className="sidebar-backdrop"
          onClick={onCloseMobile}
        />
      )}

      <aside className={`sidebar-container ${isCollapsed ? 'collapsed' : ''} ${isMobileOpen ? 'mobile-open' : ''}`}>
        <div className="sidebar-header">
          <div className="brand-logo-row" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%' }}>
            <div className="brand-logo" onClick={() => setActiveTab('dashboard')}>
              <img src="/logo.png" alt="SentinelAI Logo" style={{ height: '28px', width: 'auto', marginRight: '8px' }} />
              {!isCollapsed && (
                <div className="brand-text">
                  <span className="brand-name">Sentinel<span className="highlight">AI</span></span>
                </div>
              )}
            </div>
            {onToggleTheme && !isCollapsed && (
              <ThemeToggle theme={theme} onToggleTheme={onToggleTheme} floating={false} />
            )}
          </div>
        </div>

        <nav className="sidebar-nav">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              className={`sidebar-nav-item ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => {
                setActiveTab(tab.id);
                if (isMobileOpen) onCloseMobile();
              }}
              title={tab.label}
            >
              {!isCollapsed && <span className="tab-label">{tab.label}</span>}
              {isCollapsed && <span className="tab-label">{tab.label[0]}</span>}
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          {user && (
            <div style={{ position: 'relative', width: '100%' }}>
              {showProfileMenu && (
                <div className="profile-menu-popover">
                  <button
                    onClick={() => { setShowProfileMenu(false); setActiveTab('profile'); if (isMobileOpen) onCloseMobile(); }}
                    className="profile-menu-item"
                  >
                    {!isCollapsed ? 'Profile & Settings' : 'Profile'}
                  </button>
                  <button
                    onClick={() => { setShowProfileMenu(false); onLogout(); }}
                    className="profile-menu-item logout"
                  >
                    {!isCollapsed ? 'Logout' : 'Exit'}
                  </button>
                </div>


              )}

              <div
                className="user-profile-card"
                onClick={() => setShowProfileMenu(!showProfileMenu)}
              >
                <div className="user-avatar">
                  {user.first_name?.[0] || 'U'}
                </div>
                {!isCollapsed && (
                  <div className="user-info">
                    <div className="user-name">{user.first_name} {user.last_name}</div>
                    <div className="user-email">{user.email}</div>
                  </div>
                )}
                {!isCollapsed && <span className="user-caret" aria-hidden="true">{showProfileMenu ? '▲' : '▼'}</span>}
              </div>
            </div>
          )}
        </div>
      </aside>
    </>
  );
};
