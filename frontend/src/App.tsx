import { useState, useEffect } from 'react';
import { AuthNavbar } from './components/AuthNavbar';
import { Sidebar } from './components/Sidebar';
import { AuthPage } from './pages/AuthPage';
import { DashboardPage } from './pages/DashboardPage';
import { FindingsPage } from './pages/FindingsPage';
import { AuditLogsPage } from './pages/AuditLogsPage';
import { ReportViewerPage } from './pages/ReportViewerPage';
import { RemediationPage } from './pages/RemediationPage';
import { ProfilePage } from './pages/ProfilePage';
import { SupportPage } from './pages/SupportPage';
import './index.css';


export function App() {
  const [activeTab, setActiveTab] = useState<string>('auth');
  const [user, setUser] = useState<any>(null);
  const [scanResult, setScanResult] = useState<any>(null);


  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [isMobileOpen, setIsMobileOpen] = useState(false);

  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    return (localStorage.getItem('sentinel_theme') as 'dark' | 'light') || 'dark';
  });

  const [authMode, setAuthMode] = useState<'signin' | 'signup' | 'verify-otp' | 'forgot-password'>('signin');

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('sentinel_theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => (prev === 'dark' ? 'light' : 'dark'));
  };

  useEffect(() => {
    const handleLocationChange = () => {
      const path = window.location.pathname;
      const search = window.location.search;

      // Handle OAuth callback parameters
      if (search.includes('token=') && search.includes('user=')) {
        try {
          const params = new URLSearchParams(search);
          const token = params.get('token');
          const userStr = params.get('user');

          if (token && userStr) {
            const userData = JSON.parse(decodeURIComponent(userStr));
            setUser(userData);
            localStorage.setItem('sentinel_user', JSON.stringify(userData));
            localStorage.setItem('sentinel_token', token);
            setActiveTab('dashboard');
            window.history.pushState({}, '', '/dashboard');
            return;
          }
        } catch (e) {
          console.error('Failed to parse OAuth callback parameters', e);
        }
      }

      if (path === '/signup') {
        setAuthMode('signup');
        setActiveTab('auth');
      } else if (path === '/verify-otp') {
        setAuthMode('verify-otp');
        setActiveTab('auth');
      } else if (path === '/forgot-password') {
        setAuthMode('forgot-password');
        setActiveTab('auth');
      } else if (path === '/login' || path === '/signin') {
        setAuthMode('signin');
        setActiveTab('auth');
      } else if (path === '/dashboard') {
        setActiveTab('dashboard');
      } else if (path === '/findings') {
        setActiveTab('findings');
      } else if (path === '/audit-logs') {
        setActiveTab('audit-logs');
      } else if (path === '/reports') {
        setActiveTab('reports');
      } else if (path === '/remediation') {
        setActiveTab('remediation');
      } else if (path === '/profile') {
        setActiveTab('profile');
      } else if (path === '/support') {
        setActiveTab('support');
      }
    };

    handleLocationChange();
    window.addEventListener('popstate', handleLocationChange);
    return () => window.removeEventListener('popstate', handleLocationChange);
  }, []);


  // Check saved session on startup
  useEffect(() => {
    const savedUser = localStorage.getItem('sentinel_user');
    const savedToken = localStorage.getItem('sentinel_token');

    if (savedUser && savedToken) {
      try {
        setUser(JSON.parse(savedUser));
        if (window.location.pathname === '/' || window.location.pathname === '/login' || window.location.pathname === '/signup') {
          setActiveTab('dashboard');
          window.history.pushState({}, '', '/dashboard');
        }
      } catch (e) {
        localStorage.removeItem('sentinel_user');
        localStorage.removeItem('sentinel_token');
      }
    }
  }, []);

  const navigateTo = (tab: string, path: string) => {
    setActiveTab(tab);
    window.history.pushState({}, '', path);
  };

  const handleAuthSuccess = (userData: any, token: string) => {
    setUser(userData);
    localStorage.setItem('sentinel_user', JSON.stringify(userData));
    localStorage.setItem('sentinel_token', token);
    navigateTo('dashboard', '/dashboard');
  };

  const handleLogout = () => {
    setUser(null);
    localStorage.removeItem('sentinel_user');
    localStorage.removeItem('sentinel_token');
    setActiveTab('auth');
    setAuthMode('signin');
    window.history.pushState({}, '', '/login');
  };


  const handleUpdateUser = (updatedUser: any) => {
    setUser(updatedUser);
    localStorage.setItem('sentinel_user', JSON.stringify(updatedUser));
  };

  const isAuthenticated = user && activeTab !== 'auth';

  const handleTabChange = (tab: string) => {
    setActiveTab(tab);
    const path = tab === 'auth' ? '/login'
      : tab === 'dashboard' ? '/dashboard'
      : tab === 'findings' ? '/findings'
      : tab === 'audit-logs' ? '/audit-logs'
      : tab === 'reports' ? '/reports'
      : tab === 'remediation' ? '/remediation'
      : tab === 'profile' ? '/profile'
      : tab === 'support' ? '/support'
      : `/${tab}`;
    window.history.pushState({}, '', path);
  };

  // 1. AuthLayout (Unauthenticated / Sign In / Sign Up)
  if (!isAuthenticated) {
    return (
      <div className="auth-layout-root">
        <AuthNavbar authMode={authMode} setAuthMode={setAuthMode} theme={theme} onToggleTheme={toggleTheme} />
        <main className="auth-layout-content">
          <AuthPage onSuccess={handleAuthSuccess} initialMode={authMode} setAuthMode={setAuthMode} />
        </main>
      </div>
    );
  }

  // 2. AppLayout (Authenticated Pages with Side-by-Side Sidebar)
  return (
    <div className="app-layout-root">
      <Sidebar
        activeTab={activeTab}
        setActiveTab={handleTabChange}
        user={user}
        onLogout={handleLogout}
        theme={theme}
        onToggleTheme={toggleTheme}
        isCollapsed={isSidebarCollapsed}
        onToggleCollapse={() => setIsSidebarCollapsed(!isSidebarCollapsed)}
        isMobileOpen={isMobileOpen}
        onCloseMobile={() => setIsMobileOpen(false)}
      />


      <main className="main-content-body">
        {activeTab === 'dashboard' && (
          <DashboardPage
            onScanCompleted={(res) => setScanResult(res)}
            setActiveTab={setActiveTab}
          />
        )}
        {activeTab === 'findings' && <FindingsPage scanResult={scanResult} />}
        {activeTab === 'audit-logs' && (
          <AuditLogsPage scanId={scanResult?.scan_id} />
        )}
        {activeTab === 'reports' && <ReportViewerPage scanResult={scanResult} />}
        {activeTab === 'remediation' && <RemediationPage />}
        {activeTab === 'profile' && <ProfilePage user={user} onUpdateUser={handleUpdateUser} />}
        {activeTab === 'support' && <SupportPage user={user} />}
      </main>

    </div>
  );
}

export default App;
