import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { useAuth } from './hooks/useAuth';
import { SetupPage } from './pages/SetupPage';
import { LoginPage } from './pages/LoginPage';
import { MainLayout } from './pages/MainLayout';
import { ProxyDetectionToast } from './components/ProxyDetectionToast';

export function App() {
  const { user, loading, needsSetup } = useAuth();
  const { search } = useLocation();

  if (loading || needsSetup === null) {
    return (
      <div className="flex items-center justify-center h-screen bg-surface">
        <div className="text-text-secondary text-lg">Loading...</div>
      </div>
    );
  }

  if (needsSetup) {
    return (
      <Routes>
        <Route path="*" element={<SetupPage />} />
      </Routes>
    );
  }

  if (!user) {
    return (
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        {/* Keep the query string: the SSO callback lands on /?sso_error=… and LoginPage reads it */}
        <Route path="*" element={<Navigate to={{ pathname: '/login', search }} replace />} />
      </Routes>
    );
  }

  // When logged in, redirect "/login" → Root / so the URL doesn't stay as "/login" after auth
  return (
    <>
      <ProxyDetectionToast />
      <Routes>
        <Route path="/login" element={<Navigate to="/" replace />} />
        <Route path="/*" element={<MainLayout />} />
      </Routes>
    </>
  );
}
