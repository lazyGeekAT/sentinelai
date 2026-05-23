import { useEffect, useState } from 'react';
import { Navigate } from 'react-router-dom';
import { getAuthToken, isAdmin } from '../lib/api';

export default function AdminGuard({ children }) {
  const [status, setStatus] = useState('checking');

  useEffect(() => {
    if (!getAuthToken()) {
      setStatus('denied');
    } else if (isAdmin()) {
      setStatus('admin');
    } else {
      setStatus('denied');
    }
  }, []);

  if (status === 'checking') {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="w-6 h-6 border-2 border-blue-400/30 border-t-blue-400 rounded-full animate-spin" />
      </div>
    );
  }

  if (status === 'denied') {
    return <Navigate to="/login?error=unauthorized" replace />;
  }

  return children;
}
