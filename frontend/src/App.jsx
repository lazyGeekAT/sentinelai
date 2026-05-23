import React from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Login from './auth/Login'
import Register from './auth/Register'
import Dashboard from './dashboard/Dashboard'
import UserTimeline from './dashboard/UserTimeline'
import AdminGuard from './dashboard/AdminGuard'
import { getAuthToken, isAdmin } from './lib/api'
import { useNavigate, useParams } from 'react-router-dom'

function ProtectedRoute({ children }) {
  return getAuthToken() ? children : <Navigate to="/login" replace />
}

function UserTimelineRoute() {
  const navigate = useNavigate()
  const { userId } = useParams()

  return (
    <ProtectedRoute>
      <AdminGuard>
        <UserTimeline
          mode="page"
          userId={userId}
          onClose={() => navigate('/dashboard', { replace: true })}
        />
      </AdminGuard>
    </ProtectedRoute>
  )
}

function RootRedirect() {
  if (!getAuthToken()) return <Navigate to="/login" replace />
  return isAdmin() ? <Navigate to="/dashboard" replace /> : <Navigate to="/events" replace />
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<RootRedirect />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route
          path="/events"
          element={
            <ProtectedRoute>
              <div className="min-h-screen bg-gray-900 flex items-center justify-center text-gray-400">
                Event Platform — under construction
              </div>
            </ProtectedRoute>
          }
        />
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <AdminGuard>
                <Dashboard />
              </AdminGuard>
            </ProtectedRoute>
          }
        />
        <Route
          path="/dashboard/users/:userId/timeline"
          element={<UserTimelineRoute />}
        />
      </Routes>
    </BrowserRouter>
  )
}

export default App
