import axios from 'axios'

const baseURL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:9000/api'

export const api = axios.create({
  baseURL,
  headers: {
    'Content-Type': 'application/json',
  },
})

export function getAuthToken() {
  return localStorage.getItem('sentinelai_token')
}

export function setAuthToken(token) {
  if (token) {
    localStorage.setItem('sentinelai_token', token)
  } else {
    localStorage.removeItem('sentinelai_token')
  }
}

export function getUserId() {
  return localStorage.getItem('sentinelai_user_id')
}

export function setUserSession({ token, userId }) {
  setAuthToken(token)
  if (userId) {
    localStorage.setItem('sentinelai_user_id', userId)
  }
}

export function clearUserSession() {
  localStorage.removeItem('sentinelai_token')
  localStorage.removeItem('sentinelai_user_id')
}

export function isAdmin() {
  const token = getAuthToken()
  if (!token) return false
  try {
    const payload = JSON.parse(atob(token.split('.')[1]))
    return payload.is_admin === true
  } catch {
    return false
  }
}

api.interceptors.request.use((config) => {
  const token = getAuthToken()
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})
