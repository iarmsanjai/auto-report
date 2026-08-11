/**
 * frontend/src/services/api.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Axios instance with security controls:
 *
 * 1. JWT stored in sessionStorage (not localStorage) — reduces XSS persistence
 *    window: token is cleared when the browser tab/session is closed.
 *
 * 2. X-Requested-With: XMLHttpRequest header added on every request — the
 *    backend can use this as a CSRF signal alongside SameSite cookie policy.
 *
 * 3. 401 handler clears the token and dispatches a logout event — prevents
 *    the app from silently operating with an expired/invalid token.
 *
 * 4. Error messages surfaced to the UI are taken from server response detail
 *    only if it is a non-500 client error — 500 responses show a generic
 *    message to avoid leaking server internals to the end user.
 */
import axios from 'axios'

const BASE = '/api'

export const TOKEN_KEY = 'vapt_auth_token'

const api = axios.create({
  baseURL: BASE,
  timeout: 30000,
})

// ─── Request interceptor — attach JWT Bearer token + CSRF hint header ─────────
api.interceptors.request.use(config => {
  // sessionStorage: cleared when browser session ends (safer than localStorage
  // which persists indefinitely and is accessible to any JS on the page)
  const token = sessionStorage.getItem(TOKEN_KEY)
  if (token) config.headers.Authorization = `Bearer ${token}`

  // X-Requested-With is a CSRF protection signal — simple requests (e.g., form
  // submits from other origins) cannot set custom headers without CORS preflight
  config.headers['X-Requested-With'] = 'XMLHttpRequest'

  return config
})

// ─── Response interceptor — handle 401 globally ───────────────────────────────
api.interceptors.response.use(
  res => res,
  err => {
    if (err.response?.status === 401) {
      sessionStorage.removeItem(TOKEN_KEY)
      // Notify App.jsx to show login screen
      window.dispatchEvent(new Event('vapt:unauthorized'))
    }
    return Promise.reject(err)
  }
)

/**
 * Extract a safe, user-facing error message from an Axios error.
 * For 5xx errors, returns a generic message to avoid leaking server internals.
 * For 4xx errors, returns the server's detail string (input/validation errors).
 */
export function getErrorMessage(err, fallback = 'An unexpected error occurred. Please try again.') {
  const status = err?.response?.status
  if (!status) return fallback
  // For server errors, return a generic message
  if (status >= 500) return 'A server error occurred. Please try again later.'
  // For client errors, the server detail is safe to surface
  return err?.response?.data?.detail || err?.message || fallback
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

export async function loginUser(username, password) {
  const form = new URLSearchParams()
  form.append('username', username)
  form.append('password', password)
  const { data } = await api.post('/auth/login', form, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return data  // { access_token, token_type, username, role }
}

export async function getMe() {
  const { data } = await api.get('/auth/me')
  return data  // { username, role }
}

export async function changePassword(currentPassword, newPassword) {
  const { data } = await api.post('/auth/change-password', {
    current_password: currentPassword,
    new_password: newPassword,
  })
  return data
}

export async function listUsers() {
  const { data } = await api.get('/auth/admin/users')
  return data
}

export async function createUser(username, password, role) {
  const { data } = await api.post('/auth/admin/users', { username, password, role })
  return data
}

export async function updateUser(username, role, newPassword) {
  const { data } = await api.put(`/auth/admin/users/${username}`, { role, new_password: newPassword })
  return data
}

export async function deleteUser(username) {
  const { data } = await api.delete(`/auth/admin/users/${username}`)
  return data
}

// ─── Import ───────────────────────────────────────────────────────────────────

export async function importCSV(file) {
  const form = new FormData()
  form.append('file', file)
  const { data } = await api.post('/import/csv', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data
}

// Stub for future Snyk / Source Code Review import (coming soon)
export async function importHTML(file) {
  const form = new FormData()
  form.append('file', file)
  const { data } = await api.post('/import/html', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data
}

// ─── Findings ──────────────────────────────────────────────────────────────

export async function validateFindings(findings) {
  const { data } = await api.post('/findings/validate', findings)
  return data
}

export async function getStats(findings) {
  const { data } = await api.post('/findings/stats', findings)
  return data
}

export async function deduplicateFindings(findings) {
  const { data } = await api.post('/findings/deduplicate', findings)
  return data
}

// ─── Export ───────────────────────────────────────────────────────────────────

export async function exportJSON(payload) {
  const { data } = await api.post('/export/json', payload)
  return data
}

export async function exportHTML(payload, template = 'default_report') {
  const { data } = await api.post(`/export/html?template=${encodeURIComponent(template)}`, payload, {
    responseType: 'text',
  })
  return data
}

export async function exportDOCX(payload, template = 'default_report') {
  const { data } = await api.post(`/export/docx?template=${encodeURIComponent(template)}`, payload, {
    responseType: 'blob',
  })
  return data
}

export async function generateAIContent(title, field, currentContent) {
  const { data } = await api.post('/ai/generate',
    { title, field, current_content: currentContent }
  )
  return data
}

export async function saveReportToDB(reportId, meta, findings) {
  const { data } = await api.post(`/reports${reportId ? `?report_id=${encodeURIComponent(reportId)}` : ''}`, { meta, findings })
  return data
}

export async function getReportsFromDB() {
  const { data } = await api.get('/reports')
  return data
}

export async function loadReportFromDB(reportId) {
  const { data } = await api.get(`/reports/${encodeURIComponent(reportId)}`)
  return data
}

export async function deleteReportFromDB(reportId) {
  const { data } = await api.delete(`/reports/${encodeURIComponent(reportId)}`)
  return data
}

export async function updateReportStatus(reportId, status) {
  const { data } = await api.put(`/reports/${encodeURIComponent(reportId)}/status`, { status })
  return data
}

export async function requestEditAccess(reportId) {
  const { data } = await api.put(`/reports/${encodeURIComponent(reportId)}/request_edit`)
  return data
}

export async function approveEditAccess(reportId, requestedBy) {
  const { data } = await api.put(`/reports/${encodeURIComponent(reportId)}/approve_edit`, { requested_by: requestedBy })
  return data
}

export async function previewPDF(payload) {
  const { data } = await api.post('/export/preview', payload, {
    responseType: 'blob',
  })
  return data
}

export async function exportPDF(payload, template = 'default_report') {
  const { data } = await api.post(`/export/pdf?template=${encodeURIComponent(template)}`, payload, {
    responseType: 'blob',
  })
  return data
}

// ─── Misc ─────────────────────────────────────────────────────────────────────

export async function getSampleFindings() {
  const { data } = await api.get('/sample/findings')
  return data
}

export async function getTemplates() {
  const { data } = await api.get('/templates')
  return data
}

export async function checkHealth() {
  const { data } = await api.get('/health')
  return data
}

// ─── Download helpers ─────────────────────────────────────────────────────────

export function downloadBlob(content, filename, mimeType = 'text/plain') {
  const blob = content instanceof Blob
    ? content
    : new Blob([typeof content === 'string' ? content : JSON.stringify(content, null, 2)], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.style.display = 'none'
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  setTimeout(() => {
    URL.revokeObjectURL(url)
  }, 150)
}

export function todayStr() {
  return new Date().toISOString().split('T')[0]
}
