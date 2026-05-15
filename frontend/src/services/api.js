import axios from 'axios'

const BASE = '/api'

export const TOKEN_KEY = 'vapt_auth_token'

const api = axios.create({
  baseURL: BASE,
  timeout: 30000,
})

// ─── Request interceptor — attach JWT Bearer token ────────────────────────────
api.interceptors.request.use(config => {
  const token = localStorage.getItem(TOKEN_KEY)
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// ─── Response interceptor — handle 401 globally ───────────────────────────────
api.interceptors.response.use(
  res => res,
  err => {
    if (err.response?.status === 401) {
      localStorage.removeItem(TOKEN_KEY)
      // Notify App.jsx to show login screen
      window.dispatchEvent(new Event('vapt:unauthorized'))
    }
    return Promise.reject(err)
  }
)

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
  const { data } = await api.post(`/export/html?template=${template}`, payload, {
    responseType: 'text',
  })
  return data
}

export async function exportDOCX(payload, template = 'default_report') {
  const { data } = await api.post(`/export/docx?template=${template}`, payload, {
    responseType: 'blob'
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
  const { data } = await api.post(`/reports${reportId ? `?report_id=${reportId}` : ''}`, { meta, findings })
  return data
}

export async function getReportsFromDB() {
  const { data } = await api.get('/reports')
  return data
}

export async function loadReportFromDB(reportId) {
  const { data } = await api.get(`/reports/${reportId}`)
  return data
}

export async function deleteReportFromDB(reportId) {
  const { data } = await api.delete(`/reports/${reportId}`)
  return data
}

export async function updateReportStatus(reportId, status) {
  const { data } = await api.put(`/reports/${reportId}/status`, { status })
  return data
}

export async function requestEditAccess(reportId) {
  const { data } = await api.put(`/reports/${reportId}/request_edit`)
  return data
}

export async function approveEditAccess(reportId, requestedBy) {
  const { data } = await api.put(`/reports/${reportId}/approve_edit`, { requested_by: requestedBy })
  return data
}

export async function previewHTML(payload) {
  const { data } = await api.post('/export/preview', payload, {
    responseType: 'text',
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
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export function todayStr() {
  return new Date().toISOString().split('T')[0]
}
