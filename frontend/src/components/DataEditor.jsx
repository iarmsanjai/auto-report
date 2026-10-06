import { useState, useEffect, useCallback, useRef, Component } from 'react'
import { generateAIContent, importCSV } from '../services/api'

const EMPTY_FINDING = {
  id: '', title: '', summary: '', description: '', impact: '', recommendation: '',
  cvss: { score: 0, vector: '', level: 'medium' },
  ease: 'Moderate', cwe: '',
  affected_components: [], payload: [],
  poc: '',
  references: [],
  validated: false, false_positive: false, source: 'manual',
  evidence_images: [], device_identifier: '', port_protocol: '',
}

function normalizeHosts(hosts, components) {
  const result = []
  if (Array.isArray(hosts) && hosts.length > 0) {
    hosts.forEach(h => {
      if (typeof h === 'string') {
        if (h.includes(':')) {
          const parts = h.split(':')
          result.push({ ip: parts[0].trim(), port: parts[1].trim(), protocol: 'tcp' })
        } else {
          result.push({ ip: h.trim(), port: '', protocol: '' })
        }
      } else if (h && typeof h === 'object') {
        result.push({ ip: h.ip || '', port: h.port || '', protocol: h.protocol || 'tcp' })
      }
    })
  } else if (Array.isArray(components) && components.length > 0) {
    components.forEach(c => {
      if (typeof c === 'string' && c.includes(':')) {
        const parts = c.split(':')
        result.push({ ip: parts[0].trim(), port: parts[1].trim(), protocol: 'tcp' })
      } else if (c && typeof c === 'object') {
        result.push({ ip: c.ip || '', port: c.port || '', protocol: 'tcp' })
      } else {
        result.push({ ip: String(c || '').trim(), port: '', protocol: '' })
      }
    })
  }
  return result
}

function buildFindingState(initial) {
  if (!initial || !initial.id) {
    return { ...EMPTY_FINDING, id: genId() }
  }
  const cvss = typeof initial.cvss === 'object' && initial.cvss ? initial.cvss : { score: 0, vector: '', level: 'medium' }
  return {
    ...EMPTY_FINDING,
    ...initial,
    cvss: {
      score: cvss.score || 0,
      vector: cvss.vector || '',
      level: (cvss.level || 'medium').toLowerCase(),
    },
    affected_components: Array.isArray(initial.affected_components) ? [...initial.affected_components] : [],
    affected_hosts: normalizeHosts(initial.affected_hosts, initial.affected_components),
    payload: Array.isArray(initial.payload) ? [...initial.payload] : [],
    references: Array.isArray(initial.references) ? [...initial.references] : [],
    evidence_images: Array.isArray(initial.evidence_images) ? [...initial.evidence_images] : [],
  }
}

class EditorErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, errorInfo) {
    console.error('Editor Error Boundary:', error, errorInfo)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="card" style={{ padding: 30, textAlign: 'center', borderColor: 'var(--red)', margin: '20px 0' }}>
          <h3 style={{ color: 'var(--red)', marginBottom: 10 }}>⚠️ Unable to load finding editor</h3>
          <p style={{ fontSize: 12, color: 'var(--dim)', marginBottom: 20 }}>
            An error occurred: {this.state.error?.message}
          </p>
          <button
            className="btn btn-primary"
            onClick={() => {
              this.setState({ hasError: false, error: null })
              if (this.props.onReset) this.props.onReset()
            }}
          >
            ← Return to Report Configuration
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

const SEV_COLORS = { critical: '#e60000', high: '#ff7a00', medium: '#ffcc00', low: '#6b1c4f', info: '#6e6e6e' }

const BUILTIN_TEMPLATES = [
  {
    id: 'tmpl-sqli',
    title: 'SQL Injection (SQLi)',
    summary: 'Application fails to sanitize user input in database queries.',
    cvss: { score: 8.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', level: 'high' },
    ease: 'Trivial',
    cwe: 'CWE-89',
    description: 'The application contains a SQL injection vulnerability where user-supplied input is directly concatenated into database SQL statements without parameterization.',
    poc: "1. Navigate to target form or search input.\n2. Enter payload: ' OR '1'='1 --\n3. Observe database error response or bypass of authentication.",
    recommendation: 'Use parameterized queries (prepared statements) or ORM libraries for database access.',
  },
  {
    id: 'tmpl-xss',
    title: 'Cross-Site Scripting (XSS)',
    summary: 'User input is reflected in HTTP responses without proper output encoding.',
    cvss: { score: 6.1, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', level: 'medium' },
    ease: 'Moderate',
    cwe: 'CWE-79',
    description: 'The application reflects untrusted input back to browser clients without context-aware HTML entity encoding, allowing arbitrary client-side script execution.',
    poc: '1. Access parameter with payload: <script>alert("XSS")</script>\n2. Observe payload execution in client browser context.',
    recommendation: 'Implement context-aware HTML entity encoding on all user inputs before rendering them in response templates.',
  },
  {
    id: 'tmpl-headers',
    title: 'Missing Security Headers',
    summary: 'HTTP response headers miss HSTS, CSP, and X-Frame-Options.',
    cvss: { score: 3.8, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N', level: 'low' },
    ease: 'Trivial',
    cwe: 'CWE-693',
    description: 'The server response does not contain recommended security headers like HSTS, Content-Security-Policy, and X-Frame-Options.',
    poc: 'Inspect response headers using curl -I or browser developer tools.',
    recommendation: 'Configure HTTP response headers: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options.',
  },
  {
    id: 'tmpl-weak-tls',
    title: 'Weak SSL/TLS Configuration',
    summary: 'Server supports outdated TLS versions (TLS 1.0 / 1.1) or weak ciphers.',
    cvss: { score: 5.3, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', level: 'medium' },
    ease: 'Moderate',
    cwe: 'CWE-326',
    description: 'The web server supports legacy protocols (TLS 1.0/1.1) or weak cipher suites vulnerable to cryptographic attacks.',
    poc: 'Run testssl.sh or nmap --script ssl-enum-ciphers -p 443 <target>',
    recommendation: 'Disable TLS 1.0 and TLS 1.1. Enforce TLS 1.2+ with modern AEAD ciphers.',
  },
  {
    id: 'tmpl-csrf',
    title: 'Cross-Site Request Forgery (CSRF)',
    summary: 'State-changing actions lack Anti-CSRF token protection.',
    cvss: { score: 6.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N', level: 'medium' },
    ease: 'Moderate',
    cwe: 'CWE-352',
    description: 'The application allows state-changing requests without checking anti-CSRF tokens or enforcing SameSite cookie attributes.',
    poc: 'Create a cross-origin HTML form submitting to the vulnerable endpoint automatically.',
    recommendation: 'Implement cryptographically strong anti-CSRF tokens for all state-changing HTTP requests.',
  }
]

const TEMPLATE_LS_KEY = 'vapt_custom_vulnerability_templates'

function getSavedTemplates() {
  try {
    const saved = localStorage.getItem(TEMPLATE_LS_KEY)
    const custom = saved ? JSON.parse(saved) : []
    return [...custom, ...BUILTIN_TEMPLATES]
  } catch {
    return BUILTIN_TEMPLATES
  }
}

function saveCustomTemplate(templateObj) {
  try {
    const saved = localStorage.getItem(TEMPLATE_LS_KEY)
    const custom = saved ? JSON.parse(saved) : []
    const idx = custom.findIndex(t => t.title?.toLowerCase() === templateObj.title?.toLowerCase())
    if (idx >= 0) {
      custom[idx] = templateObj
    } else {
      custom.unshift(templateObj)
    }
    localStorage.setItem(TEMPLATE_LS_KEY, JSON.stringify(custom))
  } catch (e) {
    console.error('Failed saving custom template', e)
  }
}

function genId() {
  return 'f' + Math.random().toString(36).slice(2, 9)
}

// ─── Shared field components (defined outside to prevent remount on render) ───
function Field({ label, type = 'text', placeholder = '', value, onChange }) {
  return (
    <div className="form-group">
      <label className="form-label">{label}</label>
      <input
        type={type}
        value={value}
        onChange={onChange}
        className="form-input"
        placeholder={placeholder}
      />
    </div>
  )
}

function TA({ label, rows = 5, mono = false, placeholder = '', value, onChange, onGenerate, generating }) {
  return (
    <div className="form-group">
      <div className="flex items-center justify-between" style={{ marginBottom: 5 }}>
        <label className="form-label" style={{ marginBottom: 0 }}>{label}</label>
        {onGenerate && (
          <button 
            type="button" 
            onClick={onGenerate} 
            disabled={generating}
            style={{ 
              background: 'transparent', border: '1px solid var(--cyan-dim)', borderRadius: 4, padding: '2px 6px',
              color: 'var(--cyan)', fontSize: 9, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
              fontFamily: "'PT Sans', sans-serif", textTransform: 'uppercase', letterSpacing: 0.5
            }}
          >
            {generating ? <span className="spinner" style={{width: 10, height: 10, borderWidth: 1}}/> : '✨'} 
            {generating ? 'Thinking...' : 'AI Suggest'}
          </button>
        )}
      </div>
      <textarea
        value={value}
        onChange={onChange}
        className="form-textarea"
        rows={rows}
        placeholder={placeholder}
        style={mono ? { fontFamily: 'PT Sans, sans-serif', fontSize: 11 } : {}}
      />
    </div>
  )
}

// ─── Report Metadata Form ────────────────────────────────────────────────────
function MetaForm({ meta, setMeta }) {
  const m = meta || {}
  const set = useCallback((k, v) => {
    setMeta(prev => ({ ...(prev || {}), [k]: v }))
  }, [setMeta])

  return (
    <div>
      <div className="flex items-center justify-between mb-20">
        <div className="page-title" style={{ marginBottom: 0 }}>⚙ Report Configuration</div>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          fontSize: 12,
          color: 'var(--green)',
          background: 'rgba(0, 230, 153, 0.08)',
          padding: '6px 14px',
          borderRadius: 20,
          border: '1px solid rgba(0, 230, 153, 0.2)',
          fontWeight: 600
        }}>
          <span className="header-save-dot" />
          <span>✓ Auto-saved in real-time</span>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
        <div className="card">
          <div className="section-label">Client Information</div>
          <Field label="Client Name" value={m.client_name || ''} onChange={e => set('client_name', e.target.value)} placeholder="ACME Corporation" />
          <Field label="Application Name" value={m.application_name || ''} onChange={e => set('application_name', e.target.value)} placeholder="Customer Portal" />
          <Field label="Application Version" value={m.application_version || ''} onChange={e => set('application_version', e.target.value)} placeholder="2.1.0" />
          <div className="form-group">
            <label className="form-label">Testing Approach</label>
            <select value={m.application_approach || 'External'} onChange={e => set('application_approach', e.target.value)} className="form-select">
              {['Internal', 'External', 'Internal/External'].map(o => <option key={o}>{o}</option>)}
            </select>
          </div>
          <Field label="Scoped IPs Count" value={m.scoped_ips_count || ''} onChange={e => set('scoped_ips_count', e.target.value)} placeholder="e.g. 15" />
        </div>

        <div className="card">
          <div className="section-label">Team & Timeline</div>
          <div className="form-group">
            <label className="form-label">Tester Name</label>
            <select
              value={m.tester_name || 'Anish R'}
              onChange={e => set('tester_name', e.target.value)}
              className="form-select"
            >
              {['Anish R', 'Abirami V', 'Samruth Sriram', 'Jonathan', 'Sanjai M', 'Dhanush D'].map(o => (
                <option key={o} value={o}>{o}</option>
              ))}
            </select>
          </div>

          <div className="form-group">
            <label className="form-label">Validator / Reviewer</label>
            <select
              value={m.validator_name || 'Arun Krishna'}
              onChange={e => set('validator_name', e.target.value)}
              className="form-select"
            >
              {['Arun Krishna', 'Vignesh C', 'Samruth Sriram', 'Anish R'].map(o => (
                <option key={o} value={o}>{o}</option>
              ))}
            </select>
          </div>

          <Field label="Document Title" value={m.document_title || ''} onChange={e => set('document_title', e.target.value)} placeholder="Vulnerability Assessment Report" />

          <div className="form-group">
            <label className="form-label">Approved By</label>
            <select
              value={m.approved_by || 'Thanikainathan TS (ISMS Lead Auditor)'}
              onChange={e => set('approved_by', e.target.value)}
              className="form-select"
            >
              {['Thanikainathan TS (ISMS Lead Auditor)'].map(o => (
                <option key={o} value={o}>{o}</option>
              ))}
            </select>
          </div>
          <Field label="Project ID" value={m.project_id || ''} onChange={e => set('project_id', e.target.value)} placeholder={`IARM-${new Date().getFullYear()}-001`} />
          <Field label="Assessment Start Date" type="date" value={m.assessment_startdate || ''} onChange={e => set('assessment_startdate', e.target.value)} />
          <Field label="Assessment End Date" type="date" value={m.assessment_enddate || ''} onChange={e => set('assessment_enddate', e.target.value)} />
          <Field label="Report Delivery Date" type="date" value={m.report_delivery_date || ''} onChange={e => set('report_delivery_date', e.target.value)} />
        </div>

        <div className="card">
          <div className="section-label">Document Dates</div>
          <Field label="Basic Document Date" type="date" value={m.basic_document_date || ''} onChange={e => set('basic_document_date', e.target.value)} />
          <Field label="Draft Document Date" type="date" value={m.draft_document_date || ''} onChange={e => set('draft_document_date', e.target.value)} />
          <Field label="Peer Review Date" type="date" value={m.peer_review_date || ''} onChange={e => set('peer_review_date', e.target.value)} />
        </div>
      </div>
    </div>
  )
}

// ─── Finding Form ─────────────────────────────────────────────────────────────
function FindingForm({ initial, onSave, onCancel, toast }) {
  const isNew = !initial?.id
  const [f, setF] = useState(() => buildFindingState(initial))

  useEffect(() => {
    setF(buildFindingState(initial))
  }, [initial])

  const set = (k, v) => setF(p => ({ ...p, [k]: v }))
  const setCvss = (k, v) => setF(p => ({ ...p, cvss: { ...(p.cvss || { score: 0, vector: '', level: 'medium' }), [k]: v } }))

  const [templates, setTemplates] = useState(() => getSavedTemplates())
  const [tmplSearch, setTmplSearch] = useState('')
  const [showTmplDropdown, setShowTmplDropdown] = useState(false)

  const filteredTemplates = templates.filter(t =>
    t.title?.toLowerCase().includes(tmplSearch.toLowerCase()) ||
    t.cwe?.toLowerCase().includes(tmplSearch.toLowerCase()) ||
    t.summary?.toLowerCase().includes(tmplSearch.toLowerCase())
  )

  const applyTemplate = (tmpl) => {
    setF(prev => ({
      ...prev,
      title: tmpl.title || prev.title,
      summary: tmpl.summary || prev.summary,
      cvss: tmpl.cvss ? { ...tmpl.cvss } : prev.cvss,
      ease: tmpl.ease || prev.ease,
      cwe: tmpl.cwe || prev.cwe,
      description: tmpl.description || prev.description,
      poc: tmpl.poc || prev.poc,
      recommendation: tmpl.recommendation || prev.recommendation,
      device_identifier: tmpl.device_identifier || prev.device_identifier,
      port_protocol: tmpl.port_protocol || prev.port_protocol,
    }))
    setTmplSearch('')
    setShowTmplDropdown(false)
    toast(`Template "${tmpl.title}" loaded ✓`)
  }

  const handleAddToTemplate = () => {
    if (!f.title?.trim()) {
      toast('Please enter a Title before saving as a template', 'warn')
      return
    }
    const newTmpl = {
      id: 'custom-' + Date.now(),
      title: f.title,
      summary: f.summary || '',
      cvss: f.cvss ? { ...f.cvss } : { score: 5.0, level: 'medium' },
      ease: f.ease || 'Moderate',
      cwe: f.cwe || '',
      description: f.description || '',
      poc: f.poc || '',
      recommendation: f.recommendation || '',
      device_identifier: f.device_identifier || '',
      port_protocol: f.port_protocol || '',
    }
    saveCustomTemplate(newTmpl)
    setTemplates(getSavedTemplates())
    toast(`Saved "${f.title}" to Vulnerability Template Library ✓`)
  }

  const save = () => {
    if (!f.title?.trim()) {
      toast('Title is required', 'error')
      return
    }
    onSave(f)
    toast(isNew ? 'Finding added ✓' : 'Finding updated ✓')
  }

  const [generatingField, setGeneratingField] = useState(null)

  const askAI = async (field) => {
    if (!f.title?.trim()) {
      toast('Please enter a Title first so the AI knows what to generate.', 'warn')
      return
    }
    setGeneratingField(field)
    try {
      const result = await generateAIContent(f.title, field, f[field] || '')
      set(field, result.content)
      toast(`AI generated ${field} ✓`)
    } catch (err) {
      if (err?.response?.status === 401) {
        toast('Authentication error. Please try again.', 'error')
      } else {
        toast('AI Generation failed. Check backend logs.', 'error')
      }
    } finally {
      setGeneratingField(null)
    }
  }

  // TA is now a top-level component; used with explicit value/onChange below

  const sevColor = SEV_COLORS[f.cvss?.level] || '#6e6e6e'

  return (
    <div>
      <div className="flex items-center justify-between mb-20">
        <div className="page-title" style={{ marginBottom: 0 }}>
          {isNew ? '+ Add Finding' : '✎ Edit Finding'}
          {!isNew && <span style={{ fontSize: 12, color: 'var(--dim)', marginLeft: 14, fontFamily: 'PT Sans, sans-serif' }}>{f.title}</span>}
        </div>
        <div className="flex gap-12 items-center">
          <button
            type="button"
            className="btn btn-sm"
            style={{ borderColor: 'var(--cyan-dim)', color: 'var(--cyan)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}
            onClick={handleAddToTemplate}
            title="Save current finding into Vulnerability Template Library"
          >
            🔖 Add to Template
          </button>
          <button className="btn btn-primary" onClick={save}>{isNew ? '+ Add Finding' : '✓ Save Finding'}</button>
          <button className="btn" onClick={onCancel}>Cancel</button>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
        {/* Vulnerability Template Library Search */}
        <div className="card" style={{ background: 'var(--bg2)', border: '1px solid var(--cyan-dim)' }}>
          <div className="flex items-center justify-between" style={{ marginBottom: 10 }}>
            <div style={{ fontWeight: 700, fontSize: 13, color: 'var(--cyan)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <span>📚 Vulnerability Template Library</span>
              <span style={{ fontSize: 10, color: 'var(--dim)', fontWeight: 400 }}>(Search & click to auto-fill current finding)</span>
            </div>
            <span style={{ fontSize: 11, color: 'var(--dim)' }}>{templates.length} Templates</span>
          </div>

          <div style={{ position: 'relative' }}>
            <input
              type="text"
              className="form-input"
              placeholder="🔍 Search vulnerability templates (e.g. SQL Injection, XSS, Security Headers, CSRF)..."
              value={tmplSearch}
              onChange={e => { setTmplSearch(e.target.value); setShowTmplDropdown(true) }}
              onFocus={() => setShowTmplDropdown(true)}
            />

            {showTmplDropdown && (
              <div style={{
                position: 'absolute',
                top: '100%',
                left: 0,
                right: 0,
                zIndex: 100,
                background: 'var(--bg)',
                border: '1px solid var(--cyan-dim)',
                borderRadius: 8,
                maxHeight: 280,
                overflowY: 'auto',
                boxShadow: '0 8px 24px rgba(0,0,0,0.6)',
                marginTop: 4
              }}>
                <div className="flex items-center justify-between" style={{ padding: '6px 12px', background: 'var(--bg2)', borderBottom: '1px solid var(--border)', fontSize: 10, color: 'var(--dim)' }}>
                  <span>SELECT A TEMPLATE TO PRE-FILL</span>
                  <button type="button" onClick={() => setShowTmplDropdown(false)} style={{ background: 'none', border: 'none', color: 'var(--dim)', cursor: 'pointer' }}>✕ Close</button>
                </div>

                {filteredTemplates.length === 0 ? (
                  <div style={{ padding: 14, fontSize: 11, color: 'var(--dim)', fontStyle: 'italic' }}>
                    No templates matching "{tmplSearch}"
                  </div>
                ) : (
                  filteredTemplates.map(tmpl => (
                    <div
                      key={tmpl.id}
                      onClick={() => applyTemplate(tmpl)}
                      style={{
                        padding: '10px 14px',
                        borderBottom: '1px solid var(--border)',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        transition: 'background 0.12s',
                      }}
                      onMouseEnter={e => e.currentTarget.style.background = 'rgba(0, 212, 255, 0.08)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    >
                      <div>
                        <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--text)' }}>
                          {tmpl.title} {tmpl.cwe && <span style={{ fontSize: 10, color: 'var(--dim)', marginLeft: 6 }}>({tmpl.cwe})</span>}
                        </div>
                        {tmpl.summary && <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 2 }}>{tmpl.summary}</div>}
                      </div>
                      <span className={`sev-badge sev-${tmpl.cvss?.level || 'info'}`} style={{ textTransform: 'capitalize', fontSize: 10 }}>
                        {tmpl.cvss?.level || 'info'}
                      </span>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        </div>

        {/* Basic Information */}
        <div className="card">
          <div className="section-label">Basic Information</div>
          <div className="form-group">
            <label className="form-label">Title *</label>
            <input value={f.title || ''} onChange={e => set('title', e.target.value)} className="form-input" placeholder="e.g. SQL Injection — Login Form" />
          </div>
          <div className="form-group">
            <label className="form-label">One-line Summary</label>
            <input value={f.summary || ''} onChange={e => set('summary', e.target.value)} className="form-input" placeholder="Brief description for the findings table" />
          </div>
          <div className="grid-2">
            <div className="form-group">
              <label className="form-label">Severity *</label>
              <select value={f.cvss?.level || 'medium'} onChange={e => setCvss('level', e.target.value)} className="form-select">
                {['critical', 'high', 'medium', 'low'].map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">Ease of Exploit</label>
              <select value={f.ease || 'Moderate'} onChange={e => set('ease', e.target.value)} className="form-select">
                {['Trivial', 'Moderate', 'Difficult'].map(o => <option key={o}>{o}</option>)}
              </select>
            </div>
          </div>
          
          <div className="grid-2" style={{ marginTop: 12 }}>
            <div className="form-group">
              <label className="form-label">Device Identifier (Type)</label>
              <input value={f.device_identifier || ''} onChange={e => set('device_identifier', e.target.value)} className="form-input" placeholder="e.g. firewall, router, server" />
            </div>
            <div className="form-group">
              <label className="form-label">Port / Protocol Summary</label>
              <input value={f.port_protocol || ''} onChange={e => set('port_protocol', e.target.value)} className="form-input" placeholder="e.g. 443/tcp, 80/http" />
            </div>
          </div>
        </div>

        {/* Finding Details */}
        <div className="card">
          <div className="section-label">Finding Details</div>
          <TA label="Description * — explain the vulnerability" rows={6} placeholder="Describe the vulnerability, root cause, and affected code/endpoint..." value={f.description || ''} onChange={e => set('description', e.target.value)} onGenerate={() => askAI('description')} generating={generatingField === 'description'} />
          <TA label="Proof of Concept — steps to reproduce" rows={6} mono placeholder="Step 1: Navigate to /endpoint&#10;Step 2: Inject payload: ' OR 1=1--&#10;Step 3: Observe 200 OK response..." value={f.poc || ''} onChange={e => set('poc', e.target.value)} onGenerate={() => askAI('poc')} generating={generatingField === 'poc'} />
          <TA label="Recommendation * — how to fix" rows={5} placeholder="Use parameterized queries. Implement input validation..." value={f.recommendation || ''} onChange={e => set('recommendation', e.target.value)} onGenerate={() => askAI('recommendation')} generating={generatingField === 'recommendation'} />
        </div>

        {/* Affected Endpoints */}
        <div className="card">
          <div className="section-label flex items-center justify-between" style={{ marginBottom: 10 }}>
            <span>🌐 Affected Endpoints (IP & Port)</span>
            <button
              type="button"
              className="btn btn-sm"
              style={{ fontSize: 10, padding: '2px 8px' }}
              onClick={() => setF(p => ({ ...p, _bulkEndpoints: !p._bulkEndpoints }))}
            >
              {f._bulkEndpoints ? '📱 IP & Port Fields' : '📝 Bulk Paste View'}
            </button>
          </div>

          {f._bulkEndpoints ? (
            <div>
              <div style={{ fontSize: 11, color: 'var(--dim)', marginBottom: 6 }}>
                Enter endpoints as <code>IP:Port</code> (one per line):
              </div>
              <textarea
                value={(f.affected_components && f.affected_components.length > 0)
                  ? f.affected_components.join('\n')
                  : (f.affected_hosts || []).map(h => h.port ? `${h.ip}:${h.port}` : h.ip).filter(Boolean).join('\n')}
                onChange={e => {
                  const lines = e.target.value.split('\n').map(l => l.trim()).filter(Boolean)
                  const hosts = lines.map(line => {
                    if (line.includes(':')) {
                      const parts = line.split(':')
                      return { ip: parts[0].trim(), port: parts[1].trim(), protocol: 'tcp' }
                    }
                    return { ip: line, port: '', protocol: '' }
                  })
                  setF(p => ({ ...p, affected_components: lines, affected_hosts: hosts }))
                }}
                className="form-textarea"
                rows={5}
                placeholder={'192.168.0.1: 55\n192.168.0.5: 66\n192.168.0.1: 32\n192.168.0.1: 45\n192.168.0.2: 23'}
                style={{ fontFamily: 'PT Sans, sans-serif', fontSize: 11 }}
              />
            </div>
          ) : (
            <div>
              {(f.affected_hosts || []).length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 12 }}>
                  {f.affected_hosts.map((h, idx) => (
                    <div key={idx} className="flex items-center gap-8" style={{ background: 'var(--bg2)', padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border)' }}>
                      <span style={{ fontSize: 10, color: 'var(--cyan)', fontWeight: 600 }}>IP:</span>
                      <input
                        className="form-input"
                        style={{ padding: '3px 8px', fontSize: 11, flex: 2 }}
                        value={h.ip || ''}
                        placeholder="192.168.0.1"
                        onChange={e => {
                          const newHosts = [...(f.affected_hosts || [])]
                          newHosts[idx] = { ...newHosts[idx], ip: e.target.value }
                          const comps = newHosts.map(x => x.port ? `${x.ip}:${x.port}` : x.ip).filter(Boolean)
                          setF(p => ({ ...p, affected_hosts: newHosts, affected_components: comps }))
                        }}
                      />
                      <span style={{ fontSize: 10, color: 'var(--cyan)', fontWeight: 600 }}>Port:</span>
                      <input
                        className="form-input"
                        style={{ padding: '3px 8px', fontSize: 11, width: 90 }}
                        value={h.port || ''}
                        placeholder="55"
                        onChange={e => {
                          const newHosts = [...(f.affected_hosts || [])]
                          newHosts[idx] = { ...newHosts[idx], port: e.target.value }
                          const comps = newHosts.map(x => x.port ? `${x.ip}:${x.port}` : x.ip).filter(Boolean)
                          setF(p => ({ ...p, affected_hosts: newHosts, affected_components: comps }))
                        }}
                      />
                      <button
                        type="button"
                        className="btn btn-sm btn-danger"
                        style={{ padding: '3px 7px', fontSize: 10 }}
                        onClick={() => {
                          const newHosts = f.affected_hosts.filter((_, i) => i !== idx)
                          const comps = newHosts.map(x => x.port ? `${x.ip}:${x.port}` : x.ip).filter(Boolean)
                          setF(p => ({ ...p, affected_hosts: newHosts, affected_components: comps }))
                        }}
                      >
                        ✕
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ fontSize: 11, color: 'var(--dim)', marginBottom: 10, fontStyle: 'italic' }}>
                  No IP & Port endpoints configured.
                </div>
              )}
              <button
                type="button"
                className="btn btn-sm"
                style={{ borderColor: 'var(--cyan)', color: 'var(--cyan)', fontSize: 11 }}
                onClick={() => {
                  const newHosts = [...(f.affected_hosts || []), { ip: '192.168.0.1', port: '80', protocol: 'tcp' }]
                  const comps = newHosts.map(x => x.port ? `${x.ip}:${x.port}` : x.ip).filter(Boolean)
                  setF(p => ({ ...p, affected_hosts: newHosts, affected_components: comps }))
                }}
              >
                + Add IP & Port
              </button>
            </div>
          )}
        </div>

        {/* Preview chip */}
        <div className="card" style={{ borderColor: `${sevColor}33`, background: `${sevColor}08` }}>
          <div className="section-label">Preview</div>
          <div className="flex items-center gap-8" style={{ marginBottom: 8 }}>
            <span className={`sev-badge sev-${f.cvss?.level || 'info'}`}>{f.cvss?.level || 'info'}</span>
            {f.cvss?.score > 0 && <span style={{ fontSize: 11, color: 'var(--dim)' }}>CVSS {f.cvss.score}</span>}
            {f.ease && <span style={{ fontSize: 11, color: 'var(--dim)' }}>· {f.ease}</span>}
            {f.cwe && <span style={{ fontSize: 11, color: 'var(--dim)' }}>· {f.cwe}</span>}
          </div>
          <div style={{ fontWeight: 700, color: 'var(--text)', fontSize: 13 }}>
            {f.title || <span style={{ color: 'var(--muted)' }}>Title not set</span>}
          </div>
          {f.summary && <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 4 }}>{f.summary}</div>}
        </div>
      </div>
    </div>
  )
}

function EditorImportPanel({ findings, setFindings, toast, onSuccess }) {
  const [drag, setDrag] = useState(false)
  const [loading, setLoading] = useState(false)
  const [preview, setPreview] = useState(null)
  const fileRef = useRef()

  const processFiles = async (files) => {
    const validFiles = []
    for (const file of files) {
      const ext = file.name.split('.').pop().toLowerCase()
      if (ext !== 'csv') {
        toast(`Skipped '${file.name}': Nessus import requires a .csv file`, 'warn')
      } else {
        validFiles.push(file)
      }
    }

    if (validFiles.length === 0) return

    setLoading(true)
    setPreview(null)

    let allFindings = []
    let fileNames = []
    let successCount = 0

    try {
      for (const file of validFiles) {
        const result = await importCSV(file)
        if (result.count > 0) {
          allFindings = [...allFindings, ...result.findings]
          fileNames.push(file.name)
          successCount++
        } else {
          toast(`No findings found in ${file.name}`, 'warn')
        }
      }

      if (successCount === 0) {
        toast('No findings were extracted.', 'warn')
        return
      }

      setPreview({
        names: fileNames.join(', '),
        count: allFindings.length,
        findings: allFindings,
      })
      toast(`Extracted ${allFindings.length} findings from ${successCount} file(s)`)
    } catch (err) {
      toast(err?.response?.data?.detail || 'Upload failed — check backend status.', 'error')
    } finally {
      setLoading(false)
    }
  }

  const onDrop = (e) => {
    e.preventDefault()
    setDrag(false)
    const files = Array.from(e.dataTransfer.files)
    if (files.length > 0) processFiles(files)
  }

  const handleMerge = () => {
    if (!preview) return
    setFindings(prev => [...prev, ...preview.findings])
    toast(`Merged ${preview.findings.length} findings into current project ✓`)
    setPreview(null)
    onSuccess()
  }

  return (
    <div className="card" style={{ maxWidth: 650, margin: '0 auto', padding: 24 }}>
      <div className="section-label" style={{ marginBottom: 12 }}>↑ Add Scanner CSV to Active Project</div>
      <p style={{ fontSize: 12, color: 'var(--dim)', marginBottom: 20 }}>
        Upload one or more Nessus CSV files to extract and merge findings into your current active project session.
      </p>

      <div
        onDragOver={e => { e.preventDefault(); setDrag(true) }}
        onDragLeave={() => setDrag(false)}
        onDrop={onDrop}
        onClick={() => !preview && fileRef.current?.click()}
        style={{
          border: '2px dashed var(--border)',
          borderRadius: 8,
          padding: '30px 20px',
          textAlign: 'center',
          background: drag ? 'rgba(0,212,255,0.05)' : 'var(--bg)',
          borderColor: drag ? 'var(--cyan)' : 'var(--border)',
          cursor: preview ? 'default' : 'pointer',
          transition: 'all 0.15s',
          marginBottom: 20
        }}
      >
        {loading ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
            <div className="spinner" style={{ width: 28, height: 28 }} />
            <div style={{ fontSize: 12, color: 'var(--dim)' }}>Parsing CSV data...</div>
          </div>
        ) : preview ? (
          <div>
            <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text)', marginBottom: 12 }}>
              Ready to merge: {preview.count} findings from {preview.names}
            </div>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'center' }}>
              <button className="btn btn-success btn-sm" onClick={handleMerge}>
                + Merge findings
              </button>
              <button className="btn btn-sm" onClick={() => setPreview(null)}>
                ✕ Clear
              </button>
            </div>
          </div>
        ) : (
          <div>
            <div style={{ fontSize: 32, marginBottom: 8, opacity: 0.5 }}>🛡</div>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', marginBottom: 4 }}>
              Drag CSV files here or click to browse
            </div>
            <div style={{ fontSize: 11, color: 'var(--dim)' }}>Accepts Nessus .csv format</div>
          </div>
        )}

        <input
          ref={fileRef}
          type="file"
          multiple
          accept=".csv"
          style={{ display: 'none' }}
          onChange={e => e.target.files && processFiles(Array.from(e.target.files))}
        />
      </div>
    </div>
  )
}

// ─── DataEditor wrapper — toggles meta config vs finding form ─────────────────
export default function DataEditor({ meta, setMeta, findings, setFindings, editTarget, setEditTarget, toast }) {
  const [activeTab, setActiveTab] = useState(editTarget ? 'finding' : 'meta')

  useEffect(() => {
    if (editTarget) {
      setActiveTab('finding')
    }
  }, [editTarget])

  const handleSave = (f) => {
    if (editTarget?.id) {
      setFindings(prev => prev.map(x => x.id === f.id ? f : x))
    } else {
      setFindings(prev => [...prev, f])
    }
    setEditTarget(null)
    setActiveTab('meta')
  }

  const handleCancel = () => {
    setEditTarget(null)
    setActiveTab('meta')
  }

  const startNew = () => {
    setEditTarget(null)
    setActiveTab('finding')
  }

  return (
    <div>
      {/* Tab bar */}
      <div className="flex gap-4 mb-20" style={{ borderBottom: '1px solid var(--border)', paddingBottom: 0 }}>
        {[
          { id: 'meta', label: '⚙ Report Config' },
          { id: 'finding', label: editTarget ? '✎ Edit Finding' : '+ Add Finding' },
          { id: 'import_csv', label: '↑ Import CSV' },
        ].map(t => (
          <button
            key={t.id}
            onClick={() => { if (t.id !== 'finding') setEditTarget(null); setActiveTab(t.id) }}
            style={{
              background: 'transparent',
              border: 'none',
              borderBottom: `2px solid ${activeTab === t.id ? 'var(--cyan)' : 'transparent'}`,
              color: activeTab === t.id ? 'var(--cyan)' : 'var(--dim)',
              padding: '8px 16px',
              cursor: 'pointer',
              fontFamily: "'PT Sans', sans-serif",
              fontSize: 12,
              fontWeight: activeTab === t.id ? 600 : 400,
              marginBottom: -1,
              transition: 'all 0.12s',
            }}
          >
            {t.label}
          </button>
        ))}
        <button className="btn btn-success btn-sm" style={{ marginLeft: 'auto' }} onClick={startNew}>
          + New Finding
        </button>
      </div>

      {activeTab === 'meta' && (
        <EditorErrorBoundary>
          <MetaForm meta={meta} setMeta={setMeta} toast={toast} />
        </EditorErrorBoundary>
      )}
      {activeTab === 'finding' && (
        <EditorErrorBoundary onReset={handleCancel}>
          <FindingForm
            key={editTarget?.id || 'new_finding'}
            initial={editTarget}
            onSave={handleSave}
            onCancel={handleCancel}
            toast={toast}
          />
        </EditorErrorBoundary>
      )}
      {activeTab === 'import_csv' && (
        <EditorImportPanel
          findings={findings}
          setFindings={setFindings}
          toast={toast}
          onSuccess={() => setActiveTab('meta')}
        />
      )}
    </div>
  )
}
