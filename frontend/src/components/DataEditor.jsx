import { useState, useCallback, useRef } from 'react'
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

const SEV_COLORS = { critical: '#e60000', high: '#ff7a00', medium: '#ffcc00', low: '#6b1c4f', info: '#6e6e6e' }

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
function MetaForm({ meta, setMeta, toast }) {
  const [local, setLocal] = useState({ ...meta })
  const set = useCallback((k, v) => setLocal(p => ({ ...p, [k]: v })), [])
  const save = () => { setMeta({ ...local }); toast('Configuration saved ✓') }

  return (
    <div>
      <div className="flex items-center justify-between mb-20">
        <div className="page-title" style={{ marginBottom: 0 }}>⚙ Report Configuration</div>
        <div className="flex gap-8">
          <button className="btn btn-primary" onClick={save}>✓ Save</button>
          <button className="btn" onClick={() => setLocal({ ...meta })}>Reset</button>
        </div>
      </div>

      <div className="grid-2" style={{ gap: 20 }}>
        <div>
          <div className="card mb-16">
            <div className="section-label">Client Information</div>
            <Field label="Client Name" value={local.client_name || ''} onChange={e => set('client_name', e.target.value)} placeholder="ACME Corporation" />
            <Field label="Application Name" value={local.application_name || ''} onChange={e => set('application_name', e.target.value)} placeholder="Customer Portal" />
            <Field label="Application Version" value={local.application_version || ''} onChange={e => set('application_version', e.target.value)} placeholder="2.1.0" />
            <div className="form-group">
              <label className="form-label">Testing Approach</label>
              <select value={local.application_approach || 'External'} onChange={e => set('application_approach', e.target.value)} className="form-select">
                {['Internal', 'External', 'Internal/External'].map(o => <option key={o}>{o}</option>)}
              </select>
            </div>
            <Field label="Scoped IPs Count" value={local.scoped_ips_count || ''} onChange={e => set('scoped_ips_count', e.target.value)} placeholder="e.g. 15" />
          </div>

        </div>
        <div>
          <div className="card mb-16">
            <div className="section-label">Team & Timeline</div>
            <Field label="Tester Name" value={local.tester_name || ''} onChange={e => set('tester_name', e.target.value)} placeholder="Your Name" />
            <Field label="Validator / Reviewer" value={local.validator_name || ''} onChange={e => set('validator_name', e.target.value)} placeholder="Validator Name" />
            <Field label="Document Title" value={local.document_title || ''} onChange={e => set('document_title', e.target.value)} placeholder="Vulnerability Assessment Report" />
            <Field label="Approved By" value={local.approved_by || ''} onChange={e => set('approved_by', e.target.value)} placeholder="Approver Name" />
            <Field label="Project ID" value={local.project_id || ''} onChange={e => set('project_id', e.target.value)} placeholder={`IARM-${new Date().getFullYear()}-001`} />
            <Field label="Assessment Start Date" type="date" value={local.assessment_startdate || ''} onChange={e => set('assessment_startdate', e.target.value)} />
            <Field label="Assessment End Date" type="date" value={local.assessment_enddate || ''} onChange={e => set('assessment_enddate', e.target.value)} />
            <Field label="Report Delivery Date" type="date" value={local.report_delivery_date || ''} onChange={e => set('report_delivery_date', e.target.value)} />
          </div>
          <div className="card">
            <div className="section-label">Document Dates</div>
            <Field label="Basic Document Date" type="date" value={local.basic_document_date || ''} onChange={e => set('basic_document_date', e.target.value)} />
            <Field label="Draft Document Date" type="date" value={local.draft_document_date || ''} onChange={e => set('draft_document_date', e.target.value)} />
            <Field label="Peer Review Date" type="date" value={local.peer_review_date || ''} onChange={e => set('peer_review_date', e.target.value)} />
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Finding Form ─────────────────────────────────────────────────────────────
function FindingForm({ initial, onSave, onCancel, toast }) {
  const isNew = !initial?.id
  const [f, setF] = useState(isNew ? { ...EMPTY_FINDING, id: genId() } : {
    ...initial,
    cvss: { ...initial.cvss },
    affected_components: [...(initial.affected_components || [])],
    payload: [...(initial.payload || [])],
    references: [...(initial.references || [])],
    evidence_images: [...(initial.evidence_images || [])],
  })
  const set = (k, v) => setF(p => ({ ...p, [k]: v }))
  const setCvss = (k, v) => setF(p => ({ ...p, cvss: { ...p.cvss, [k]: v } }))

  const save = () => {
    if (!f.title?.trim())           { toast('Title is required', 'error'); return }
    if (!f.description?.trim())     { toast('Description is required', 'error'); return }
    if (!f.recommendation?.trim())  { toast('Recommendation is required', 'error'); return }
    onSave({ ...f })
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
        <div className="flex gap-8">
          <button className="btn btn-primary" onClick={save}>{isNew ? '+ Add' : '✓ Save'}</button>
          <button className="btn" onClick={onCancel}>Cancel</button>
        </div>
      </div>

      <div className="grid-2" style={{ gap: 20 }}>
        {/* Left column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
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
                  {['critical', 'high', 'medium', 'low', 'info'].map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Ease of Exploit</label>
                <select value={f.ease || 'Moderate'} onChange={e => set('ease', e.target.value)} className="form-select">
                  {['Trivial', 'Moderate', 'Difficult'].map(o => <option key={o}>{o}</option>)}
                </select>
              </div>
            </div>
            
            <div className="form-group" style={{ marginTop: 12 }}>
              <label className="form-label">Device Identifier (Type)</label>
              <input value={f.device_identifier || ''} onChange={e => set('device_identifier', e.target.value)} className="form-input" placeholder="e.g. firewall, router, server" />
            </div>
            
            <div className="form-group" style={{ marginTop: 12 }}>
              <label className="form-label">Port / Protocol</label>
              <input value={f.port_protocol || ''} onChange={e => set('port_protocol', e.target.value)} className="form-input" placeholder="e.g. 443/tcp, 80/http" />
            </div>

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



          <div className="card">
            <div className="section-label">References — one per line</div>
            <textarea
              value={(f.references || []).join('\n')}
              onChange={e => set('references', e.target.value.split('\n').filter(Boolean))}
              className="form-textarea"
              rows={3}
              placeholder="https://owasp.org/..."
            />
          </div>

        </div>

        {/* Right column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="card">
            <div className="section-label">Finding Details</div>
            <TA label="Description * — explain the vulnerability" rows={7} placeholder="Describe the vulnerability, root cause, and affected code/endpoint..." value={f.description || ''} onChange={e => set('description', e.target.value)} onGenerate={() => askAI('description')} generating={generatingField === 'description'} />

            <TA label="Proof of Concept — steps to reproduce" rows={7} mono placeholder="Step 1: Navigate to /endpoint&#10;Step 2: Inject payload: ' OR 1=1--&#10;Step 3: Observe 200 OK response..." value={f.poc || ''} onChange={e => set('poc', e.target.value)} onGenerate={() => askAI('poc')} generating={generatingField === 'poc'} />
            <TA label="Recommendation * — how to fix" rows={6} placeholder="Use parameterized queries. Implement input validation..." value={f.recommendation || ''} onChange={e => set('recommendation', e.target.value)} onGenerate={() => askAI('recommendation')} generating={generatingField === 'recommendation'} />
          </div>
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

      {activeTab === 'meta' && <MetaForm meta={meta} setMeta={setMeta} toast={toast} />}
      {activeTab === 'finding' && <FindingForm initial={editTarget} onSave={handleSave} onCancel={handleCancel} toast={toast} />}
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
