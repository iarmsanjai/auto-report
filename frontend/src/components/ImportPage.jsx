import { useState, useRef, useCallback } from 'react'
import { importCSV } from '../services/api'
import ThemeToggle from './ThemeToggle'

const SCAN_TYPES = [
  {
    id: 'nessus',
    icon: '🛡',
    label: 'VA report',
    sublabel: 'Vulnerability Scanner',
    description: 'Import findings from a Nessus scan export. Automatically maps severity, CVSS scores, and affected hosts.',
    accept: '.csv',
    fileHint: '.csv',
    template: 'nessus',
    active: true,
    color: '#00d4ff',
    glow: 'rgba(0,212,255,0.15)',
  },
  {
    id: 'snyk',
    icon: '🔍',
    label: 'Source Code Review',
    sublabel: 'SAST/SCA Scan',
    description: 'Import findings from a Snyk SAST/SCA report. Maps CWE, severity and remediation guidance.',
    accept: '.html',
    fileHint: '.html',
    template: 'snyk',
    active: false,
    color: '#9f7aea',
    glow: 'rgba(159,122,234,0.12)',
  },
  {
    id: 'webvapt',
    icon: '🌐',
    label: 'Web VAPT',
    sublabel: 'Web Penetration Test',
    description: 'Import manual web application penetration test findings in structured VAPT report format.',
    accept: '.csv,.json',
    fileHint: '.csv / .json',
    template: 'webvapt',
    active: false,
    color: '#ff8c42',
    glow: 'rgba(255,140,66,0.12)',
  },
]

export default function ImportPage({ onImportDone, onBack, authUser, toast }) {
  const [selectedType, setSelectedType] = useState(null)
  const [drag, setDrag]       = useState(false)
  const [loading, setLoading] = useState(false)
  const [preview, setPreview] = useState(null)
  const fileRef = useRef()

  const currentType = SCAN_TYPES.find(t => t.id === selectedType)

  const process = useCallback(async (file) => {
    if (!currentType) return
    const ext = file.name.split('.').pop().toLowerCase()

    if (selectedType === 'nessus' && ext !== 'csv') {
      toast('Nessus import requires a .csv file', 'error')
      return
    }

    setLoading(true)
    setPreview(null)
    try {
      let result
      if (selectedType === 'nessus') {
        result = await importCSV(file)
      } else {
        toast('This scanner type is not yet supported', 'warn')
        setLoading(false)
        return
      }

      if (!result.count) {
        toast(`No findings found in ${file.name}. ${result.warnings?.[0] || ''}`, 'warn')
        return
      }
      setPreview({
        name: file.name,
        count: result.count,
        findings: result.findings,
        warnings: result.warnings || [],
        scanType: selectedType,
        template: currentType.template,
      })
      toast(`Extracted ${result.count} findings from ${file.name}`)
    } catch (err) {
      toast(err?.response?.data?.detail || 'Upload failed — is the backend running?', 'error')
    } finally {
      setLoading(false)
    }
  }, [selectedType, currentType, toast])

  const onDrop = useCallback(e => {
    e.preventDefault()
    setDrag(false)
    const file = e.dataTransfer.files[0]
    if (file) process(file)
  }, [process])

  const confirm = (mode) => {
    onImportDone(preview.findings, mode, preview.scanType, preview.template)
  }

  const handleCardClick = (type) => {
    if (!type.active) return
    setSelectedType(prev => prev === type.id ? null : type.id)
    setPreview(null)
    if (fileRef.current) fileRef.current.value = ''
  }

  return (
    <div style={{
      minHeight: '100vh',
      width: '100vw',
      background: 'var(--bg)',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      fontFamily: "'Inter', 'PT Sans', sans-serif",
      position: 'relative',
      overflowX: 'hidden',
      overflowY: 'auto',
    }}>

      {/* ── Background grid ── */}
      <div style={{
        position: 'fixed', inset: 0, pointerEvents: 'none',
        backgroundImage: `
          linear-gradient(rgba(0,212,255,0.025) 1px, transparent 1px),
          linear-gradient(90deg, rgba(0,212,255,0.025) 1px, transparent 1px)
        `,
        backgroundSize: '48px 48px',
      }} />

      {/* ── Radial glow ── */}
      <div style={{
        position: 'fixed', top: '30%', left: '50%',
        transform: 'translate(-50%,-50%)',
        width: 900, height: 500,
        background: 'radial-gradient(ellipse, rgba(0,212,255,0.05) 0%, transparent 65%)',
        pointerEvents: 'none',
      }} />

      {/* ── Top bar ── */}
      <div style={{
        width: '100%', maxWidth: 980,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '24px 0 0',
      }}>
        {/* Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <button className="btn" style={{ marginRight: 16 }} onClick={onBack}>← Back</button>
          <span style={{ fontSize: 22, color: 'var(--cyan)' }}>⬡</span>
          <span style={{
            fontFamily: "'Inter', 'PT Sans', sans-serif", fontWeight: 700,
            fontSize: 15, letterSpacing: 2, color: 'var(--cyan)',
          }}>
            <span style={{ color: 'var(--red)' }}>IARM</span> VAPT REPORTS
          </span>
          <span style={{
            background: 'var(--cyan-dim)', color: 'var(--cyan)',
            border: '1px solid var(--cyan)', borderRadius: 4,
            padding: '1px 8px', fontSize: 9, letterSpacing: 2,
          }}>v1.0</span>
        </div>

        {/* User + breadcrumb */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 20, fontSize: 11 }}>
          {/* Breadcrumb */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            fontFamily: "'Inter', 'PT Sans', sans-serif", color: 'var(--dim)',
          }}>
            <span style={{ color: 'var(--green)' }}>✓ Login</span>
            <span>──▶</span>
            <span style={{ color: 'var(--green)' }}>✓ Hub</span>
            <span>──▶</span>
            <span style={{
              color: 'var(--cyan)', fontWeight: 700,
              background: 'rgba(0,212,255,0.08)',
              border: '1px solid rgba(0,212,255,0.4)',
              borderRadius: 4, padding: '2px 10px',
            }}>↑ Import</span>
          </div>
          {/* User chip */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6,
            borderLeft: '1px solid var(--border)', paddingLeft: 16,
          }}>
            <span style={{ color: 'var(--cyan)', fontSize: 13 }}>⬡</span>
            <span style={{ color: 'var(--text2)' }}>{authUser?.username || 'admin'}</span>
            <span style={{ color: 'var(--dim)', fontSize: 9, textTransform: 'uppercase', letterSpacing: 0.5 }}>
              {authUser?.role}
            </span>
          </div>
          {/* Theme Toggle */}
          <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: 16 }}>
            <ThemeToggle />
          </div>
        </div>
      </div>

      {/* ── Top accent line ── */}
      <div style={{
        width: '100%', maxWidth: 980,
        borderTop: '1px solid var(--border)', marginTop: 16,
        marginBottom: 40,
      }} />

      {/* ── Main content ── */}
      <div style={{ width: '100%', maxWidth: 980, padding: '0 0 60px' }}>

        {/* Header */}
        <div style={{ marginBottom: 36, textAlign: 'center' }}>
          <div style={{
            fontFamily: "'PT Sans', sans-serif",
            fontSize: 22, fontWeight: 700, color: 'var(--cyan)',
            letterSpacing: 2, marginBottom: 10,
          }}>
            ↑ IMPORT VULNERABILITY DATA
          </div>
          <div style={{ fontSize: 13, color: 'var(--dim)', maxWidth: 480, margin: '0 auto' }}>
            Select your scan source below. Once you upload and confirm, you'll be taken straight to the dashboard.
          </div>
        </div>

        {/* ── STEP 1: Scan type cards ── */}
        <div style={{
          fontSize: 11, color: 'var(--dim)', letterSpacing: 1.2,
          textTransform: 'uppercase', marginBottom: 14,
          fontFamily: "'Inter', 'PT Sans', sans-serif", fontWeight: 600
        }}>
          Step 1 — Select Scan Type
        </div>

        <div className="scan-type-grid" style={{ marginBottom: 32 }}>
          {SCAN_TYPES.map(type => {
            const isSelected = selectedType === type.id
            return (
              <div
                key={type.id}
                className={`scan-card ${isSelected ? 'scan-card-selected' : ''} ${!type.active ? 'scan-card-disabled' : ''}`}
                style={{ '--card-color': type.color }}
                onClick={() => handleCardClick(type)}
                title={type.active ? `Select ${type.label}` : 'Coming soon'}
              >
                {!type.active && (
                  <div className="scan-badge-soon">🔒 Coming Soon</div>
                )}

                <div className="scan-card-icon" style={{ color: type.active ? type.color : 'var(--muted)' }}>
                  {type.icon}
                </div>

                <div className="scan-card-label" style={{ color: type.active ? 'var(--text)' : 'var(--dim)' }}>
                  {type.label}
                </div>
                <div className="scan-card-sublabel">{type.sublabel}</div>
                <div className="scan-card-desc">{type.description}</div>

                <div className="scan-card-hint" style={{ color: type.active ? type.color : 'var(--muted)' }}>
                  Accepts: {type.fileHint}
                </div>

                {isSelected && (
                  <div className="scan-card-check">✓ Selected</div>
                )}
              </div>
            )
          })}
        </div>

        {/* ── STEP 2: Upload zone ── */}
        {selectedType && currentType && (
          <div className="scan-upload-section">
            <div style={{
              fontSize: 11, color: 'var(--dim)', letterSpacing: 1.2,
              textTransform: 'uppercase', marginBottom: 14,
              fontFamily: "'Inter', 'PT Sans', sans-serif", fontWeight: 600
            }}>
              Step 2 — Upload {currentType.label} File
            </div>

            <div
              onDragOver={e => { e.preventDefault(); setDrag(true) }}
              onDragLeave={() => setDrag(false)}
              onDrop={onDrop}
              onClick={() => !preview && fileRef.current?.click()}
              className="scan-dropzone"
              style={{
                borderColor: drag ? currentType.color : undefined,
                background: drag ? `${currentType.glow}` : undefined,
                cursor: preview ? 'default' : 'pointer',
              }}
            >
              {loading ? (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 14 }}>
                  <div className="spinner" style={{ width: 36, height: 36, borderTopColor: currentType.color }} />
                  <div style={{ color: 'var(--dim)', fontSize: 13 }}>
                    Parsing {currentType.label} file...
                  </div>
                </div>
              ) : preview ? (
                /* ── Preview inside dropzone ── */
                <div onClick={e => e.stopPropagation()} style={{ width: '100%', textAlign: 'left' }}>
                  {/* Preview header */}
                  <div style={{
                    display: 'flex', alignItems: 'center',
                    justifyContent: 'space-between', marginBottom: 16,
                    flexWrap: 'wrap', gap: 10,
                  }}>
                    <div>
                      <span style={{ color: currentType.color, fontWeight: 700, fontSize: 13 }}>
                        {preview.name}
                      </span>
                      <span style={{ color: 'var(--dim)', fontSize: 11, marginLeft: 14 }}>
                        {preview.count} findings extracted
                      </span>
                      <span style={{
                        marginLeft: 12, fontSize: 10, padding: '2px 8px',
                        borderRadius: 4,
                        background: `${currentType.glow}`,
                        border: `1px solid ${currentType.color}`,
                        color: currentType.color,
                      }}>
                        {preview.template} template
                      </span>
                    </div>
                    <div style={{ display: 'flex', gap: 8 }}>
                      <button
                        className="btn btn-primary btn-sm"
                        style={{ borderColor: currentType.color, color: currentType.color, background: currentType.glow }}
                        onClick={() => confirm('replace')}
                      >
                        ↑ Load &amp; Continue
                      </button>
                      <button className="btn btn-success btn-sm" onClick={() => confirm('merge')}>
                        + Merge
                      </button>
                      <button className="btn btn-sm" onClick={() => { setPreview(null); if (fileRef.current) fileRef.current.value = '' }}>
                        ✕ Cancel
                      </button>
                    </div>
                  </div>

                  {/* Warnings */}
                  {preview.warnings.map((w, i) => (
                    <div key={i} className="warn-banner" style={{ marginBottom: 12 }}>{w}</div>
                  ))}

                  {/* Table */}
                  <div style={{
                    maxHeight: 260, overflowY: 'auto', overflowX: 'auto',
                    border: '1px solid var(--border)', borderRadius: 6,
                  }}>
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th style={{ width: 36 }}>#</th>
                          <th>Title</th>
                          <th style={{ width: 90 }}>Severity</th>
                          <th style={{ width: 80 }}>CVSS</th>
                          <th style={{ width: 80 }}>CWE</th>
                          <th style={{ width: 80 }}>Source</th>
                        </tr>
                      </thead>
                      <tbody>
                        {preview.findings.map((f, i) => (
                          <tr key={f.id}>
                            <td style={{ color: 'var(--dim)', fontFamily: 'PT Sans, sans-serif', fontSize: 11 }}>{i + 1}</td>
                            <td className="truncate" style={{ maxWidth: 300 }}>{f.title}</td>
                            <td><span className={`sev-badge sev-${f.cvss?.level}`}>{f.cvss?.level}</span></td>
                            <td style={{ fontFamily: 'PT Sans, sans-serif', fontSize: 11, color: 'var(--dim)' }}>{f.cvss?.score || '—'}</td>
                            <td style={{ fontFamily: 'PT Sans, sans-serif', fontSize: 11, color: 'var(--dim)' }}>{f.cwe || '—'}</td>
                            <td style={{ fontSize: 10, color: 'var(--dim)' }}>{f.source}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : (
                /* ── Empty drop zone ── */
                <>
                  <span className="scan-dropzone-icon" style={{ color: drag ? currentType.color : 'var(--dim)' }}>
                    {currentType.icon}
                  </span>
                  <div style={{
                    color: drag ? currentType.color : 'var(--text)',
                    fontWeight: 600, fontSize: 15, marginBottom: 6,
                    transition: 'color 0.15s',
                  }}>
                    Drop {currentType.label} file here or click to browse
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--dim)', marginBottom: 4 }}>
                    Accepts: <span style={{ color: currentType.color, fontFamily: "'PT Sans', sans-serif" }}>{currentType.fileHint}</span>
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 8 }}>
                    Template: <span style={{ color: currentType.color }}>{currentType.template}</span>
                  </div>
                </>
              )}

              <input
                ref={fileRef}
                type="file"
                accept={currentType.accept}
                style={{ display: 'none' }}
                onChange={e => e.target.files[0] && process(e.target.files[0])}
              />
            </div>
          </div>
        )}

        {/* ── Placeholder hint when nothing selected ── */}
        {!selectedType && (
          <div style={{
            textAlign: 'center', padding: '28px 24px',
            border: '1px dashed var(--border)', borderRadius: 10,
            color: 'var(--dim)', fontSize: 12,
          }}>
            <div style={{ fontSize: 24, marginBottom: 8, opacity: 0.3 }}>↑</div>
            Select a scan type above to reveal the upload zone
          </div>
        )}
      </div>
    </div>
  )
}
