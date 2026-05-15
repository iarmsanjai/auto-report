import { useState, useRef, useCallback } from 'react'
import { importCSV } from '../services/api'

const SCAN_TYPES = [
  {
    id: 'nessus',
    icon: '🛡',
    label: 'Nessus',
    sublabel: 'Vulnerability Scanner',
    description: 'Import findings from a Nessus scan export. Automatically maps severity, CVSS scores, and affected hosts.',
    accept: '.csv',
    fileHint: 'Accepts: .csv',
    template: 'nessus',
    active: true,
    color: '#00d4ff',
  },
  {
    id: 'snyk',
    icon: '🔍',
    label: 'Snyk',
    sublabel: 'Source Code Review',
    description: 'Import findings from a Snyk security report. Maps CWE, severity and fix recommendations.',
    accept: '.html',
    fileHint: 'Accepts: .html',
    template: 'snyk',
    active: false,
    color: '#9f7aea',
  },
  {
    id: 'webvapt',
    icon: '🌐',
    label: 'Web VAPT',
    sublabel: 'Web Penetration Test',
    description: 'Import manual web application penetration test findings. Supports structured VAPT report formats.',
    accept: '.csv,.json',
    fileHint: 'Accepts: .csv, .json',
    template: 'webvapt',
    active: false,
    color: '#ff8c42',
  },
]

export default function FileUpload({ onImport, toast }) {
  const [selectedType, setSelectedType] = useState(null)
  const [drag, setDrag]       = useState(false)
  const [loading, setLoading] = useState(false)
  const [preview, setPreview] = useState(null)
  const fileRef = useRef()

  const currentType = SCAN_TYPES.find(t => t.id === selectedType)

  const process = useCallback(async (file) => {
    if (!currentType) return
    const ext = file.name.split('.').pop().toLowerCase()

    // Validate extension per scan type
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
        toast('This scanner type is not yet supported on the backend', 'warn')
        setLoading(false)
        return
      }

      if (!result.count) {
        toast(`No findings extracted from ${file.name}. ${result.warnings?.[0] || ''}`, 'warn')
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
    onImport(preview.findings, mode, preview.scanType, preview.template)
    const verb = mode === 'replace' ? 'Replaced all with' : 'Merged'
    toast(`${verb} ${preview.findings.length} findings`)
    setPreview(null)
  }

  const handleCardClick = (type) => {
    if (!type.active) return
    setSelectedType(prev => prev === type.id ? null : type.id)
    setPreview(null)
    if (fileRef.current) fileRef.current.value = ''
  }

  return (
    <div>
      {/* ── Gate header ── */}
      <div style={{ marginBottom: 28 }}>
        {/* Workflow breadcrumb */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8,
          fontSize: 11, color: 'var(--dim)', marginBottom: 16,
          fontFamily: "'PT Sans', sans-serif",
        }}>
          <span style={{ color: 'var(--green)' }}>✓ Login</span>
          <span style={{ color: 'var(--border2)' }}>──▶</span>
          <span style={{
            color: 'var(--cyan)', fontWeight: 700,
            background: 'rgba(0,212,255,0.08)',
            border: '1px solid var(--cyan)',
            borderRadius: 4, padding: '2px 10px',
          }}>↑ Import</span>
          <span style={{ color: 'var(--border2)' }}>──▶</span>
          <span style={{ color: 'var(--muted)' }}>Dashboard</span>
        </div>

        <div className="page-title" style={{ marginBottom: 6 }}>↑ Import Vulnerability Data</div>
        <div style={{ fontSize: 12, color: 'var(--dim)', maxWidth: 520 }}>
          Select your scan type below and upload the report file to begin.
          You will be taken to the dashboard automatically after import.
        </div>
      </div>

      {/* ── Scan type selector ── */}
      <div style={{ marginBottom: 28 }}>
        <div className="section-label" style={{ marginBottom: 14 }}>
          Step 1 — Select Scan Type
        </div>
        <div className="scan-type-grid">
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
                {/* Coming Soon badge */}
                {!type.active && (
                  <div className="scan-badge-soon">🔒 Coming Soon</div>
                )}

                {/* Icon */}
                <div className="scan-card-icon" style={{ color: type.active ? type.color : 'var(--muted)' }}>
                  {type.icon}
                </div>

                {/* Labels */}
                <div className="scan-card-label" style={{ color: type.active ? 'var(--text)' : 'var(--dim)' }}>
                  {type.label}
                </div>
                <div className="scan-card-sublabel">
                  {type.sublabel}
                </div>

                {/* Description */}
                <div className="scan-card-desc">
                  {type.description}
                </div>

                {/* File hint */}
                <div className="scan-card-hint" style={{ color: type.active ? type.color : 'var(--muted)' }}>
                  {type.fileHint}
                </div>

                {/* Selected check */}
                {isSelected && (
                  <div className="scan-card-check">✓ Selected</div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* ── Upload zone (shown only when a scan type is selected) ── */}
      {selectedType && currentType && (
        <div className="scan-upload-section">
          <div className="section-label" style={{ marginBottom: 14 }}>
            Step 2 — Upload {currentType.label} File
          </div>

          <div
            onDragOver={e => { e.preventDefault(); setDrag(true) }}
            onDragLeave={() => setDrag(false)}
            onDrop={onDrop}
            onClick={() => fileRef.current?.click()}
            className="scan-dropzone"
            style={{ borderColor: drag ? currentType.color : undefined }}
          >
            {loading ? (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
                <div className="spinner" style={{ width: 32, height: 32, borderTopColor: currentType.color }} />
                <div style={{ color: 'var(--dim)', fontSize: 13 }}>Parsing {currentType.label} file...</div>
              </div>
            ) : (
              <>
                <div className="scan-dropzone-icon" style={{ color: drag ? currentType.color : 'var(--dim)' }}>
                  {currentType.icon}
                </div>
                <div style={{ color: drag ? currentType.color : 'var(--text)', fontWeight: 600, fontSize: 14, marginBottom: 6, transition: 'color 0.15s' }}>
                  Drop {currentType.label} file here or click to browse
                </div>
                <div style={{ fontSize: 12, color: 'var(--dim)', marginBottom: 4 }}>
                  {currentType.fileHint}
                </div>
                <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>
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

      {/* ── Preview panel ── */}
      {preview && (
        <div className="card mb-20" style={{ marginTop: 20 }}>
          {/* Header */}
          <div className="flex items-center justify-between mb-16">
            <div>
              <span style={{ color: currentType?.color || 'var(--cyan)', fontWeight: 700, fontSize: 13 }}>
                {preview.name}
              </span>
              <span style={{ color: 'var(--dim)', fontSize: 11, marginLeft: 14 }}>
                {preview.count} findings extracted
              </span>
              <span style={{
                marginLeft: 12, fontSize: 10, padding: '2px 8px',
                borderRadius: 4, background: 'rgba(0,212,255,0.1)',
                border: `1px solid ${currentType?.color || 'var(--cyan)'}`,
                color: currentType?.color || 'var(--cyan)',
              }}>
                {preview.template} template
              </span>
            </div>
            <div className="flex gap-8">
              <button className="btn btn-primary btn-sm" onClick={() => confirm('replace')}>
                ↑ Replace All
              </button>
              <button className="btn btn-success btn-sm" onClick={() => confirm('merge')}>
                + Merge
              </button>
              <button className="btn btn-sm" onClick={() => setPreview(null)}>✕</button>
            </div>
          </div>

          {/* Warnings */}
          {preview.warnings.map((w, i) => (
            <div key={i} className="warn-banner mb-12">{w}</div>
          ))}

          {/* Preview table */}
          <div style={{ maxHeight: 320, overflowY: 'auto', overflowX: 'auto', border: '1px solid var(--border)', borderRadius: 6 }}>
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
      )}

      {/* ── Placeholder when nothing selected ── */}
      {!selectedType && (
        <div style={{
          textAlign: 'center', padding: '32px 24px',
          border: '1px dashed var(--border)', borderRadius: 10,
          color: 'var(--dim)', fontSize: 12, marginTop: 4,
        }}>
          <div style={{ fontSize: 28, marginBottom: 10, opacity: 0.4 }}>↑</div>
          Select a scan type above to begin importing findings
        </div>
      )}
    </div>
  )
}
