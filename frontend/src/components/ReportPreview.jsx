import { useState, useRef } from 'react'
import { exportHTML, exportDOCX, downloadBlob, todayStr, updateReportStatus } from '../services/api'

function computeStats(findings) {
  const active = findings.filter(f => !f.false_positive)
  return {
    count_critical: active.filter(f => f.cvss?.level === 'critical').length,
    count_high:     active.filter(f => f.cvss?.level === 'high').length,
    count_medium:   active.filter(f => f.cvss?.level === 'medium').length,
    count_low:      active.filter(f => f.cvss?.level === 'low').length,
    count_info:     active.filter(f => f.cvss?.level === 'info').length,
    total:          active.length,
  }
}

const SEV_COLORS = { critical: '#e60000', high: '#ff7a00', medium: '#ffcc00', low: '#6b1c4f', info: '#6e6e6e' }
const SEV_TEXT   = { critical: '#fff', high: '#fff', medium: '#000', low: '#fff', info: '#fff' }

export default function ReportPreview({ findings, meta, toast, authUser, currentReportId, currentReportStatus, setCurrentReportStatus }) {
  const [loading, setLoading]   = useState(false)
  const [pdfLoading, setPdfLoading] = useState(false)
  const [docxLoading, setDocxLoading] = useState(false)
  const [template, setTemplate] = useState('default_report')
  const [previewHtml, setPreviewHtml] = useState(null)
  const printIframeRef = useRef(null)

  const stats  = computeStats(findings)
  const active = findings.filter(f => !f.false_positive)
  const payload = { report: meta, findings, finding_stats: stats }

  const doExportHTML = async () => {
    setLoading(true)
    try {
      const html = await exportHTML(payload, template)
      const slug = (meta.client_name || 'report').replace(/\s+/g, '_')
      downloadBlob(html, `vapt_report_${slug}_${todayStr()}.html`, 'text/html')
      toast('HTML report downloaded ✓')
    } catch (err) {
      toast('Export failed — ' + (err?.response?.data?.detail || 'check backend'), 'error')
    } finally {
      setLoading(false)
    }
  }

  const doPreview = async () => {
    setLoading(true)
    try {
      const html = await exportHTML(payload, template)
      setPreviewHtml(html)
    } catch (err) {
      toast('Preview failed — ' + (err?.response?.data?.detail || 'check backend'), 'error')
    } finally {
      setLoading(false)
    }
  }

  const openInTab = async () => {
    setLoading(true)
    try {
      const html = await exportHTML(payload, template)
      const blob = new Blob([html], { type: 'text/html' })
      window.open(URL.createObjectURL(blob), '_blank')
    } catch (err) {
      toast('Failed to open preview', 'error')
    } finally {
      setLoading(false)
    }
  }

  const doExportPDF = async () => {
    setPdfLoading(true)
    try {
      const html = await exportHTML(payload, template)
      const iframe = printIframeRef.current
      // Inject the report HTML and trigger browser print dialog
      iframe.srcdoc = html
      iframe.onload = () => {
        try {
          iframe.contentWindow.focus()
          iframe.contentWindow.print()
        } catch (e) {
          // Fallback: open in new tab with print triggered
          const blob = new Blob([html], { type: 'text/html' })
          const url = URL.createObjectURL(blob)
          const win = window.open(url, '_blank')
          win.onload = () => win.print()
        }
        setPdfLoading(false)
      }
    } catch (err) {
      toast('PDF export failed — ' + (err?.response?.data?.detail || 'check backend'), 'error')
      setPdfLoading(false)
    }
  }

  const doExportDOCX = async () => {
    setDocxLoading(true)
    try {
      const blob = await exportDOCX(payload, template)
      const slug = (meta.client_name || 'report').replace(/\s+/g, '_')
      downloadBlob(blob, `vapt_report_${slug}_${todayStr()}.docx`, 'application/vnd.openxmlformats-officedocument.wordprocessingml.document')
      toast('MS Word report downloaded ✓')
    } catch (err) {
      toast('DOCX export failed', 'error')
    } finally {
      setDocxLoading(false)
    }
  }

  const handleRequestApproval = async () => {
    if (!currentReportId) {
      toast('Please Save to Cloud first before requesting approval', 'warn')
      return
    }
    setLoading(true)
    try {
      await updateReportStatus(currentReportId, 'pending_approval')
      setCurrentReportStatus('pending_approval')
      toast('Report sent for approval ✓')
    } catch (err) {
      toast('Failed to request approval', 'error')
    } finally {
      setLoading(false)
    }
  }

  const isUser = authUser?.role !== 'admin'
  const canRequestApproval = isUser && ['draft', 'needs_change'].includes(currentReportStatus)

  return (
    <div>
      <div className="page-title">⊙ Report Preview & Export</div>

      {/* Status banner */}
      {currentReportId && (
        <div style={{
          padding: '12px 16px', background: 'var(--bg2)', border: '1px solid var(--border)',
          borderRadius: 6, marginBottom: 20, display: 'flex', alignItems: 'center', justifyContent: 'space-between'
        }}>
          <div>
            <span style={{ fontSize: 12, color: 'var(--dim)', marginRight: 10 }}>Cloud Status:</span>
            <span className={`sev-badge ${
              currentReportStatus === 'approved' ? 'sev-low' :
              currentReportStatus === 'needs_change' ? 'sev-high' :
              currentReportStatus === 'pending_approval' ? 'sev-medium' : ''
            }`}>
              {currentReportStatus.replace('_', ' ').toUpperCase()}
            </span>
          </div>
          {canRequestApproval && (
            <button className="btn btn-sm" style={{ borderColor: 'var(--cyan)', color: 'var(--cyan)' }} onClick={handleRequestApproval} disabled={loading}>
              ↑ Request to Approval
            </button>
          )}
        </div>
      )}

      {/* Summary cards */}
      <div className="card mb-20">
        <div className="section-label">Export Summary</div>
        <div className="grid-4">
          {[
            { label: 'Client', val: meta.client_name || <span className="text-muted">Not set</span> },
            { label: 'Application', val: meta.application_name || <span className="text-muted">Not set</span> },
            { label: 'Active Findings', val: active.length, color: 'var(--cyan)' },
            { label: 'Report Date', val: meta.report_delivery_date || <span className="text-muted">Not set</span> },
          ].map((s, i) => (
            <div key={i}>
              <div style={{ fontSize: 10, color: 'var(--dim)', marginBottom: 4 }}>{s.label}</div>
              <div style={{ fontSize: 13, color: s.color || 'var(--text)', fontWeight: s.color ? 700 : 400 }}>{s.val}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Severity breakdown */}
      <div className="card mb-20">
        <div className="section-label">Severity Breakdown (Active Findings)</div>
        <div style={{ display: 'flex', gap: 10 }}>
          {['critical','high','medium','low','info'].map(s => (
            <div key={s} style={{
              background: `${SEV_COLORS[s]}15`,
              border: `1px solid ${SEV_COLORS[s]}33`,
              borderRadius: 8,
              padding: '14px 18px',
              textAlign: 'center',
              flex: 1,
            }}>
              <div style={{ fontFamily: 'PT Sans, sans-serif', fontSize: 28, fontWeight: 700, color: SEV_COLORS[s] }}>
                {stats[`count_${s}`]}
              </div>
              <div style={{ fontSize: 10, color: 'var(--dim)', marginTop: 5 }}>{s.charAt(0).toUpperCase() + s.slice(1)}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Findings list preview */}
      {active.length > 0 && (
        <div className="card mb-20">
          <div className="section-label">Findings Included in Export ({active.length})</div>
          <div style={{ maxHeight: 220, overflowY: 'auto', overflowX: 'auto' }}>
            <table className="data-table">
              <thead><tr><th>#</th><th>Title</th><th style={{ width: 100 }}>Severity</th><th style={{ width: 70 }}>CVSS</th></tr></thead>
              <tbody>
                {active.map((f, i) => (
                  <tr key={f.id}>
                    <td style={{ color: 'var(--dim)', fontFamily: 'PT Sans, sans-serif', fontSize: 11 }}>{i + 1}</td>
                    <td className="truncate" style={{ maxWidth: 360 }}>{f.title}</td>
                    <td><span className={`sev-badge sev-${f.cvss?.level}`}>{f.cvss?.level}</span></td>
                    <td style={{ fontFamily: 'PT Sans, sans-serif', fontSize: 11, color: 'var(--dim)' }}>{f.cvss?.score || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Template selector + export buttons */}
      <div className="grid-3" style={{ gap: 16, marginBottom: 20 }}>
        {/* HTML export */}
        <div className="card" style={{ borderColor: '#00d4ff22' }}>
          <div style={{ color: 'var(--cyan)', fontWeight: 700, fontSize: 13, marginBottom: 8 }}>HTML Report</div>
          <div style={{ fontSize: 11, color: 'var(--dim)', lineHeight: 1.8, marginBottom: 14 }}>
            Full styled IARM report. Print via browser (Ctrl+P) for PDF. Includes all sections, tables, and finding details.
          </div>

          <div className="flex gap-8 flex-wrap">
            <button className="btn btn-primary btn-sm" onClick={doExportHTML} disabled={loading}>
              {loading ? <span className="spinner" /> : '↓'} Download
            </button>
            <button className="btn btn-sm" onClick={doPreview} disabled={loading}>⊙ Preview</button>
            <button className="btn btn-sm" onClick={openInTab} disabled={loading}>↗ Open Tab</button>
          </div>
        </div>

        {/* PDF export */}
        <div className="card" style={{ borderColor: '#f6872522' }}>
          <div style={{ color: '#f68725', fontWeight: 700, fontSize: 13, marginBottom: 8 }}>📄 PDF Report</div>
          <div style={{ fontSize: 11, color: 'var(--dim)', lineHeight: 1.8, marginBottom: 14 }}>
            Renders the selected HTML template and opens the browser <strong style={{color:'var(--text)'}}>Print dialog</strong>. Choose <em>Save as PDF</em> to download a fully formatted A4 PDF.
          </div>

          <button
            className="btn btn-sm"
            style={{ background: '#f68725', color: '#000', fontWeight: 700, border: 'none' }}
            onClick={doExportPDF}
            disabled={pdfLoading || loading}
          >
            {pdfLoading ? <span className="spinner" /> : '🖨'} Print / Save as PDF
          </button>
          <div style={{ fontSize: 10, color: 'var(--dim)', marginTop: 8 }}>
            In the print dialog → Destination → <strong style={{color:'var(--text)'}}>Save as PDF</strong>
          </div>
        </div>

        {/* DOCX export */}
        <div className="card" style={{ borderColor: '#3b82f622' }}>
          <div style={{ color: '#3b82f6', fontWeight: 700, fontSize: 13, marginBottom: 8 }}>📝 Word Report</div>
          <div style={{ fontSize: 11, color: 'var(--dim)', lineHeight: 1.8, marginBottom: 14 }}>
            Generates a standard <strong>.docx</strong> file for MS Word. Preserves styling and tables perfectly. Great for manual editing.
          </div>

          <button
            className="btn btn-sm"
            style={{ background: '#3b82f6', color: '#fff', fontWeight: 700, border: 'none' }}
            onClick={doExportDOCX}
            disabled={docxLoading || loading || pdfLoading}
          >
            {docxLoading ? <span className="spinner" /> : '↓'} Download DOCX
          </button>
        </div>


      </div>

      {/* Hidden iframe for PDF printing */}
      <iframe
        ref={printIframeRef}
        style={{ position: 'fixed', top: -9999, left: -9999, width: 1, height: 1, border: 'none', opacity: 0 }}
        title="pdf-print-frame"
      />

      {/* Warnings */}
      {(!meta.client_name || !meta.application_name) && (
        <div className="warn-banner mb-12">
          <strong>⚠ Incomplete metadata:</strong> Set Client Name and Application Name in Editor → Report Config before exporting.
        </div>
      )}
      {active.length === 0 && (
        <div className="error-banner mb-12">
          <strong>✕ No active findings:</strong> Import or create findings before exporting.
        </div>
      )}

      {/* Inline preview iframe */}
      {previewHtml && (
        <div className="card mt-20" style={{ padding: 0, overflowX: 'auto' }}>
          <div className="flex items-center justify-between" style={{ padding: '10px 16px', borderBottom: '1px solid var(--border)' }}>
            <span style={{ fontSize: 12, color: 'var(--dim)' }}>Report Preview — {template}</span>
            <button className="btn btn-sm" onClick={() => setPreviewHtml(null)}>✕ Close</button>
          </div>
          <iframe
            srcDoc={previewHtml}
            style={{ width: '100%', height: 700, border: 'none', background: '#fff' }}
            title="Report Preview"
            sandbox="allow-same-origin"
          />
        </div>
      )}
    </div>
  )
}
