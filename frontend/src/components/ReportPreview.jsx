import { useState, useRef } from 'react'
import { exportHTML, exportPDF, downloadBlob, todayStr, updateReportStatus, formatDateLong } from '../services/api'

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
const SEV_TEXT   = { critical: '#fff', high: '#fff', medium: '#fff', low: '#fff', info: '#fff' }

export default function ReportPreview({ findings, meta, toast, authUser, currentReportId, currentReportStatus, setCurrentReportStatus }) {
  const [loading, setLoading]   = useState(false)
  const [pdfLoading, setPdfLoading] = useState(false)
  const [template, setTemplate] = useState('default_report')
  const printIframeRef = useRef(null)

  const stats  = computeStats(findings)
  const active = findings.filter(f => !f.false_positive)
  const payload = { report: meta, findings, finding_stats: stats }

  const getFileName = (ext) => {
    const appName = (meta.application_name || 'App').trim()
    const date = new Date()
    const month = date.toLocaleString('default', { month: 'long' })
    const year = date.getFullYear()
    return `${appName} Vulnerability Assessment Report - ${month} ${year}.${ext}`
  }



  const parseBlobError = async (err, fallback = 'check backend') => {
    if (err?.response?.data) {
      if (err.response.data instanceof Blob) {
        try {
          const text = await err.response.data.text()
          const parsed = JSON.parse(text)
          if (typeof parsed.detail === 'string') return parsed.detail
          if (Array.isArray(parsed.detail)) return parsed.detail.map(d => d.msg || d.detail).join('; ')
        } catch (_) {}
      } else if (err.response.data.detail) {
        if (typeof err.response.data.detail === 'string') return err.response.data.detail
        if (Array.isArray(err.response.data.detail)) return err.response.data.detail.map(d => d.msg || d.detail).join('; ')
      }
    }
    return err?.message || fallback
  }

  const doDownloadPDF = async () => {
    setPdfLoading(true)
    try {
      const blob = await exportPDF(payload, template)
      downloadBlob(blob, getFileName('pdf'), 'application/pdf')
      toast('PDF report downloaded ✓')
    } catch (err) {
      const detail = await parseBlobError(err)
      toast('PDF export failed — ' + detail, 'error')
    } finally {
      setPdfLoading(false)
    }
  }

  const doExportPDF = async () => {
    setPdfLoading(true)
    try {
      const html = await exportHTML(payload, template)
      const iframe = printIframeRef.current
      iframe.srcdoc = html
      iframe.onload = () => {
        try {
          if (meta.document_title) iframe.contentDocument.title = meta.document_title
          iframe.contentWindow.focus()
          iframe.contentWindow.print()
        } catch (e) {
          const blob = new Blob([html], { type: 'text/html' })
          const url = URL.createObjectURL(blob)
          const win = window.open(url, '_blank')
          win.onload = () => {
            if (meta.document_title) win.document.title = meta.document_title
            win.print()
          }
        }
        setPdfLoading(false)
      }
    } catch (err) {
      const detail = await parseBlobError(err)
      toast('PDF export failed — ' + detail, 'error')
      setPdfLoading(false)
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
      <div className="page-title">⊙ Report PDF Preview & Export</div>

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
            { label: 'Report Date', val: meta.report_delivery_date ? formatDateLong(meta.report_delivery_date) : <span className="text-muted">Not set</span> },
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
              <div style={{ fontFamily: "'EB Garamond', Garamond, serif", fontSize: 28, fontWeight: 700, color: SEV_COLORS[s] }}>
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
                    <td style={{ color: 'var(--dim)', fontFamily: "'EB Garamond', Garamond, serif", fontSize: 11 }}>{i + 1}</td>
                    <td className="truncate" style={{ maxWidth: 360 }}>{f.title}</td>
                    <td><span className={`sev-badge sev-${f.cvss?.level}`}>{f.cvss?.level}</span></td>
                    <td style={{ fontFamily: "'EB Garamond', Garamond, serif", fontSize: 11, color: 'var(--dim)' }}>{f.cvss?.score || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Template selector + export buttons */}
      <div style={{ marginBottom: 20 }}>
        {/* PDF export */}
        <div className="card" style={{ borderColor: '#f6872522' }}>
          <div style={{ color: '#f68725', fontWeight: 700, fontSize: 13, marginBottom: 8 }}>📄 PDF Report</div>
          <div style={{ fontSize: 11, color: 'var(--dim)', lineHeight: 1.8, marginBottom: 14 }}>
            Direct PDF generation. You can preview or download the file directly.
          </div>

          <div className="flex gap-8 flex-wrap">
            <button
              className="btn btn-primary btn-sm"
              style={{ background: '#f68725', color: '#000', fontWeight: 700, border: 'none' }}
              onClick={doDownloadPDF}
              disabled={pdfLoading || loading}
            >
              {pdfLoading ? <span className="spinner" /> : '↓'} Download PDF
            </button>
            <button
              className="btn btn-sm"
              onClick={doExportPDF}
              disabled={pdfLoading || loading}
            >
              👁 Preview
            </button>
          </div>
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


    </div>
  )
}
