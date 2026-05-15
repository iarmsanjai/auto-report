import { useState, useEffect } from 'react'
import { getReportsFromDB, loadReportFromDB, deleteReportFromDB, updateReportStatus, exportHTML, requestEditAccess, approveEditAccess } from '../services/api'

const STATUS_STYLE = {
  approved:         { badge: 'sev-low',    label: 'APPROVED' },
  needs_change:     { badge: 'sev-high',   label: 'NEEDS CHANGE' },
  pending_approval: { badge: 'sev-medium', label: 'PENDING APPROVAL' },
  draft:            { badge: '',           label: 'DRAFT' },
}

export default function ReportsManager({ onEditReport, toast, authUser }) {
  const [reports,    setReports]    = useState([])
  const [loading,    setLoading]    = useState(true)
  const [previewHtml, setPreviewHtml] = useState(null)
  const [previewTitle, setPreviewTitle] = useState('')
  const [previewLoading, setPreviewLoading] = useState(null) // report id being previewed
  
  // Search and filter state
  const [searchQuery, setSearchQuery] = useState('')
  const [filterType, setFilterType]   = useState('all')

  const fetchReports = async () => {
    setLoading(true)
    try {
      const data = await getReportsFromDB()
      setReports(data)
    } catch {
      toast('Failed to load reports', 'error')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchReports() }, [])

  const handleEdit = async (id) => {
    try {
      const data = await loadReportFromDB(id)
      onEditReport(id, data.meta, data.findings, data.status)
    } catch {
      toast('Failed to load report', 'error')
    }
  }

  const handleDelete = async (id) => {
    const reportToDelete = reports.find(r => r.id === id)
    if (!reportToDelete) return

    // Immediately remove from UI
    setReports(prev => prev.filter(r => r.id !== id))
    
    let undone = false
    toast(`Report '${reportToDelete.client_name || 'Draft'}' removed`, 'warn', () => {
      undone = true
      setReports(prev => [reportToDelete, ...prev])
      toast('Report restored', 'ok')
    })

    // Actually delete from DB after 10 seconds if not undone
    setTimeout(async () => {
      if (!undone) {
        try {
          await deleteReportFromDB(id)
        } catch {
          // If it fails silently in the background, we don't disrupt the user,
          // but next fetch will bring it back.
        }
      }
    }, 10000)
  }

  const handleStatusUpdate = async (id, status) => {
    try {
      await updateReportStatus(id, status)
      toast('Status updated ✓')
      fetchReports()
    } catch {
      toast('Failed to update status', 'error')
    }
  }

  const handlePreview = async (r) => {
    setPreviewLoading(r.id)
    try {
      const data = await loadReportFromDB(r.id)
      const stats = computeStats(data.findings || [])
      const html = await exportHTML({ report: data.meta, findings: data.findings, finding_stats: stats })
      setPreviewTitle(`${r.client_name} — ${r.project_id}`)
      setPreviewHtml(html)
    } catch {
      toast('Failed to generate preview', 'error')
    } finally {
      setPreviewLoading(null)
    }
  }

  const handleRequestEdit = async (id) => {
    try {
      await requestEditAccess(id)
      toast('Edit request sent to admin', 'ok')
      fetchReports()
    } catch {
      toast('Failed to request edit', 'error')
    }
  }

  const handleApproveEdit = async (id, requestedBy) => {
    try {
      await approveEditAccess(id, requestedBy)
      toast(`Edit approved for ${requestedBy}`, 'ok')
      fetchReports()
    } catch {
      toast('Failed to approve edit', 'error')
    }
  }

  const isAdmin = authUser?.role === 'admin'
  const isEditor = authUser?.role === 'editor'
  const isViewer = authUser?.role === 'viewer'

  const filteredReports = reports.filter(report => {
    // Default to nessus for old reports that don't have scanType saved
    const scanType = report.scanType || 'nessus'
    
    if (filterType !== 'all' && scanType !== filterType) return false
    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      if (!report.client_name?.toLowerCase().includes(q) &&
          !report.project_id?.toLowerCase().includes(q) &&
          !report.username?.toLowerCase().includes(q)) {
        return false
      }
    }
    return true
  })

  if (loading) {
    return <div style={{ padding: 40, textAlign: 'center', color: 'var(--dim)' }}><span className="spinner" /> Loading reports...</div>
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-16">
        <div className="page-title" style={{ marginBottom: 0 }}>
          {isAdmin || isViewer || isEditor ? '☁ All Cloud Reports' : '☁ My Cloud Reports'}
        </div>
        <button className="btn btn-sm" onClick={fetchReports}>↻ Refresh</button>
      </div>

      {/* Filters and Search */}
      <div className="flex gap-8 mb-16 items-center flex-wrap">
        <input
          type="text"
          className="form-input"
          placeholder="Search by client, project, or user..."
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          style={{ width: 280, padding: '6px 12px' }}
        />
        <select
          className="form-select"
          value={filterType}
          onChange={e => setFilterType(e.target.value)}
          style={{ width: 200, padding: '6px 12px' }}
        >
          <option value="all">All Report Types</option>
          <option value="nessus">VA Report (Nessus)</option>
          <option value="snyk">Source Code Report (Snyk)</option>
          <option value="webvapt">Web VAPT Report</option>
        </select>
        <div style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--dim)' }}>
          Showing {filteredReports.length} {filteredReports.length === 1 ? 'report' : 'reports'}
        </div>
      </div>

      {/* Report list */}
      {filteredReports.length === 0 ? (
        <div className="card" style={{ color: 'var(--dim)', fontSize: 13, padding: 32, textAlign: 'center' }}>
          {reports.length === 0 ? 'No reports saved yet.' : 'No reports match your filters.'}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {filteredReports.map(r => {
            const st = STATUS_STYLE[r.status] || STATUS_STYLE.draft
            const isPending = r.status === 'pending_approval'
            const scanType = r.scanType || 'nessus'
            
            return (
              <div key={r.id} className="card" style={{ padding: '14px 18px' }}>
                {/* Top row: info + status */}
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: 14, color: 'var(--text)', marginBottom: 3 }}>
                      {r.client_name}
                    </div>
                    <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', fontSize: 11, color: 'var(--dim)' }}>
                      <span style={{ fontFamily: 'PT Sans, sans-serif', color: 'var(--cyan)' }}>{r.project_id}</span>
                      <span style={{ color: 'var(--orange)' }}>
                        {scanType === 'nessus' ? '🛡 VA Report' : scanType === 'snyk' ? '🔍 Source Code Report' : scanType === 'webvapt' ? '🌐 WAPT Report' : '📄 Report'}
                      </span>
                      {(isAdmin || isViewer || isEditor) && <span>👤 {r.username}</span>}
                      <span>🕒 {new Date(r.updated_at).toLocaleString()}</span>
                    </div>
                  </div>
                  <span className={`sev-badge ${st.badge}`} style={{ fontSize: 9, flexShrink: 0 }}>
                    {st.label}
                  </span>
                </div>

                {/* Bottom row: action buttons — grouped cleanly */}
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', borderTop: '1px solid var(--border)', paddingTop: 10 }}>

                  {/* Admin-only: Approve / Needs Change — shown only for pending */}
                  {isAdmin && isPending && (
                    <>
                      <button
                        className="btn btn-sm"
                        style={{ color: 'var(--green)', borderColor: 'var(--green)', fontWeight: 600 }}
                        onClick={() => handleStatusUpdate(r.id, 'approved')}
                      >
                        ✓ Approve
                      </button>
                      <button
                        className="btn btn-sm"
                        style={{ color: 'var(--red)', borderColor: 'var(--red)', fontWeight: 600 }}
                        onClick={() => handleStatusUpdate(r.id, 'needs_change')}
                      >
                        ✕ Needs Change
                      </button>
                      <div style={{ width: 1, background: 'var(--border)', margin: '0 4px' }} />
                    </>
                  )}

                  {/* Admin-only: Approve Edit Request */}
                  {isAdmin && r.edit_requested_by && (
                    <>
                      <button
                        className="btn btn-sm"
                        style={{ color: '#fff', background: 'var(--purple)', borderColor: 'var(--purple)', fontWeight: 600 }}
                        onClick={() => handleApproveEdit(r.id, r.edit_requested_by)}
                      >
                        ✓ Approve Edit ({r.edit_requested_by})
                      </button>
                      <div style={{ width: 1, background: 'var(--border)', margin: '0 4px' }} />
                    </>
                  )}

                  {/* HTML Preview (Admin, Viewer, Editor) */}
                  {(isAdmin || isViewer || isEditor) && (
                    <button
                      className="btn btn-sm"
                      style={{ color: 'var(--cyan)', borderColor: 'var(--cyan)' }}
                      onClick={() => handlePreview(r)}
                      disabled={previewLoading === r.id}
                    >
                      {previewLoading === r.id ? <span className="spinner" /> : '⊙'} Preview
                    </button>
                  )}

                  {/* Edit Flow */}
                  {!isViewer && (
                    <>
                      {/* If user owns it or is admin, they can edit */}
                      {(isAdmin || r.username === authUser.username) ? (
                        <button className="btn btn-sm" onClick={() => handleEdit(r.id)}>
                          ✎ Edit
                        </button>
                      ) : (
                        /* Otherwise (Editor viewing someone else's report), they must request edit */
                        r.edit_requested_by === authUser.username ? (
                          <button className="btn btn-sm" style={{ color: 'var(--orange)' }} disabled>
                            ⏳ Edit Requested
                          </button>
                        ) : (
                          <button className="btn btn-sm" onClick={() => handleRequestEdit(r.id)}>
                            ✋ Request Edit
                          </button>
                        )
                      )}
                    </>
                  )}

                  {/* Delete (Admin ONLY) */}
                  {isAdmin && (
                    <button
                      className="btn btn-sm"
                      style={{ borderColor: '#ff444466', color: 'var(--red)' }}
                      onClick={() => handleDelete(r.id)}
                    >
                      ✕ Delete
                    </button>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* HTML Preview Modal */}
      {previewHtml && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 1000,
          background: 'rgba(0,0,0,0.75)',
          display: 'flex', flexDirection: 'column',
        }}>
          {/* Modal header */}
          <div style={{
            background: 'var(--bg2)', borderBottom: '1px solid var(--border)',
            padding: '12px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0,
          }}>
            <div>
              <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--cyan)' }}>⊙ Report Preview</span>
              <span style={{ fontSize: 11, color: 'var(--dim)', marginLeft: 12 }}>{previewTitle}</span>
            </div>
            <button
              className="btn btn-sm"
              style={{ borderColor: 'var(--red)', color: 'var(--red)' }}
              onClick={() => setPreviewHtml(null)}
            >
              ✕ Close
            </button>
          </div>

          {/* Modal iframe */}
          <iframe
            srcDoc={previewHtml}
            style={{ flex: 1, border: 'none', background: '#fff' }}
            title="Report HTML Preview"
            sandbox="allow-same-origin allow-scripts"
          />
        </div>
      )}
    </div>
  )
}

// Helper to compute stats for export payload
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
