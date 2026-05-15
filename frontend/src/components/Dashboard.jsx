const SEV = [
  { key: 'critical', color: 'var(--sev-critical)', label: 'Critical' },
  { key: 'high',     color: 'var(--sev-high)',     label: 'High' },
  { key: 'medium',   color: 'var(--sev-medium)',   label: 'Medium' },
  { key: 'low',      color: 'var(--sev-low)',       label: 'Low' },
  { key: 'info',     color: 'var(--sev-info)',      label: 'Info' },
]

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

export default function Dashboard({ findings, meta, setPage, onLoadSample }) {
  const stats = computeStats(findings)
  const validated = findings.filter(f => f.validated).length
  const fps = findings.filter(f => f.false_positive).length
  const totalActive = findings.length - fps

  return (
    <div>
      <div className="mb-24">
        <div style={{ fontFamily: 'PT Sans, sans-serif', fontSize: 18, fontWeight: 700, color: 'var(--cyan)', marginBottom: 4 }}>
          {meta.client_name ? `${meta.client_name} — VAPT Report` : 'VAPT Report Automation System'}
        </div>
        <div style={{ fontSize: 12, color: 'var(--dim)' }}>
          {meta.application_name || 'No engagement configured — go to Editor to set report metadata'}
        </div>
      </div>

      {/* Severity strip */}
      <div className="grid-5 mb-16">
        {SEV.map(s => (
          <div
            key={s.key}
            className="card"
            onClick={() => setPage('findings')}
            style={{ textAlign: 'center', cursor: 'pointer', borderColor: `${s.color}33`, padding: '16px 10px' }}
          >
            <div style={{ fontFamily: 'PT Sans, sans-serif', fontSize: 32, fontWeight: 700, color: s.color, lineHeight: 1 }}>
              {stats[`count_${s.key}`]}
            </div>
            <div style={{ fontSize: 10, color: 'var(--dim)', marginTop: 7, letterSpacing: 0.5 }}>{s.label.toUpperCase()}</div>
          </div>
        ))}
      </div>

      {/* Summary cards */}
      <div className="grid-4 mb-20">
        {[
          { label: 'Total Findings', val: findings.length, color: 'var(--cyan)' },
          { label: 'Active', val: totalActive, color: 'var(--green)' },
          { label: 'Validated', val: validated, color: 'var(--orange)' },
          { label: 'False Positives', val: fps, color: 'var(--dim)' },
        ].map(s => (
          <div key={s.label} className="card">
            <div style={{ fontSize: 28, fontWeight: 700, color: s.color, lineHeight: 1 }}>{s.val}</div>
            <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 6 }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Severity distribution bar */}
      {stats.total > 0 && (
        <div className="card mb-20">
          <div className="section-label">Severity Distribution</div>
          <div style={{ display: 'flex', height: 22, borderRadius: 4, overflow: 'hidden', marginBottom: 10 }}>
            {SEV.map(s => {
              const pct = stats[`count_${s.key}`] / stats.total * 100
              return pct > 0 ? (
                <div
                  key={s.key}
                  title={`${s.label}: ${stats[`count_${s.key}`]}`}
                  style={{
                    width: `${pct}%`,
                    background: s.color,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: 10,
                    fontWeight: 700,
                    color: s.key === 'medium' ? '#000' : '#fff',
                    transition: 'width 0.3s',
                  }}
                >
                  {pct > 7 ? `${Math.round(pct)}%` : ''}
                </div>
              ) : null
            })}
          </div>
          <div className="flex gap-12 flex-wrap">
            {SEV.map(s => stats[`count_${s.key}`] > 0 && (
              <span key={s.key} style={{ fontSize: 11, color: s.color }}>
                ■ {s.label} ({stats[`count_${s.key}`]})
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Recent findings */}
      {findings.length > 0 ? (
        <div className="card mb-20" style={{ overflowX: 'auto' }}>
          <div className="section-label">Recent Findings</div>
          <table className="data-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Title</th>
                <th>Severity</th>
                <th>CVSS</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {findings.slice(0, 8).map((f, i) => (
                <tr key={f.id} style={{ opacity: f.false_positive ? 0.45 : 1 }}>
                  <td style={{ color: 'var(--dim)', fontFamily: 'PT Sans, sans-serif', fontSize: 11 }}>{i + 1}</td>
                  <td className="truncate" style={{ maxWidth: 340 }}>{f.title}</td>
                  <td>
                    <span className={`sev-badge sev-${f.cvss?.level}`}>{f.cvss?.level}</span>
                  </td>
                  <td style={{ fontFamily: 'PT Sans, sans-serif', fontSize: 11, color: 'var(--dim)' }}>
                    {f.cvss?.score || '—'}
                  </td>
                  <td>
                    {f.false_positive && <span style={{ color: 'var(--red)', fontSize: 10 }}>FP</span>}
                    {f.validated && !f.false_positive && <span style={{ color: 'var(--green)', fontSize: 10 }}>✓ Validated</span>}
                    {!f.validated && !f.false_positive && <span style={{ color: 'var(--dim)', fontSize: 10 }}>Pending</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {findings.length > 8 && (
            <div style={{ textAlign: 'center', marginTop: 12 }}>
              <button className="btn btn-sm" onClick={() => setPage('findings')}>
                View all {findings.length} findings →
              </button>
            </div>
          )}
        </div>
      ) : (
        <div className="card mb-20" style={{ textAlign: 'center', padding: 48 }}>
          <div style={{ fontSize: 40, marginBottom: 16 }}>⬡</div>
          <div style={{ color: 'var(--dim)', marginBottom: 16, fontSize: 13 }}>
            No findings yet. Import a scan report or add findings manually.
          </div>
          <div className="flex gap-8 items-center" style={{ justifyContent: 'center' }}>
            <button className="btn btn-primary" onClick={() => setPage('upload')}>↑ Import Data</button>
            <button className="btn btn-success" onClick={() => setPage('editor')}>+ Add Finding</button>
            <button className="btn" onClick={onLoadSample}>⬡ Load Sample</button>
          </div>
        </div>
      )}

      {/* Quick actions */}
      <div className="flex gap-8 flex-wrap">
        <button className="btn btn-success"  onClick={() => setPage('editor')}>+ Add Finding</button>
        <button className="btn btn-warning"  onClick={() => setPage('editor')}>⚙ Configure Report</button>
        <button className="btn btn-purple"   onClick={() => setPage('preview')}>⊙ Preview Report</button>
      </div>
    </div>
  )
}
